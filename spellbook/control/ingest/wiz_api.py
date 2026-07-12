"""Direct Wiz GraphQL ingestion.

Pulls issues (and any attack-path context they carry) straight from the Wiz
GraphQL API, reusing :func:`spellbook.wiz.auth.exchange_token` for the bearer
token. The token/endpoint/query are all injectable or env-configurable because
the Wiz schema is tenant/region-specific and can't be pinned here — parsing is
deliberately tolerant, and the raw Wiz payload is kept on each finding for
diagnosis.

- ``WIZ_API_URL``           the tenant's GraphQL endpoint (e.g. https://api.<region>.app.wiz.io/graphql)
- ``WIZ_ISSUES_QUERY_FILE`` optional path to override the default Issues query
- ``WIZ_CLIENT_ID`` / ``WIZ_CLIENT_SECRET``  service-account creds (token via exchange_token)

Tested against a canned GraphQL response through an injected ``httpx.Client`` — no
live Wiz needed.
"""

from __future__ import annotations

import ipaddress
import os
import uuid

import httpx

from spellbook.control.ingest.model import (
    Asset,
    AttackPath,
    AttackStep,
    Finding,
    Posture,
    Source,
    Vector,
)
from spellbook.wiz.auth import exchange_token

# A representative Issues query. Overridable via WIZ_ISSUES_QUERY_FILE — the exact
# selectable fields vary by tenant/schema version.
DEFAULT_ISSUES_QUERY = """
query Issues($first: Int, $after: String, $filterBy: IssueFilters) {
  issues(first: $first, after: $after, filterBy: $filterBy) {
    nodes {
      id
      severity
      status
      type
      sourceRule { __typename ... on Control { id name } }
      entitySnapshot {
        id type name nativeType cloudPlatform subscriptionId externalId providerUniqueId
      }
      createdAt
    }
    pageInfo { hasNextPage endCursor }
  }
}
""".strip()


class WizAPIError(Exception):
    """Raised on a failed Wiz GraphQL request (transport, HTTP, or GraphQL errors)."""


def issues_query() -> str:
    override = os.environ.get("WIZ_ISSUES_QUERY_FILE")
    if override and os.path.exists(override):
        return open(override).read()
    return DEFAULT_ISSUES_QUERY


class WizClient:
    def __init__(
        self,
        *,
        api_url: str | None = None,
        token: str | None = None,
        http: httpx.Client | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.api_url = api_url or os.environ.get("WIZ_API_URL")
        self.timeout = timeout
        self._token = token
        self._http = http  # inject an httpx.Client (e.g. with MockTransport) for tests

    def _bearer(self) -> str:
        if self._token:
            return self._token
        client_id = os.environ.get("WIZ_CLIENT_ID")
        client_secret = os.environ.get("WIZ_CLIENT_SECRET")
        if not (client_id and client_secret):
            raise WizAPIError("no Wiz token and WIZ_CLIENT_ID/WIZ_CLIENT_SECRET are unset")
        self._token = exchange_token(client_id, client_secret)
        return self._token

    def execute(self, query: str, variables: dict | None = None) -> dict:
        if not self.api_url:
            raise WizAPIError("WIZ_API_URL is not set (the tenant GraphQL endpoint)")
        client = self._http or httpx.Client(timeout=self.timeout)
        try:
            resp = client.post(
                self.api_url,
                json={"query": query, "variables": variables or {}},
                headers={
                    "Authorization": f"Bearer {self._bearer()}",
                    "Content-Type": "application/json",
                },
            )
        except httpx.HTTPError as exc:
            raise WizAPIError(f"Wiz request failed: {exc}") from exc
        if resp.status_code != 200:
            raise WizAPIError(f"Wiz HTTP {resp.status_code}: {resp.text[:200]}")
        body = resp.json()
        if body.get("errors"):
            raise WizAPIError(f"Wiz GraphQL errors: {body['errors']}")
        return body.get("data") or {}

    def fetch_issues(self, first: int = 20, filter_by: dict | None = None) -> list[dict]:
        """Return raw issue nodes (tolerant of the exact connection field name)."""
        data = self.execute(issues_query(), {"first": first, "filterBy": filter_by or {}})
        return _issue_nodes(data)


def _issue_nodes(data: dict) -> list[dict]:
    """Pull the first connection-shaped ``{nodes: [...]}`` out of a GraphQL data blob."""
    for value in data.values():
        if isinstance(value, dict) and isinstance(value.get("nodes"), list):
            return value["nodes"]
    return []


# --- mapping --------------------------------------------------------------
_VECTOR_HINTS = {
    "exposed": Vector.EXPOSED_SERVICE, "public": Vector.EXPOSED_SERVICE,
    "cve": Vector.CVE, "vuln": Vector.CVE,
    "iam": Vector.IAM, "permission": Vector.IAM, "privilege": Vector.IAM,
}


def _guess_vector(raw: dict) -> Vector:
    text = f"{raw.get('type', '')} {(raw.get('sourceRule') or {}).get('name', '')}".lower()
    for hint, vector in _VECTOR_HINTS.items():
        if hint in text:
            return vector
    return Vector.MISCONFIG


def _looks_like_host(value: str) -> bool:
    """A network-addressable host: a dotted name (or IP), not an opaque resource id."""
    if "." in value:
        return True
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _entity_host(entity: dict) -> str | None:
    """The entity's network host, if it has one. Non-network assets return None."""
    for key in ("externalId", "name", "providerUniqueId", "id"):
        value = entity.get(key)
        if value and _looks_like_host(str(value)):
            return str(value)
    return None


def map_issue(raw: dict) -> tuple[Finding, AttackPath | None]:
    """Normalise one Wiz issue to a Finding (+ an AttackPath when derivable)."""
    entity = raw.get("entitySnapshot") or {}
    issue_id = str(raw.get("id") or uuid.uuid4().hex)
    title = str((raw.get("sourceRule") or {}).get("name") or raw.get("type") or "Wiz issue")
    asset = Asset(
        id=str(entity.get("providerUniqueId") or entity.get("id") or issue_id),
        cloud=str(entity.get("cloudPlatform") or "gcp").lower(),
        project=entity.get("subscriptionId"),
        host=_entity_host(entity),
    )
    finding = Finding(
        id=issue_id, source=Source.WIZ, asset=asset, vector=_guess_vector(raw),
        severity=str(raw.get("severity") or "").upper(), title=title, raw=raw,
    )
    return finding, _extract_attack_path(raw, finding)


def _extract_attack_path(raw: dict, finding: Finding) -> AttackPath | None:
    """Build a linear path from Wiz attack-path data, or synthesise a minimal one."""
    steps_raw = None
    for key in ("attackPath", "attackPaths"):
        node = raw.get(key)
        if isinstance(node, dict) and isinstance(node.get("steps"), list):
            steps_raw = node["steps"]
            break
        if isinstance(node, list) and node and isinstance(node[0], dict):
            steps_raw = node[0].get("steps") if isinstance(node[0].get("steps"), list) else node
            break

    path_id = f"{finding.id}:path"
    if steps_raw:
        steps = [
            AttackStep(
                index=i,
                technique=str(s.get("technique") or s.get("type") or "lateral_move"),
                description=str(s.get("description") or ""),
                from_entity=str(s.get("from") or s.get("from_entity") or ""),
                to_entity=str(s.get("to") or s.get("to_entity") or ""),
                posture=Posture.INTERNAL if str(s.get("posture")).lower() == "internal"
                else Posture.EXTERNAL,
            )
            for i, s in enumerate(steps_raw)
            if isinstance(s, dict)
        ]
        if steps:
            return AttackPath(id=path_id, finding_id=finding.id, name=finding.title,
                              source=Source.WIZ, entry_point="internet",
                              impact=finding.asset.id, steps=steps, raw=raw)

    # Fallback: a single public-exposure step so there's always something to validate/show.
    if finding.asset.host:
        return AttackPath(
            id=path_id, finding_id=finding.id, name=finding.title, source=Source.WIZ,
            entry_point="internet", impact=finding.asset.id,
            steps=[AttackStep(index=0, technique="public_exposure", from_entity="internet",
                              to_entity=finding.asset.host, posture=Posture.EXTERNAL,
                              suggested_tool="reachability")],
        )
    return None


def ingest_from_wiz(client: WizClient, store, first: int = 20) -> list[str]:
    """Fetch issues, persist each as a Finding (+ AttackPath). Returns finding ids."""
    ids: list[str] = []
    for raw in client.fetch_issues(first=first):
        finding, path = map_issue(raw)
        store.save_finding(finding)
        if path is not None:
            store.save_attack_path(path)
        ids.append(finding.id)
    return ids
