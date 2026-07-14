"""Injectable GCP access backend for the internal ("assumed-breach") tools.

The M1 ``gcp_lateral`` tools model what an attacker does after landing inside the
VPC: read the instance's identity from the metadata server, then measure the
blast radius of the service account it can borrow. Those live GCP surfaces are
reached only through a :class:`GcpBackend` — a thin Protocol — so the tool logic
is unit-tested against a fake and the ``httpx``/metadata coupling lives in one
adapter (:class:`MetadataGcpBackend`). This mirrors the ``QueryFn`` injection in
:mod:`spellbook.worker.loop`.

**Credentials never leave the runner.** The backend can mint an access token
(``testIamPermissions`` needs one), but the token string is used internally and
is *never* returned to the agent — the ``metadata_token`` tool surfaces only a
fingerprint + scopes + expiry (see :mod:`spellbook.runner.tools.gcp_lateral`).

The three metadata/IAM call sites that must be confirmed against a real GCP
instance before trusting live internal runs are marked ``# VERIFY (live)``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

_METADATA_BASE = "http://metadata.google.internal/computeMetadata/v1"
_METADATA_HEADERS = {"Metadata-Flavor": "Google"}
# testIamPermissions on the project resource — the granted subset is the blast radius.
_RESOURCE_MANAGER = "https://cloudresourcemanager.googleapis.com/v1"

# A curated set of high-impact permissions. The subset the borrowed SA actually
# holds is the reported "blast radius" — this is a signal, not an exhaustive audit.
BLAST_RADIUS_PERMISSIONS = (
    "resourcemanager.projects.setIamPolicy",
    "iam.serviceAccounts.actAs",
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccountKeys.create",
    "compute.instances.list",
    "compute.instances.setMetadata",
    "storage.buckets.list",
    "storage.objects.get",
    "secretmanager.versions.access",
    "cloudsql.instances.connect",
)


@dataclass(frozen=True)
class GcpIdentity:
    """The service-account identity a breached instance can borrow."""

    email: str
    project_id: str = ""
    numeric_project_id: str = ""
    zone: str = ""
    scopes: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class GcpToken:
    """A minted access token. The raw ``value`` stays inside the runner."""

    value: str
    expires_in: int = 0
    token_type: str = "Bearer"


class GcpBackend(Protocol):
    """The slice of the GCP metadata/IAM surface the lateral tools depend on."""

    def identity(self) -> GcpIdentity: ...
    def access_token(self) -> GcpToken: ...
    def test_permissions(self, resource: str, permissions: list[str]) -> list[str]: ...


class MetadataGcpBackend:
    """Real backend: the local GCE metadata server + Resource Manager REST.

    Constructed lazily by :func:`get_backend` on a real internal runner; never
    exercised by the offline test suite (which injects a fake).
    """

    def __init__(self, *, timeout: float = 3.0, http: Any = None) -> None:
        self.timeout = timeout
        self._http = http  # injectable httpx.Client for tests/reuse; else per-call

    def _client(self):
        import httpx  # lazy: only needed on a live runner

        return self._http or httpx.Client(timeout=self.timeout)

    def _metadata(self, path: str) -> str:
        # VERIFY (live): metadata paths under /instance and /project.
        client = self._client()
        try:
            resp = client.get(f"{_METADATA_BASE}/{path}", headers=_METADATA_HEADERS)
            resp.raise_for_status()
            return resp.text.strip()
        finally:
            if self._http is None:
                client.close()

    def identity(self) -> GcpIdentity:
        sa = "instance/service-accounts/default"
        scopes = self._metadata(f"{sa}/scopes")
        return GcpIdentity(
            email=self._metadata(f"{sa}/email"),
            project_id=self._metadata("project/project-id"),
            numeric_project_id=self._metadata("project/numeric-project-id"),
            zone=self._metadata("instance/zone").rsplit("/", 1)[-1],
            scopes=tuple(s for s in scopes.splitlines() if s.strip()),
        )

    def access_token(self) -> GcpToken:
        import json

        # VERIFY (live): token endpoint returns {access_token, expires_in, token_type}.
        raw = json.loads(self._metadata("instance/service-accounts/default/token"))
        return GcpToken(
            value=raw["access_token"],
            expires_in=int(raw.get("expires_in", 0)),
            token_type=raw.get("token_type", "Bearer"),
        )

    def test_permissions(self, resource: str, permissions: list[str]) -> list[str]:
        import httpx

        token = self.access_token()
        client = self._client()
        try:
            # VERIFY (live): projects.testIamPermissions request/response shape.
            resp = client.post(
                f"{_RESOURCE_MANAGER}/projects/{resource}:testIamPermissions",
                headers={"Authorization": f"{token.token_type} {token.value}"},
                json={"permissions": permissions},
            )
            resp.raise_for_status()
            return list(resp.json().get("permissions", []))
        except httpx.HTTPError:
            return []
        finally:
            if self._http is None:
                client.close()


_backend: GcpBackend | None = None


def set_backend(backend: GcpBackend | None) -> None:
    """Inject the backend (tests pass a fake; ``None`` resets to lazy default)."""
    global _backend
    _backend = backend


def get_backend() -> GcpBackend:
    """Return the injected backend, lazily constructing the real one if unset."""
    global _backend
    if _backend is None:
        _backend = MetadataGcpBackend()
    return _backend
