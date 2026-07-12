"""Phase B: Wiz GraphQL client + issue mapping, against a canned response.

Uses httpx.MockTransport — no network, no live Wiz, no real credentials.
"""

import json

import httpx
import pytest

from spellbook.control.ingest.model import Posture, Source, Vector
from spellbook.control.ingest.wiz_api import (
    WizAPIError,
    WizClient,
    ingest_from_wiz,
    map_issue,
)
from spellbook.control.store.store import Store, init_engine

# A representative (best-effort) Wiz Issues response, incl. one attack path.
_CANNED = {
    "data": {
        "issues": {
            "nodes": [
                {
                    "id": "wiz-issue-1",
                    "severity": "CRITICAL",
                    "status": "OPEN",
                    "type": "TOXIC_COMBINATION",
                    "sourceRule": {"__typename": "Control", "id": "c1",
                                   "name": "Publicly exposed VM with critical CVE"},
                    "entitySnapshot": {"id": "e1", "type": "VIRTUAL_MACHINE",
                                       "name": "web-1", "cloudPlatform": "GCP",
                                       "subscriptionId": "prod-proj",
                                       "externalId": "api.acme.com"},
                    "attackPath": {"steps": [
                        {"technique": "public_exposure", "from": "internet",
                         "to": "web-1", "posture": "external"},
                        {"technique": "exploit_cve", "from": "web-1",
                         "to": "web-1", "posture": "external"},
                        {"technique": "iam_privesc", "from": "web-1",
                         "to": "prod-db", "posture": "internal"},
                    ]},
                },
                {
                    "id": "wiz-issue-2",
                    "severity": "HIGH",
                    "type": "CLOUD_CONFIGURATION",
                    "sourceRule": {"name": "Over-privileged IAM role"},
                    "entitySnapshot": {"id": "e2", "type": "SERVICE_ACCOUNT",
                                       "name": "ci-sa", "cloudPlatform": "GCP"},
                },
            ],
            "pageInfo": {"hasNextPage": False, "endCursor": None},
        }
    }
}


def _client(response=_CANNED, status=200):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer test-token"
        return httpx.Response(status, json=response)
    http = httpx.Client(transport=httpx.MockTransport(handler))
    return WizClient(api_url="https://api.test.app.wiz.io/graphql", token="test-token", http=http)


def test_fetch_issues_returns_nodes():
    nodes = _client().fetch_issues(first=10)
    assert len(nodes) == 2 and nodes[0]["id"] == "wiz-issue-1"


def test_map_issue_builds_finding_and_attack_path():
    finding, path = map_issue(_CANNED["data"]["issues"]["nodes"][0])
    assert finding.id == "wiz-issue-1" and finding.source is Source.WIZ
    assert finding.severity == "CRITICAL" and finding.vector is Vector.EXPOSED_SERVICE
    assert finding.asset.host == "api.acme.com" and finding.asset.cloud == "gcp"
    assert path is not None and len(path.steps) == 3
    assert path.steps[0].technique == "public_exposure"
    assert path.steps[2].posture is Posture.INTERNAL


def test_map_issue_synthesises_path_when_absent():
    # issue-2 has no attackPath and no host → no synthesised path
    finding, path = map_issue(_CANNED["data"]["issues"]["nodes"][1])
    assert finding.vector is Vector.IAM and path is None


def test_graphql_errors_raise():
    client = _client({"errors": [{"message": "bad query"}]})
    with pytest.raises(WizAPIError):
        client.fetch_issues()


def test_http_error_status_raises():
    client = _client({"data": {}}, status=401)
    with pytest.raises(WizAPIError):
        client.fetch_issues()


def test_missing_api_url_raises():
    with pytest.raises(WizAPIError):
        WizClient(token="x").fetch_issues()


def test_ingest_from_wiz_persists_findings_and_paths():
    store = Store(init_engine())
    ids = ingest_from_wiz(_client(), store)
    assert ids == ["wiz-issue-1", "wiz-issue-2"]
    assert len(store.list_findings()) == 2
    assert len(store.get_attack_path("wiz-issue-1:path").steps) == 3
    assert store.get_attack_path("wiz-issue-2:path") is None
