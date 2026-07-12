"""API tests via TestClient with fake agent backend (no GCP, no Gemini)."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from spellbook.safety.classify import ACTIVE_INVASIVE, ACTIVE_NONINVASIVE
from spellbook.control.agent.google_agent import GoogleAgentClient, RunnerEndpoint
from spellbook.control.app import create_app
from spellbook.control.orchestrator import Orchestrator
from spellbook.control.store.store import Store, init_engine
from tests.test_google_agent import FakeInteractions, _VERDICT_JSON


@pytest.fixture
def client():
    store = Store(init_engine())
    backend = FakeInteractions(["running", "completed"], output_text=_VERDICT_JSON)
    orch = Orchestrator(
        store=store,
        agent=GoogleAgentClient(backend, poll_interval=0),
        runner_minter=lambda p: RunnerEndpoint("https://runner/mcp", {"Authorization": "Bearer x"}),
        scope_provider=lambda: {"acme.com"},
    )
    return TestClient(create_app(orch, store))


_FINDING = {"id": "F1", "vector": "exposed_service", "severity": "HIGH",
            "asset_id": "a1", "host": "api.acme.com", "title": "exposed admin"}


def _future():
    return (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()


def test_ingest_finding_then_run_and_complete(client):
    assert client.post("/findings", json=_FINDING).status_code == 201

    r = client.post("/runs", json={"finding_id": "F1", "posture": "external"})
    assert r.status_code == 201
    run_id = r.json()["id"]
    assert r.json()["status"] == "running"

    done = client.post(f"/runs/{run_id}/complete").json()
    assert done["status"] == "completed"
    assert done["verdict"] == "EXPLOITABLE"
    assert done["evidence"][0]["tool"] == "http_probe"


def test_run_on_unknown_finding_is_404(client):
    assert client.post("/runs", json={"finding_id": "nope", "posture": "external"}).status_code == 404


def test_exploit_tier_denied_without_authorization(client):
    client.post("/findings", json=_FINDING)
    run = client.post("/runs", json={"finding_id": "F1", "posture": "external",
                                     "tier": ACTIVE_INVASIVE}).json()
    assert run["status"] == "denied" and "needs_authorization" in run["error"]


def test_authorization_enables_exploit_run(client):
    client.post("/findings", json=_FINDING)
    auth = {"id": "A1", "target": "acme.com", "max_tier": ACTIVE_INVASIVE,
            "authorized_by": "andy", "blast_radius_note": "lab host", "expires_at": _future()}
    assert client.post("/authorizations", json=auth).status_code == 201
    run = client.post("/runs", json={"finding_id": "F1", "posture": "external",
                                     "tier": ACTIVE_INVASIVE, "authorization_id": "A1"}).json()
    assert run["status"] == "running"


def test_authorization_without_blast_note_is_422(client):
    bad = {"id": "A2", "target": "acme.com", "max_tier": ACTIVE_INVASIVE,
           "authorized_by": "andy", "blast_radius_note": "  ", "expires_at": _future()}
    assert client.post("/authorizations", json=bad).status_code == 422


def test_index_serves_ui(client):
    r = client.get("/")
    assert r.status_code == 200 and "Spellbook" in r.text and "Start validation run" in r.text


def test_list_runs(client):
    client.post("/findings", json=_FINDING)
    client.post("/runs", json={"finding_id": "F1", "posture": "internal"})
    runs = client.get("/runs").json()
    assert len(runs) == 1 and runs[0]["posture"] == "internal"
