"""API tests via TestClient (no GCP, no model, no worker).

The agent loop now lives in a separate worker: `POST /runs` dispatches, the worker
claims via `GET /internal/runs/claim` and reports via `POST /internal/runs/{id}/result`.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from spellbook.control.app import create_app
from spellbook.control.orchestrator import Orchestrator
from spellbook.control.store.store import Store, init_engine
from spellbook.safety.classify import ACTIVE_INVASIVE, ACTIVE_NONINVASIVE

_VERDICT = {
    "label": "EXPLOITABLE", "confidence": 0.9, "summary": "open and unauthenticated",
    "evidence_chain": [{"tool": "http_probe", "target": "api.acme.com",
                        "observation": "200 no auth", "interpretation": "admin exposed"}],
    "reproduction": "GET /admin", "attack_path": [],
}

_WORKER_TOKEN = "wtok"
_AUTH = {"Authorization": f"Bearer {_WORKER_TOKEN}"}


@pytest.fixture
def client():
    store = Store(init_engine())
    orch = Orchestrator(store=store, scope_provider=lambda: {"acme.com"})
    return TestClient(create_app(orch, store, worker_token=_WORKER_TOKEN))


_FINDING = {"id": "F1", "vector": "exposed_service", "severity": "HIGH",
            "asset_id": "a1", "host": "api.acme.com", "title": "exposed admin"}


def _future():
    return (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()


def test_ingest_dispatch_claim_and_report(client):
    assert client.post("/findings", json=_FINDING).status_code == 201

    r = client.post("/runs", json={"finding_id": "F1", "posture": "external"})
    assert r.status_code == 201
    run_id = r.json()["id"]
    assert r.json()["status"] == "dispatched"

    # A worker claims it.
    claim = client.get("/internal/runs/claim", params={"posture": "external"}, headers=_AUTH)
    assert claim.status_code == 200
    job = claim.json()
    assert job["run_id"] == run_id and job["finding"]["id"] == "F1"
    assert job["scope"] == ["acme.com"]

    # …runs the loop and reports the verdict back.
    done = client.post(f"/internal/runs/{run_id}/result",
                       json={"verdict": _VERDICT, "audit": []}, headers=_AUTH).json()
    assert done["status"] == "completed"
    assert done["verdict"] == "EXPLOITABLE"
    assert done["evidence"][0]["tool"] == "http_probe"


def test_claim_empty_queue_is_204(client):
    assert client.get("/internal/runs/claim", params={"posture": "external"},
                      headers=_AUTH).status_code == 204


def test_internal_api_requires_worker_token(client):
    assert client.get("/internal/runs/claim", params={"posture": "external"}).status_code == 401
    assert client.post("/internal/runs/x/result", json={"verdict": None}).status_code == 401


def test_run_on_unknown_finding_is_404(client):
    assert client.post("/runs", json={"finding_id": "nope", "posture": "external"}).status_code == 404


def test_exploit_tier_denied_without_authorization(client):
    client.post("/findings", json=_FINDING)
    run = client.post("/runs", json={"finding_id": "F1", "posture": "external",
                                     "tier": ACTIVE_INVASIVE}).json()
    assert run["status"] == "denied" and "needs_authorization" in run["error"]


def test_authorization_enables_exploit_dispatch(client):
    client.post("/findings", json=_FINDING)
    auth = {"id": "A1", "target": "acme.com", "max_tier": ACTIVE_INVASIVE,
            "authorized_by": "andy", "blast_radius_note": "lab host", "expires_at": _future()}
    assert client.post("/authorizations", json=auth).status_code == 201
    run = client.post("/runs", json={"finding_id": "F1", "posture": "external",
                                     "tier": ACTIVE_INVASIVE, "authorization_id": "A1"}).json()
    assert run["status"] == "dispatched"


def test_authorization_without_blast_note_is_422(client):
    bad = {"id": "A2", "target": "acme.com", "max_tier": ACTIVE_INVASIVE,
           "authorized_by": "andy", "blast_radius_note": "  ", "expires_at": _future()}
    assert client.post("/authorizations", json=bad).status_code == 422


def test_index_serves_ui(client):
    r = client.get("/")
    assert r.status_code == 200 and "Spellbook" in r.text


def test_list_runs(client):
    client.post("/findings", json=_FINDING)
    client.post("/runs", json={"finding_id": "F1", "posture": "internal"})
    runs = client.get("/runs").json()
    assert len(runs) == 1 and runs[0]["posture"] == "internal"
