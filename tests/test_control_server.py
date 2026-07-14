"""Tests for the env-driven control-plane composition root.

Confirms ``create_app_from_env`` wires a working app from the environment: seeding
populates the DB, the scope gate denies out-of-scope runs, an in-scope run reaches
``dispatched`` (a worker will claim it), and the ``/internal`` API is bearer-gated
when ``SPELLBOOK_WORKER_TOKEN`` is set.
"""

import pytest
from fastapi.testclient import TestClient

from spellbook.control import server


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("SPELLBOOK_DATABASE_URL", "sqlite://")
    monkeypatch.setenv("SPELLBOOK_SEED", "1")
    monkeypatch.delenv("SPELLBOOK_WORKER_TOKEN", raising=False)
    return monkeypatch


def test_seed_populates_findings_and_runs(env):
    env.setenv("SPELLBOOK_SCOPE", "")
    client = TestClient(server.create_app_from_env())
    findings = {f["id"] for f in client.get("/findings").json()}
    assert {"F-1024", "F-1025"} <= findings
    runs = client.get("/runs").json()
    assert {r["id"] for r in runs} == {"run-ext", "run-int"}
    # The merged attack-path view is one entry per step, internal winning over skipped.
    steps = client.get("/attack-paths/P-1").json()["step_results"]
    assert [(s["step_index"], s["status"]) for s in steps] == [
        (0, "validated"), (1, "validated"), (2, "validated"), (3, "validated"), (4, "refuted"),
    ]


def test_in_scope_run_is_dispatched(env):
    env.setenv("SPELLBOOK_SCOPE", "10.4.2.0/24")
    client = TestClient(server.create_app_from_env())
    resp = client.post("/runs", json={"finding_id": "F-1025", "posture": "external"})
    assert resp.status_code == 201 and resp.json()["status"] == "dispatched"


def test_out_of_scope_run_is_gracefully_denied(env):
    env.setenv("SPELLBOOK_SCOPE", "")  # nothing owned → decide() denies
    client = TestClient(server.create_app_from_env())
    resp = client.post("/runs", json={"finding_id": "F-1025", "posture": "external"})
    assert resp.status_code == 201 and resp.json()["status"] == "denied"


def test_internal_api_gated_when_token_set(env):
    env.setenv("SPELLBOOK_SCOPE", "")
    env.setenv("SPELLBOOK_WORKER_TOKEN", "secret")
    client = TestClient(server.create_app_from_env())
    assert client.get("/internal/runs/claim", params={"posture": "external"}).status_code == 401
    ok = client.get("/internal/runs/claim", params={"posture": "external"},
                    headers={"Authorization": "Bearer secret"})
    assert ok.status_code == 204  # authed, but nothing dispatched
