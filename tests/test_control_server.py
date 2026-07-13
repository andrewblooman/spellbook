"""Tests for the env-driven control-plane composition root.

Confirms ``create_app_from_env`` wires a working app from the environment: seeding
populates the DB, and (with no Gemini key) a run that clears the scope gate fails
loudly via the DisabledAgent rather than silently doing nothing.
"""

import pytest
from fastapi.testclient import TestClient

from spellbook.control import server


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("SPELLBOOK_DATABASE_URL", "sqlite://")
    monkeypatch.setenv("SPELLBOOK_SEED", "1")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
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


def test_no_key_uses_disabled_agent():
    assert isinstance(server._build_agent(), server.DisabledAgent)


def test_disabled_agent_launch_raises_clear_error(env):
    # In scope → the run clears decide(), reaches the agent, and fails loudly.
    env.setenv("SPELLBOOK_SCOPE", "10.4.2.0/24")
    client = TestClient(server.create_app_from_env(), raise_server_exceptions=False)
    resp = client.post("/runs", json={"finding_id": "F-1025", "posture": "external"})
    assert resp.status_code == 500  # RuntimeError from DisabledAgent.launch surfaced, not swallowed


def test_out_of_scope_run_is_gracefully_denied(env):
    env.setenv("SPELLBOOK_SCOPE", "")  # nothing owned → decide() denies before the agent
    client = TestClient(server.create_app_from_env())
    resp = client.post("/runs", json={"finding_id": "F-1025", "posture": "external"})
    assert resp.status_code == 201 and resp.json()["status"] == "denied"


def test_runner_minter_requires_configured_url(env, monkeypatch):
    monkeypatch.delenv("SPELLBOOK_RUNNER_EXTERNAL_URL", raising=False)
    from spellbook.control.ingest.model import Posture

    mint = server._runner_minter()
    with pytest.raises(RuntimeError, match="no runner URL"):
        mint(Posture.EXTERNAL)


def test_runner_minter_builds_endpoint_with_token(monkeypatch):
    monkeypatch.setenv("SPELLBOOK_RUNNER_EXTERNAL_URL", "http://runner-external:8000/mcp")
    monkeypatch.setenv("SPELLBOOK_RUNNER_TOKEN", "tok123")
    from spellbook.control.ingest.model import Posture

    ep = server._runner_minter()(Posture.EXTERNAL)
    assert ep.url == "http://runner-external:8000/mcp"
    assert ep.auth_header == {"Authorization": "Bearer tok123"}
