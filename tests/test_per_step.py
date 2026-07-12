"""Phase C: per-step validation through the orchestrator + the attack-path API."""

import json

import pytest
from fastapi.testclient import TestClient

from spellbook.safety.classify import ACTIVE_NONINVASIVE
from spellbook.control.agent.google_agent import GoogleAgentClient, RunnerEndpoint
from spellbook.control.app import create_app
from spellbook.control.ingest.model import (
    Asset, AttackPath, AttackStep, Finding, Posture, Source, Vector,
)
from spellbook.control.orchestrator import Orchestrator
from spellbook.control.store.store import Store, init_engine
from tests.test_google_agent import FakeInteractions

_VERDICT_STEPS = json.dumps({
    "label": "INCONCLUSIVE", "confidence": 0.5, "summary": "external portion holds",
    "evidence_chain": [],
    "step_results": [
        {"step_index": 0, "status": "validated", "observation": "443 open",
         "interpretation": "reachable"},
        {"step_index": 1, "status": "validated", "observation": "no auth"},
        {"step_index": 2, "status": "skipped", "observation": "internal step"},
    ],
})


def _finding():
    return Finding(id="F1", source=Source.MANUAL, vector=Vector.EXPOSED_SERVICE, severity="HIGH",
                   title="exposed admin", asset=Asset(id="a1", host="api.acme.com"))


def _path():
    return AttackPath(id="P1", finding_id="F1", name="admin → db",
                      steps=[AttackStep(index=0, technique="public_exposure", posture=Posture.EXTERNAL),
                             AttackStep(index=1, technique="auth_bypass", posture=Posture.EXTERNAL),
                             AttackStep(index=2, technique="iam_privesc", posture=Posture.INTERNAL)])


def _orch(backend):
    store = Store(init_engine())
    orch = Orchestrator(
        store=store, agent=GoogleAgentClient(backend, poll_interval=0),
        runner_minter=lambda p: RunnerEndpoint("https://runner/mcp", {"Authorization": "Bearer x"}),
        scope_provider=lambda: {"acme.com"},
    )
    return store, orch


def test_run_with_path_persists_step_results():
    store, orch = _orch(FakeInteractions(["running", "completed"], output_text=_VERDICT_STEPS))
    store.save_finding(_finding())
    store.save_attack_path(_path())
    run_id = orch.start_run(_finding(), Posture.EXTERNAL, attack_path=_path())
    run = orch.complete_run(run_id, sleep=lambda _s: None)
    assert run.attack_path_id == "P1"
    assert {sr.step_index for sr in run.step_results} == {0, 1, 2}
    # merged view for the path exposes the same results
    assert len(store.path_step_results("P1")) == 3


def test_prompt_includes_attack_path_steps():
    backend = FakeInteractions(["running"])
    store, orch = _orch(backend)
    store.save_finding(_finding())
    store.save_attack_path(_path())
    orch.start_run(_finding(), Posture.EXTERNAL, attack_path=_path())
    sent_input = backend.created_kwargs["input"]
    assert "Attack path" in sent_input and "step 0 [external] public_exposure" in sent_input


# --- API ------------------------------------------------------------------
@pytest.fixture
def client():
    store = Store(init_engine())
    orch = Orchestrator(
        store=store,
        agent=GoogleAgentClient(FakeInteractions(["running", "completed"],
                                                 output_text=_VERDICT_STEPS), poll_interval=0),
        runner_minter=lambda p: RunnerEndpoint("https://runner/mcp", {"Authorization": "Bearer x"}),
        scope_provider=lambda: {"acme.com"},
    )
    return TestClient(create_app(orch, store))


_MANUAL_PATH = {
    "id": "MP1",
    "finding": {"id": "MF1", "vector": "exposed_service", "severity": "HIGH",
                "asset_id": "a1", "host": "api.acme.com", "title": "manual test"},
    "name": "manual chain", "entry_point": "internet", "impact": "db",
    "steps": [
        {"technique": "public_exposure", "posture": "external", "suggested_tool": "reachability"},
        {"technique": "iam_privesc", "posture": "internal"},
    ],
}


def test_manual_attack_path_create_and_get(client):
    assert client.post("/attack-paths", json=_MANUAL_PATH).status_code == 201
    path = client.get("/attack-paths/MP1").json()
    assert path["source"] == "manual" and len(path["steps"]) == 2
    assert path["steps"][0]["technique"] == "public_exposure"


def test_run_against_path_shows_merged_step_results(client):
    client.post("/attack-paths", json=_MANUAL_PATH)
    run = client.post("/runs", json={"finding_id": "MF1", "posture": "external",
                                     "attack_path_id": "MP1"}).json()
    assert run["attack_path_id"] == "MP1"
    done = client.post(f"/runs/{run['id']}/complete").json()
    assert len(done["step_results"]) == 3
    # merged onto the path
    path = client.get("/attack-paths/MP1").json()
    assert len(path["step_results"]) == 3


def test_findings_list_and_detail(client):
    client.post("/attack-paths", json=_MANUAL_PATH)
    assert any(f["id"] == "MF1" for f in client.get("/findings").json())
    detail = client.get("/findings/MF1").json()
    assert detail["attack_paths"][0]["id"] == "MP1"


def test_run_with_unknown_path_is_404(client):
    client.post("/findings", json=_MANUAL_PATH["finding"])
    r = client.post("/runs", json={"finding_id": "MF1", "posture": "external",
                                   "attack_path_id": "nope"})
    assert r.status_code == 404


def test_wiz_ingest_without_config_is_502(client):
    # No WIZ_API_URL / creds in the test env → the client errors cleanly.
    assert client.post("/wiz/ingest", json={"first": 5}).status_code == 502
