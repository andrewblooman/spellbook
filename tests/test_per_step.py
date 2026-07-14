"""Per-step validation through the orchestrator + the attack-path API.

Step results are reported by the worker via `record_result` / the internal API and
merged onto the path for the StepChain view.
"""

import json

import pytest
from fastapi.testclient import TestClient

from spellbook.control.agent.schema import Verdict
from spellbook.control.app import create_app
from spellbook.control.ingest.model import (
    Asset, AttackPath, AttackStep, Finding, Posture, Source, Vector,
)
from spellbook.control.orchestrator import Orchestrator
from spellbook.control.store.store import Store, init_engine

_VERDICT_STEPS = {
    "label": "INCONCLUSIVE", "confidence": 0.5, "summary": "external portion holds",
    "evidence_chain": [],
    "step_results": [
        {"step_index": 0, "status": "validated", "observation": "443 open",
         "interpretation": "reachable"},
        {"step_index": 1, "status": "validated", "observation": "no auth"},
        {"step_index": 2, "status": "skipped", "observation": "internal step"},
    ],
}

_WORKER_TOKEN = "wtok"
_AUTH = {"Authorization": f"Bearer {_WORKER_TOKEN}"}


def _finding():
    return Finding(id="F1", source=Source.MANUAL, vector=Vector.EXPOSED_SERVICE, severity="HIGH",
                   title="exposed admin", asset=Asset(id="a1", host="api.acme.com"))


def _path():
    return AttackPath(id="P1", finding_id="F1", name="admin → db",
                      steps=[AttackStep(index=0, technique="public_exposure", posture=Posture.EXTERNAL),
                             AttackStep(index=1, technique="auth_bypass", posture=Posture.EXTERNAL),
                             AttackStep(index=2, technique="iam_privesc", posture=Posture.INTERNAL)])


def _orch():
    store = Store(init_engine())
    return store, Orchestrator(store=store, scope_provider=lambda: {"acme.com"})


def test_run_with_path_persists_step_results():
    store, orch = _orch()
    store.save_finding(_finding())
    store.save_attack_path(_path())
    run_id = orch.start_run(_finding(), Posture.EXTERNAL, attack_path=_path())
    orch.claim(Posture.EXTERNAL)
    run = orch.record_result(run_id, verdict=Verdict.model_validate(_VERDICT_STEPS))
    assert run.attack_path_id == "P1"
    assert {sr.step_index for sr in run.step_results} == {0, 1, 2}
    assert len(store.path_step_results("P1")) == 3


# --- API ------------------------------------------------------------------
@pytest.fixture
def client():
    store = Store(init_engine())
    orch = Orchestrator(store=store, scope_provider=lambda: {"acme.com"})
    return TestClient(create_app(orch, store, worker_token=_WORKER_TOKEN))


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
    assert run["attack_path_id"] == "MP1" and run["status"] == "dispatched"

    client.get("/internal/runs/claim", params={"posture": "external"}, headers=_AUTH)
    done = client.post(f"/internal/runs/{run['id']}/result",
                       json={"verdict": _VERDICT_STEPS, "audit": []}, headers=_AUTH).json()
    assert len(done["step_results"]) == 3
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
    assert client.post("/wiz/ingest", json={"first": 5}).status_code == 502
