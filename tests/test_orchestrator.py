"""End-to-end orchestrator tests with fakes (no GCP, no model, no worker).

The orchestrator now dispatches runs (a Cloud Run agent-worker claims + reports
back) rather than launching an in-process agent, so the flow is:
start_run → gate → dispatched → claim → record_result.
"""

import json
from datetime import datetime, timedelta, timezone

from spellbook.control.agent.schema import Verdict
from spellbook.control.ingest.model import Asset, Finding, Posture, Source, Vector
from spellbook.control.orchestrator import Orchestrator
from spellbook.control.safety.authorization import Authorization
from spellbook.control.store.store import Store, init_engine
from spellbook.safety.classify import ACTIVE_INVASIVE, ACTIVE_NONINVASIVE

_VERDICT_JSON = json.dumps({
    "label": "EXPLOITABLE", "confidence": 0.9, "summary": "open and unauthenticated",
    "evidence_chain": [{"tool": "http_probe", "target": "api.acme.com",
                        "observation": "200 no auth", "interpretation": "admin exposed"}],
    "reproduction": "GET /admin", "attack_path": [],
})


def _finding():
    return Finding(id="F1", source=Source.MANUAL, vector=Vector.EXPOSED_SERVICE, severity="HIGH",
                   title="exposed admin", asset=Asset(id="a1", host="api.acme.com"))


def _orch(scope={"acme.com"}):
    store = Store(init_engine())
    return store, Orchestrator(store=store, scope_provider=lambda: set(scope))


def test_noninvasive_run_dispatches():
    store, orch = _orch()
    run_id = orch.start_run(_finding(), Posture.EXTERNAL, tier=ACTIVE_NONINVASIVE)
    assert store.get_run(run_id).status == "dispatched"


def test_out_of_scope_denied_before_dispatch():
    store, orch = _orch(scope={"other.com"})
    run_id = orch.start_run(_finding(), Posture.EXTERNAL, tier=ACTIVE_NONINVASIVE)
    run = store.get_run(run_id)
    assert run.status == "denied" and "out_of_scope" in run.error


def test_exploit_tier_denied_without_authorization():
    store, orch = _orch()
    run_id = orch.start_run(_finding(), Posture.EXTERNAL, tier=ACTIVE_INVASIVE)
    run = store.get_run(run_id)
    assert run.status == "denied" and "needs_authorization" in run.error


def test_claim_hands_worker_the_run_inputs():
    store, orch = _orch()
    store.save_authorization(Authorization(
        id="A1", target="acme.com", max_tier=ACTIVE_INVASIVE, authorized_by="andy",
        blast_radius_note="lab", expires_at=datetime.now(timezone.utc) + timedelta(hours=1)))
    run_id = orch.start_run(_finding(), Posture.EXTERNAL, tier=ACTIVE_INVASIVE,
                            authorization_id="A1")

    job = orch.claim(Posture.EXTERNAL)
    assert job.run_id == run_id
    assert job.finding.id == "F1"
    assert job.scope == {"acme.com"}
    assert [a.id for a in job.authorizations] == ["A1"]
    assert store.get_run(run_id).status == "running"  # claim flips it


def test_claim_is_posture_scoped_and_empty_returns_none():
    store, orch = _orch()
    orch.start_run(_finding(), Posture.INTERNAL)
    assert orch.claim(Posture.EXTERNAL) is None  # no external run dispatched
    assert orch.claim(Posture.INTERNAL) is not None


def test_record_result_persists_verdict_and_audit():
    store, orch = _orch()
    run_id = orch.start_run(_finding(), Posture.EXTERNAL)
    orch.claim(Posture.EXTERNAL)
    verdict = Verdict.model_validate_json(_VERDICT_JSON)
    audit = [{"tool": "http_probe", "target": "api.acme.com", "tier": ACTIVE_NONINVASIVE,
              "posture": "external", "allowed": True, "reason": "in scope"}]
    run = orch.record_result(run_id, verdict=verdict, audit_events=audit)
    assert run.status == "completed" and run.verdict_label == "EXPLOITABLE"
    assert len(run.evidence) == 1
    assert any(a.tool == "http_probe" for a in run.audit)


def test_record_result_without_verdict_marks_error():
    store, orch = _orch()
    run_id = orch.start_run(_finding(), Posture.EXTERNAL)
    orch.claim(Posture.EXTERNAL)
    run = orch.record_result(run_id, verdict=None, error="verdict_parse_failed")
    assert run.status == "error" and run.error == "verdict_parse_failed"


def test_record_result_only_accepts_a_claimed_run():
    store, orch = _orch()
    run_id = orch.start_run(_finding(), Posture.EXTERNAL)  # dispatched, not yet claimed
    verdict = Verdict.model_validate_json(_VERDICT_JSON)

    # A result for a run that was never claimed is a no-op — status stays dispatched.
    run = orch.record_result(run_id, verdict=verdict)
    assert run.status == "dispatched" and run.verdict_label is None

    # After a claim it completes; a second (duplicate) report is idempotent.
    orch.claim(Posture.EXTERNAL)
    assert orch.record_result(run_id, verdict=verdict).status == "completed"
    again = orch.record_result(run_id, verdict=None, error="late")
    assert again.status == "completed" and again.error is None


def test_pre_launch_decision_is_audited():
    store, orch = _orch(scope={"other.com"})
    run_id = orch.start_run(_finding(), Posture.EXTERNAL)
    run = store.get_run(run_id)
    assert any(a.tool == "orchestrator.pre_launch" and a.allowed is False for a in run.audit)
