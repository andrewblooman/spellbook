"""End-to-end orchestrator tests with fakes (no GCP, no Gemini)."""

from datetime import datetime, timedelta, timezone

import pytest

from spellbook.safety.classify import ACTIVE_INVASIVE, ACTIVE_NONINVASIVE
from spellbook.control.agent.google_agent import GoogleAgentClient, RunnerEndpoint
from spellbook.control.ingest.model import Asset, Finding, Posture, Source, Vector
from spellbook.control.orchestrator import Orchestrator
from spellbook.control.safety.authorization import Authorization
from spellbook.control.store.store import Store, init_engine
from tests.test_google_agent import FakeInteractions, _VERDICT_JSON


def _finding():
    return Finding(id="F1", source=Source.MANUAL, vector=Vector.EXPOSED_SERVICE, severity="HIGH",
                   title="exposed admin", asset=Asset(id="a1", host="api.acme.com"))


def _orch(backend, scope={"acme.com"}):
    store = Store(init_engine())
    agent = GoogleAgentClient(backend, poll_interval=0)
    runner = RunnerEndpoint(url="https://runner/mcp", auth_header={"Authorization": "Bearer x"})
    return store, Orchestrator(
        store=store, agent=agent,
        runner_minter=lambda posture: runner,
        scope_provider=lambda: set(scope),
    )


def test_noninvasive_run_launches_and_completes():
    backend = FakeInteractions(["running", "completed"], output_text=_VERDICT_JSON)
    store, orch = _orch(backend)
    run_id = orch.start_run(_finding(), Posture.EXTERNAL, tier=ACTIVE_NONINVASIVE)
    assert store.get_run(run_id).status == "running"
    run = orch.complete_run(run_id, sleep=lambda _s: None)
    assert run.status == "completed" and run.verdict_label == "EXPLOITABLE"
    assert len(run.evidence) == 1


def test_out_of_scope_denied_before_launch():
    backend = FakeInteractions(["running"])
    store, orch = _orch(backend, scope={"other.com"})  # finding target not in scope
    run_id = orch.start_run(_finding(), Posture.EXTERNAL, tier=ACTIVE_NONINVASIVE)
    run = store.get_run(run_id)
    assert run.status == "denied" and "out_of_scope" in run.error
    assert run.agent_job_id is None                  # never launched
    assert backend.created_kwargs is None            # agent.create never called


def test_exploit_tier_denied_without_authorization():
    backend = FakeInteractions(["running"])
    store, orch = _orch(backend)
    run_id = orch.start_run(_finding(), Posture.EXTERNAL, tier=ACTIVE_INVASIVE)
    run = store.get_run(run_id)
    assert run.status == "denied" and "needs_authorization" in run.error
    assert backend.created_kwargs is None


def test_exploit_tier_launches_with_authorization():
    backend = FakeInteractions(["running", "completed"], output_text=_VERDICT_JSON)
    store, orch = _orch(backend)
    store.save_authorization(Authorization(
        id="A1", target="acme.com", max_tier=ACTIVE_INVASIVE, authorized_by="andy",
        blast_radius_note="lab", expires_at=datetime.now(timezone.utc) + timedelta(hours=1)))
    run_id = orch.start_run(_finding(), Posture.EXTERNAL, tier=ACTIVE_INVASIVE,
                            authorization_id="A1")
    assert store.get_run(run_id).status == "running"
    run = orch.complete_run(run_id, sleep=lambda _s: None)
    assert run.status == "completed"


def test_pre_launch_decision_is_audited():
    backend = FakeInteractions(["running"])
    store, orch = _orch(backend, scope={"other.com"})
    run_id = orch.start_run(_finding(), Posture.EXTERNAL)
    run = store.get_run(run_id)
    assert any(a.tool == "orchestrator.pre_launch" and a.allowed is False for a in run.audit)
