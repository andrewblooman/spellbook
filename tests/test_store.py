"""Tests for the SQLAlchemy control-plane store (in-memory SQLite)."""

from datetime import datetime, timedelta, timezone

import pytest

from spellbook.safety.classify import ACTIVE_INVASIVE, ACTIVE_NONINVASIVE
from spellbook.control.agent.schema import EvidenceStep, Verdict, VerdictLabel
from spellbook.control.ingest.model import Asset, Finding, Posture, Source, Vector
from spellbook.control.safety.authorization import Authorization
from spellbook.control.store.store import Store, init_engine


@pytest.fixture
def store():
    return Store(init_engine())


def _finding():
    return Finding(id="F1", source=Source.WIZ, vector=Vector.EXPOSED_SERVICE, severity="HIGH",
                   title="exposed admin", asset=Asset(id="a1", host="api.acme.com", project="p"))


def _verdict():
    return Verdict(
        label=VerdictLabel.EXPLOITABLE, confidence=0.8, summary="open",
        evidence_chain=[EvidenceStep(tool="http_probe", target="api.acme.com",
                                     observation="200", interpretation="no auth")],
        reproduction="GET /admin",
    )


def test_save_finding_and_create_run(store):
    f = _finding()
    store.save_finding(f)
    store.create_run("R1", f, Posture.EXTERNAL, ACTIVE_NONINVASIVE, status="running")
    run = store.get_run("R1")
    assert run.finding_id == "F1" and run.posture == "external" and run.status == "running"


def test_record_verdict_persists_evidence(store):
    f = _finding()
    store.save_finding(f)
    store.create_run("R1", f, Posture.EXTERNAL, ACTIVE_NONINVASIVE, status="running")
    store.record_verdict("R1", _verdict())
    run = store.get_run("R1")
    assert run.verdict_label == "EXPLOITABLE" and run.confidence == 0.8
    assert len(run.evidence) == 1 and run.evidence[0].tool == "http_probe"
    assert run.verdict["reproduction"] == "GET /admin"


def test_update_run_fields(store):
    f = _finding()
    store.save_finding(f)
    store.create_run("R1", f, Posture.INTERNAL, ACTIVE_NONINVASIVE)
    store.update_run("R1", status="denied", error="out_of_scope")
    run = store.get_run("R1")
    assert run.status == "denied" and run.error == "out_of_scope"


def test_audit_rows_recorded(store):
    f = _finding()
    store.save_finding(f)
    store.create_run("R1", f, Posture.EXTERNAL, ACTIVE_NONINVASIVE)
    store.add_audit(run_id="R1", tool="orchestrator.pre_launch", target="api.acme.com",
                    tier=ACTIVE_NONINVASIVE, posture="external", allowed=True, reason="ok")
    run = store.get_run("R1")
    assert len(run.audit) == 1 and run.audit[0].allowed is True


def test_update_run_unknown_id_raises(store):
    with pytest.raises(LookupError):
        store.update_run("missing", status="x")


def test_record_verdict_unknown_id_raises(store):
    with pytest.raises(LookupError):
        store.record_verdict("missing", _verdict())


def test_active_authorizations_excludes_expired(store):
    fresh = Authorization(id="A1", target="10.0.0.0/24", max_tier=ACTIVE_INVASIVE,
                          authorized_by="andy", blast_radius_note="lab",
                          expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
    stale = Authorization(id="A2", target="10.0.1.0/24", max_tier=ACTIVE_INVASIVE,
                          authorized_by="andy", blast_radius_note="lab",
                          expires_at=datetime.now(timezone.utc) + timedelta(seconds=1))
    store.save_authorization(fresh)
    store.save_authorization(stale)
    active = store.active_authorizations(now=datetime.now(timezone.utc) + timedelta(minutes=1))
    assert {a.id for a in active} == {"A1"}
