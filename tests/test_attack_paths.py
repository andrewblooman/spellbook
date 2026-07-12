"""Phase A: attack-path model + store persistence (in-memory SQLite)."""

import pytest

from spellbook.safety.classify import ACTIVE_NONINVASIVE
from spellbook.control.agent.schema import Verdict, VerdictLabel, StepVerdict
from spellbook.control.ingest.model import (
    Asset, AttackPath, AttackStep, Finding, Posture, Source, StepStatus, Vector,
)
from spellbook.control.store.store import Store, init_engine


@pytest.fixture
def store():
    return Store(init_engine())


def _finding():
    return Finding(id="F1", source=Source.WIZ, vector=Vector.EXPOSED_SERVICE, severity="HIGH",
                   title="exposed admin", asset=Asset(id="a1", host="api.acme.com"))


def _path():
    return AttackPath(
        id="P1", finding_id="F1", name="admin → data", source=Source.WIZ,
        entry_point="internet", impact="read prod db",
        steps=[
            AttackStep(index=0, technique="public_exposure", from_entity="internet",
                       to_entity="api.acme.com", posture=Posture.EXTERNAL,
                       suggested_tool="reachability"),
            AttackStep(index=1, technique="auth_bypass", from_entity="api.acme.com",
                       to_entity="admin panel", posture=Posture.EXTERNAL,
                       suggested_tool="http_probe"),
            AttackStep(index=2, technique="iam_privesc", from_entity="admin panel",
                       to_entity="prod db", posture=Posture.INTERNAL),
        ],
    )


def test_save_and_get_attack_path_with_steps(store):
    store.save_finding(_finding())
    store.save_attack_path(_path())
    got = store.get_attack_path("P1")
    assert got is not None and got.name == "admin → data" and len(got.steps) == 3
    assert got.steps[0].technique == "public_exposure"
    assert got.steps[2].posture is Posture.INTERNAL
    assert got.source is Source.WIZ


def test_save_attack_path_replaces_steps(store):
    store.save_finding(_finding())
    store.save_attack_path(_path())
    shorter = AttackPath(id="P1", finding_id="F1", name="trimmed",
                         steps=[AttackStep(index=0, technique="public_exposure")])
    store.save_attack_path(shorter)
    got = store.get_attack_path("P1")
    assert got.name == "trimmed" and len(got.steps) == 1


def test_attack_paths_for_finding(store):
    store.save_finding(_finding())
    store.save_attack_path(_path())
    paths = store.attack_paths_for_finding("F1")
    assert len(paths) == 1 and paths[0].id == "P1"


def test_run_records_step_results_and_merges_by_path(store):
    store.save_finding(_finding())
    store.save_attack_path(_path())
    # External run validates steps 0-1; step 2 (internal) skipped this run.
    store.create_run("R-ext", _finding(), Posture.EXTERNAL, ACTIVE_NONINVASIVE,
                     status="running", attack_path_id="P1")
    verdict_ext = Verdict(
        label=VerdictLabel.INCONCLUSIVE, confidence=0.5, summary="external portion holds",
        step_results=[
            StepVerdict(step_index=0, status=StepStatus.VALIDATED, observation="443 open"),
            StepVerdict(step_index=1, status=StepStatus.VALIDATED, observation="no auth"),
            StepVerdict(step_index=2, status=StepStatus.SKIPPED, observation="internal"),
        ],
    )
    store.record_verdict("R-ext", verdict_ext)

    run = store.get_run("R-ext")
    assert {sr.step_index for sr in run.step_results} == {0, 1, 2}

    # Internal run validates step 2.
    store.create_run("R-int", _finding(), Posture.INTERNAL, ACTIVE_NONINVASIVE,
                     status="running", attack_path_id="P1")
    store.record_verdict("R-int", Verdict(
        label=VerdictLabel.EXPLOITABLE, confidence=0.8, summary="pivot works",
        step_results=[StepVerdict(step_index=2, status=StepStatus.VALIDATED,
                                  observation="assumed SA role")]))

    merged = store.path_step_results("P1")
    # 3 from external + 1 from internal, ordered by step index
    assert len(merged) == 4
    assert merged[-1].step_index == 2 and merged[-1].status == "validated"


def test_list_findings(store):
    store.save_finding(_finding())
    findings = store.list_findings()
    assert len(findings) == 1 and findings[0].id == "F1"
