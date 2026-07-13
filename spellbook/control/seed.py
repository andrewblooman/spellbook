"""Idempotent demo data for a fresh control-plane database.

Loaded on startup when ``SPELLBOOK_SEED=1`` so a newly-provisioned stack (e.g.
``docker compose up``) shows something real — two Wiz findings and one attack path
that spans both postures, with completed external + internal runs whose merged
:class:`StepResultRecord`s render in the ``StepChain``. Verdicts are written
straight to the store (no agent, no Gemini), mirroring what a real run persists.

Kept out of the request path and guarded so restarts never duplicate rows.
"""

from __future__ import annotations

from spellbook.control.agent.schema import EvidenceStep, StepVerdict, Verdict, VerdictLabel
from spellbook.control.ingest.model import (
    Asset, AttackPath, AttackStep, Finding, Posture, Source, StepStatus, Vector,
)
from spellbook.control.store.store import Store

_SEED_FINDING_ID = "F-1024"

_DEMO_VERDICT = Verdict(
    label=VerdictLabel.EXPLOITABLE, confidence=0.84,
    summary="Public endpoint reachable and unauthenticated; live SA reachable post-breach.",
    evidence_chain=[EvidenceStep(tool="http_probe", target="api.shop.example.com",
                                 observation="200, no auth header",
                                 interpretation="admin surface exposed to the internet")],
    reproduction="GET https://api.shop.example.com/admin",
)


def seed(store: Store) -> bool:
    """Seed demo data if absent. Returns True if it wrote, False if already present."""
    if store.get_finding(_SEED_FINDING_ID) is not None:
        return False

    f1 = Finding(id=_SEED_FINDING_ID, source=Source.WIZ, vector=Vector.EXPOSED_SERVICE,
                 severity="HIGH", title="Public API with weak auth → project-wide SA",
                 asset=Asset(id="a-api", host="api.shop.example.com", project="shop-prod"))
    f2 = Finding(id="F-1025", source=Source.WIZ, vector=Vector.IAM, severity="MEDIUM",
                 title="Over-privileged service account on app tier",
                 asset=Asset(id="a-app", host="10.4.2.11", project="shop-prod",
                             network_location="10.4.2.0/24"))
    store.save_finding(f1)
    store.save_finding(f2)

    ext, intl = Posture.EXTERNAL, Posture.INTERNAL
    path = AttackPath(
        id="P-1", finding_id=_SEED_FINDING_ID, name="Public API → SA takeover → data",
        source=Source.WIZ, entry_point="internet", impact="customer PII bucket",
        steps=[
            AttackStep(0, "public_exposure", "Reach the public admin API",
                       "internet", "api.shop.example.com", ext, "http_probe"),
            AttackStep(1, "exploit_cve", "Bypass weak auth on /admin",
                       "api.shop.example.com", "app-tier", ext, "http_probe"),
            AttackStep(2, "credential_theft", "Read borrowed SA token from metadata",
                       "app-tier", "metadata", intl, "metadata_token"),
            AttackStep(3, "iam_privesc", "Enumerate SA blast radius (actAs)",
                       "SA", "shop-prod", intl, "iam_blast_radius"),
            AttackStep(4, "data_access", "Reach the PII storage bucket east-west",
                       "app-tier", "pii-bucket", intl, "east_west_reach"),
        ],
    )
    store.save_attack_path(path)

    def _run(run_id: str, posture: Posture, results: list[StepVerdict]) -> None:
        store.create_run(run_id, f1, posture, "active_noninvasive",
                         status="completed", attack_path_id="P-1")
        store.record_verdict(run_id, _DEMO_VERDICT.model_copy(update={"step_results": results}))
        store.update_run(run_id, status="completed")

    # External run validates the two internet-facing steps; internal steps skipped.
    _run("run-ext", ext, [
        StepVerdict(step_index=0, status=StepStatus.VALIDATED, interpretation="200, no auth"),
        StepVerdict(step_index=1, status=StepStatus.VALIDATED, interpretation="auth bypassed"),
        StepVerdict(step_index=2, status=StepStatus.SKIPPED),
        StepVerdict(step_index=3, status=StepStatus.SKIPPED),
        StepVerdict(step_index=4, status=StepStatus.SKIPPED),
    ])
    # Internal run validates the lateral steps; the last one is blocked (refuted).
    _run("run-int", intl, [
        StepVerdict(step_index=2, status=StepStatus.VALIDATED,
                    interpretation="metadata SA token reachable"),
        StepVerdict(step_index=3, status=StepStatus.VALIDATED,
                    interpretation="iam.serviceAccounts.actAs granted"),
        StepVerdict(step_index=4, status=StepStatus.REFUTED,
                    interpretation="VPC-SC blocks east-west to the bucket"),
    ])
    return True
