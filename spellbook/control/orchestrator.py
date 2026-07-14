"""The glue: a Finding × posture → a dispatched run → a persisted verdict.

The agent loop no longer runs here — it runs in a Cloud Run **agent-worker** inside
the VPC (Claude Agent SDK). The orchestrator's job is the control-plane half:

1. persist the finding and open a `Run`;
2. **pre-launch gate** (defense in depth) — run the same :func:`decide` the worker
   enforces, so an exploit-tier run with no covering authorization never even
   dispatches, and the decision is audited;
3. if permitted, mark the run ``dispatched`` — a worker for that posture will claim it;
4. :meth:`claim` hands a dispatched run's inputs (finding, attack path, scope,
   authorizations — server-authoritative) to a worker and flips it ``running``;
5. :meth:`record_result` persists the verdict + evidence + audit the worker reports back.

Dependencies are injected (store, scope provider) so the orchestrator is exercised
end-to-end with fakes — no GCP, no model, no worker.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from spellbook.control.agent.schema import Verdict
from spellbook.control.ingest.model import AttackPath, Finding, Posture
from spellbook.control.safety.authorization import Authorization
from spellbook.control.safety.decide import decide
from spellbook.control.store.models import Run
from spellbook.control.store.store import Store

# Re-export the tier constants so callers pick a tier without reaching into the
# legacy classify module.
from spellbook.safety.classify import ACTIVE_INVASIVE, ACTIVE_NONINVASIVE, PASSIVE  # noqa: F401


@dataclass(frozen=True)
class ClaimedJob:
    """A dispatched run handed to a worker. Inputs are server-authoritative."""

    run_id: str
    finding: Finding
    posture: Posture
    scope: set[str]
    authorizations: Sequence[Authorization]
    attack_path: AttackPath | None = None


@dataclass
class Orchestrator:
    store: Store
    scope_provider: Callable[[], set[str]]

    def start_run(
        self,
        finding: Finding,
        posture: Posture,
        *,
        tier: str = ACTIVE_NONINVASIVE,
        authorization_id: str | None = None,
        attack_path: AttackPath | None = None,
    ) -> str:
        """Open, gate, and (if permitted) dispatch a run. Returns the run id."""
        run_id = uuid.uuid4().hex
        target = finding.asset.target

        self.store.save_finding(finding)
        self.store.create_run(run_id, finding, posture, tier,
                              status="pending", authorization_id=authorization_id,
                              attack_path_id=attack_path.id if attack_path else None)

        decision = decide(
            tier=tier,
            target=target,
            scope_allowlist=self.scope_provider(),
            authorizations=self.store.active_authorizations(),
        )
        self.store.add_audit(run_id=run_id, tool="orchestrator.pre_launch", target=target,
                             tier=tier, posture=posture.value, allowed=decision.allow,
                             reason=decision.reason)
        if not decision.allow:
            self.store.update_run(run_id, status="denied", error=decision.reason)
            return run_id

        # A worker for this posture will claim it via `claim`.
        self.store.update_run(run_id, status="dispatched")
        return run_id

    def claim(self, posture: Posture) -> ClaimedJob | None:
        """Hand the next dispatched run for ``posture`` to a worker, or ``None``.

        Scope and authorizations come from the control plane here — not from the
        worker, and never from the agent — so the agent cannot widen its own scope.
        """
        run = self.store.claim_dispatched_run(posture)
        if run is None:
            return None
        finding = self.store.get_finding(run.finding_id)
        attack_path = (self.store.get_attack_path(run.attack_path_id)
                       if run.attack_path_id else None)
        return ClaimedJob(
            run_id=run.id,
            finding=finding,
            posture=Posture(run.posture),
            scope=self.scope_provider(),
            authorizations=self.store.active_authorizations(),
            attack_path=attack_path,
        )

    def record_result(
        self,
        run_id: str,
        *,
        verdict: Verdict | None,
        error: str | None = None,
        audit_events: Sequence[dict] = (),
    ) -> Run | None:
        """Persist a worker's reported verdict + evidence + audit trail."""
        run = self.store.get_run(run_id)
        if run is None:
            return None

        for ev in audit_events:
            self.store.add_audit(
                run_id=run_id, tool=ev["tool"], target=ev["target"], tier=ev["tier"],
                posture=ev["posture"], allowed=ev["allowed"], reason=ev["reason"],
                detail=ev.get("detail"),
            )

        if verdict is not None:
            self.store.record_verdict(run_id, verdict)
            self.store.update_run(run_id, status="completed")
        else:
            self.store.update_run(
                run_id,
                status="error" if error else "completed_no_verdict",
                error=error,
            )
        return self.store.get_run(run_id)
