"""The glue: a Finding × posture → a launched agent run → a persisted verdict.

Responsibilities, in order:
1. persist the finding and open a `Run`;
2. **pre-launch gate** (defense in depth) — run the same :func:`decide` the runner
   enforces, so an exploit-tier run with no covering authorization never even
   launches, and the decision is audited;
3. mint a scoped remote-MCP runner endpoint for the posture and launch the agent;
4. on completion, persist the verdict + evidence chain.

Dependencies are injected (store, agent client, runner minter, scope provider) so
the orchestrator is exercised end-to-end with fakes — no GCP, no Gemini.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass

from spellbook.control.agent.google_agent import GoogleAgentClient, RunnerEndpoint
from spellbook.control.ingest.model import AttackPath, Finding, Posture
from spellbook.control.safety.decide import decide
from spellbook.control.store.models import Run
from spellbook.control.store.store import Store

# Re-export the tier constants so callers pick a tier without reaching into the
# legacy classify module.
from spellbook.safety.classify import ACTIVE_INVASIVE, ACTIVE_NONINVASIVE, PASSIVE  # noqa: F401


@dataclass
class Orchestrator:
    store: Store
    agent: GoogleAgentClient
    runner_minter: Callable[[Posture], RunnerEndpoint]
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
        """Open, gate, and (if permitted) launch a run. Returns the run id."""
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

        runner = self.runner_minter(posture)
        interaction_id = self.agent.launch(finding=finding, posture=posture, runner=runner,
                                           attack_path=attack_path)
        self.store.update_run(run_id, status="running", agent_job_id=interaction_id)
        return run_id

    def complete_run(self, run_id: str, *, sleep=time.sleep) -> Run | None:
        """Poll the agent to completion and persist the verdict/evidence."""
        run = self.store.get_run(run_id)
        if run is None or run.status != "running" or not run.agent_job_id:
            return run

        result = self.agent.run_to_completion(run.agent_job_id, sleep=sleep)
        if result.verdict is not None:
            self.store.record_verdict(run_id, result.verdict)
            self.store.update_run(run_id, status="completed")
        else:
            self.store.update_run(
                run_id,
                status="completed_no_verdict" if result.done else "error",
                error=result.error,
            )
        return self.store.get_run(run_id)
