"""Agent-worker entrypoint — the in-VPC pull loop.

Run one per posture (``python -m spellbook.worker.server``, ``SPELLBOOK_POSTURE``
set by the control plane / Cloud Run env). The loop claims a dispatched run,
builds the per-run :class:`RunContext` from the **claim response**
(posture/scope/authorizations — server-authoritative, never from the model), runs
the Claude Agent SDK validation loop, and posts the verdict + audit trail back.

No inbound port is needed (pull model), which is the simplest Cloud Run posture.

Environment:
- ``SPELLBOOK_POSTURE``       ``external`` | ``internal`` (which runs this worker claims).
- ``SPELLBOOK_CONTROL_URL``   base URL of the control plane's internal API.
- ``SPELLBOOK_WORKER_TOKEN``  bearer token presented on every control-plane call.
- ``SPELLBOOK_AGENT_MODEL``   Claude model id (default ``claude-opus-4-8``).
- ``ANTHROPIC_API_KEY``       model credentials (consumed by the Claude Agent SDK).
- ``SPELLBOOK_POLL_INTERVAL`` seconds to wait when the queue is empty (default 5).
"""

from __future__ import annotations

import asyncio
import os

from spellbook.control.ingest.model import Posture
from spellbook.runner.audit import AuditSink
from spellbook.runner.dispatch import RunContext
from spellbook.worker.control_client import ClaimedRun, ControlClient
from spellbook.worker.loop import DEFAULT_MODEL, AgentRun, AgentValidator


async def run_claimed(validator: AgentValidator, claimed: ClaimedRun) -> tuple[AgentRun, AuditSink]:
    """Run one claimed job. Returns the parsed result and the run's audit sink.

    The ``RunContext`` is built entirely from the control plane's claim response —
    the agent cannot widen its posture, scope, or authorizations.
    """
    audit = AuditSink()
    ctx = RunContext(
        posture=claimed.posture,
        scope_allowlist=set(claimed.scope),
        authorizations=list(claimed.authorizations),
        audit=audit,
    )
    result = await validator.run(
        finding=claimed.finding, posture=claimed.posture, ctx=ctx,
        attack_path=claimed.attack_path,
    )
    return result, audit


async def poll_once(validator: AgentValidator, client: ControlClient, posture: Posture) -> bool:
    """Claim + run + report one job. Returns True if a job was processed."""
    claimed = client.claim(posture)
    if claimed is None:
        return False
    result, audit = await run_claimed(validator, claimed)
    client.post_result(claimed.run_id, verdict=result.verdict, error=result.error,
                       audit_events=audit.events)
    return True


async def serve() -> None:  # pragma: no cover - process loop
    posture = Posture(os.environ.get("SPELLBOOK_POSTURE", "external"))
    control_url = os.environ["SPELLBOOK_CONTROL_URL"]
    token = os.environ.get("SPELLBOOK_WORKER_TOKEN", "")
    model = os.environ.get("SPELLBOOK_AGENT_MODEL", DEFAULT_MODEL)
    idle = float(os.environ.get("SPELLBOOK_POLL_INTERVAL", "5"))

    validator = AgentValidator(model=model)
    client = ControlClient(control_url, token)
    while True:
        try:
            worked = await poll_once(validator, client, posture)
        except Exception as exc:  # never let one bad job kill the worker loop
            print(f"worker: poll error: {exc}", flush=True)
            worked = False
        if not worked:
            await asyncio.sleep(idle)


def main() -> None:  # pragma: no cover - process entrypoint
    asyncio.run(serve())


if __name__ == "__main__":  # pragma: no cover
    main()
