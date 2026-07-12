"""The runner's per-call enforcement path — the server-side "never trust the model".

Both attack-runners (external and internal) route every tool invocation through
:func:`dispatch`. In strict order it: resolves the tool, checks the tool is valid
for this run's posture, calls :func:`~spellbook.control.safety.decide.decide`
(scope + tier + authorization), audits the decision, and only then runs the
handler. A denied call never touches the network.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from spellbook.control.ingest.model import Posture
from spellbook.control.safety.authorization import Authorization
from spellbook.control.safety.decide import decide
from spellbook.runner import tools as _tools  # noqa: F401  (populate the registry)
from spellbook.runner.audit import AuditSink
from spellbook.runner.tools import registry


@dataclass
class RunContext:
    """Per-run enforcement context handed to the runner by the orchestrator."""

    posture: Posture
    scope_allowlist: set[str]
    authorizations: Sequence[Authorization] = ()
    audit: AuditSink = field(default_factory=AuditSink)


@dataclass(frozen=True)
class ToolResult:
    allowed: bool
    reason: str
    tool: str
    target: str
    observation: dict | None = None
    error: str | None = None


def dispatch(ctx: RunContext, tool_name: str, target: str, params: dict | None = None) -> ToolResult:
    params = params or {}
    tool = registry.get(tool_name)

    if tool is None:
        ctx.audit.record(tool=tool_name, target=target, tier="unknown",
                         posture=ctx.posture.value, allowed=False, reason="unknown_tool")
        return ToolResult(False, "unknown_tool", tool_name, target)

    if ctx.posture not in tool.postures:
        reason = f"posture_mismatch: {tool_name!r} not valid in {ctx.posture.value}"
        ctx.audit.record(tool=tool_name, target=target, tier=tool.tier,
                         posture=ctx.posture.value, allowed=False, reason=reason)
        return ToolResult(False, reason, tool_name, target)

    decision = decide(
        tier=tool.tier,
        target=target,
        scope_allowlist=set(ctx.scope_allowlist),
        authorizations=ctx.authorizations,
    )
    ctx.audit.record(tool=tool_name, target=target, tier=tool.tier,
                     posture=ctx.posture.value, allowed=decision.allow, reason=decision.reason)
    if not decision.allow:
        return ToolResult(False, decision.reason, tool_name, target)

    try:
        observation = tool.handler(target, params)
    except Exception as exc:  # handler failure ≠ policy denial; surface it, still audited
        ctx.audit.record(tool=tool_name, target=target, tier=tool.tier,
                         posture=ctx.posture.value, allowed=True,
                         reason="handler_error", detail={"error": str(exc)})
        return ToolResult(True, "handler_error", tool_name, target, error=str(exc))

    return ToolResult(True, decision.reason, tool_name, target, observation=observation)
