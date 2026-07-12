"""Append-only audit trail for the attack-runner.

Every dispatch — allowed or denied — writes one :class:`AuditEvent`. This is the
tamper-evident record of what the agent tried and what the runner permitted; the
control plane later persists these alongside the run's evidence chain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class AuditEvent:
    ts: datetime
    tool: str
    target: str
    tier: str
    posture: str
    allowed: bool
    reason: str
    detail: dict = field(default_factory=dict)


class AuditSink:
    """In-memory sink. Subclass/replace to fan out to the store or GCS."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(
        self,
        *,
        tool: str,
        target: str,
        tier: str,
        posture: str,
        allowed: bool,
        reason: str,
        detail: dict | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            ts=datetime.now(timezone.utc),
            tool=tool,
            target=target,
            tier=tier,
            posture=posture,
            allowed=allowed,
            reason=reason,
            detail=detail or {},
        )
        self.events.append(event)
        return event
