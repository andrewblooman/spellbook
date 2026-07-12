"""Per-target authorization records for the full-exploit tier.

Non-destructive validation runs freely inside scope. Actually *executing* an
exploit (real PoC payload, real privilege escalation) is denied by default and
requires an explicit :class:`Authorization` that names the exact target, the
highest tier permitted, who signed off, a blast-radius note, and an expiry.

This mirrors the deterministic-classifier philosophy of the original spellbook:
the model's intent is advisory; whether an invasive call runs is decided here by
data (an unexpired, in-scope authorization), never by the agent.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

from spellbook.safety.classify import ACTIVE_INVASIVE, ACTIVE_NONINVASIVE, PASSIVE
from spellbook.control.safety.scope import target_in_scope

# Ordered severity of side-effect tiers; a higher rank needs stronger authorization.
_TIER_RANK = {PASSIVE: 0, ACTIVE_NONINVASIVE: 1, ACTIVE_INVASIVE: 2}


@dataclass(frozen=True)
class Authorization:
    """A signed grant to run up to ``max_tier`` against ``target`` until ``expires_at``.

    ``target`` is an owned-asset scope entry (host / IP / CIDR). ``expires_at``
    must be timezone-aware.
    """

    id: str
    target: str
    max_tier: str
    authorized_by: str
    blast_radius_note: str
    expires_at: datetime

    def __post_init__(self) -> None:
        if self.max_tier not in _TIER_RANK:
            raise ValueError(f"unknown tier: {self.max_tier!r}")
        if not self.authorized_by.strip():
            raise ValueError("authorization requires authorized_by")
        if not self.blast_radius_note.strip():
            raise ValueError("authorization requires a blast_radius_note")
        if self.expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")

    def covers(self, *, target: str, tier: str, now: datetime | None = None) -> bool:
        """True if this authorization permits ``tier`` against ``target`` right now."""
        now = now or datetime.now(timezone.utc)
        if now >= self.expires_at:
            return False
        if _TIER_RANK.get(tier, 99) > _TIER_RANK[self.max_tier]:
            return False
        # The specific target must fall within this authorization's scope entry.
        return target_in_scope(target, {self.target})


def find_covering(
    authorizations: Iterable[Authorization],
    *,
    target: str,
    tier: str,
    now: datetime | None = None,
) -> Authorization | None:
    """Return the first authorization covering ``(target, tier)``, or ``None``."""
    now = now or datetime.now(timezone.utc)
    for auth in authorizations:
        if auth.covers(target=target, tier=tier, now=now):
            return auth
    return None
