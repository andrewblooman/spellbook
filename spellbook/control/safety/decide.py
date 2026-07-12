"""The single enforcement point for whether a runner tool call may execute.

Both the control-plane orchestrator (before launching an exploit-tier run) and
the runner (independently, per tool call — defense in depth) call :func:`decide`.
It combines the three deterministic checks in strict order:

1. **scope** — the target must be on the owned-asset allowlist, else hard deny;
2. **default ceiling** — ``passive`` and ``active_noninvasive`` run freely in scope;
3. **authorization** — ``active_invasive`` (full-exploit) runs only with a valid,
   unexpired :class:`~spellbook.control.safety.authorization.Authorization`.

The result is a :class:`Decision` carrying a human-readable reason, which the
caller writes to the audit log regardless of outcome.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

from spellbook.safety.classify import ACTIVE_INVASIVE, ACTIVE_NONINVASIVE, PASSIVE
from spellbook.control.safety.authorization import Authorization, find_covering
from spellbook.control.safety.scope import target_in_scope

# Tiers permitted in scope without a per-target authorization (the default ceiling).
DEFAULT_ALLOWED = frozenset({PASSIVE, ACTIVE_NONINVASIVE})


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str


def decide(
    *,
    tier: str,
    target: str,
    scope_allowlist: set[str],
    authorizations: Iterable[Authorization] = (),
    now: datetime | None = None,
) -> Decision:
    """Decide whether a ``tier`` tool call against ``target`` may run."""
    now = now or datetime.now(timezone.utc)

    if not target_in_scope(target, set(scope_allowlist)):
        return Decision(False, f"out_of_scope: {target!r} is not on the owned-asset allowlist")

    if tier in DEFAULT_ALLOWED:
        return Decision(True, f"in_scope: tier {tier!r} within default ceiling")

    if tier == ACTIVE_INVASIVE:
        auth = find_covering(authorizations, target=target, tier=tier, now=now)
        if auth is None:
            return Decision(
                False,
                f"needs_authorization: tier {tier!r} on {target!r} requires a valid Authorization",
            )
        return Decision(True, f"authorized by {auth.id!r} until {auth.expires_at.isoformat()}")

    return Decision(False, f"unknown_tier: {tier!r}")
