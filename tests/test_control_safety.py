"""Tests for the exploitability platform's enforced safety core.

This is the highest-risk surface (per the plan's §10): scope, the default
non-destructive ceiling, and the authorization-gated full-exploit tier. These
run without any agent, SDK, or network.
"""

from datetime import datetime, timedelta, timezone

import pytest

from spellbook.safety.classify import ACTIVE_INVASIVE, ACTIVE_NONINVASIVE, PASSIVE
from spellbook.control.safety.scope import target_in_scope
from spellbook.control.safety.authorization import Authorization, find_covering
from spellbook.control.safety.decide import decide


def _auth(**kw):
    base = dict(
        id="A1",
        target="10.0.0.0/24",
        max_tier=ACTIVE_INVASIVE,
        authorized_by="andy",
        blast_radius_note="isolated lab host, snapshot taken",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    base.update(kw)
    return Authorization(**base)


# --- target_in_scope ------------------------------------------------------
@pytest.mark.parametrize("target,allow,expected", [
    ("api.acme.com", {"acme.com"}, True),          # subdomain suffix
    ("acme.com", {"acme.com"}, True),              # exact host
    ("evil.org", {"acme.com"}, False),             # unowned host
    ("10.0.0.5", {"10.0.0.0/24"}, True),           # ip in cidr
    ("10.0.1.5", {"10.0.0.0/24"}, False),          # ip outside cidr
    ("10.0.0.0/28", {"10.0.0.0/24"}, True),        # cidr subnet of allowed cidr
    ("10.0.0.0/20", {"10.0.0.0/24"}, False),       # cidr wider than allowed
    ("10.0.0.5", set(), False),                    # empty allowlist → deny
    ("resource/xyz", {"resource/xyz"}, True),      # exact non-network asset id
])
def test_target_in_scope(target, allow, expected):
    assert target_in_scope(target, allow) is expected


# --- Authorization construction validation --------------------------------
def test_authorization_requires_blast_radius_note():
    with pytest.raises(ValueError):
        _auth(blast_radius_note="  ")


def test_authorization_requires_aware_expiry():
    with pytest.raises(ValueError):
        _auth(expires_at=datetime(2030, 1, 1))  # naive


def test_authorization_rejects_unknown_tier():
    with pytest.raises(ValueError):
        _auth(max_tier="nonsense")


# --- Authorization.covers -------------------------------------------------
def test_covers_in_scope_and_tier():
    a = _auth()
    assert a.covers(target="10.0.0.9", tier=ACTIVE_INVASIVE) is True


def test_covers_expired_is_false():
    a = _auth(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    assert a.covers(target="10.0.0.9", tier=ACTIVE_INVASIVE) is False


def test_covers_target_outside_scope():
    a = _auth(target="10.0.0.0/24")
    assert a.covers(target="10.0.1.9", tier=ACTIVE_INVASIVE) is False


def test_covers_tier_above_max_denied():
    a = _auth(max_tier=ACTIVE_NONINVASIVE)
    assert a.covers(target="10.0.0.9", tier=ACTIVE_INVASIVE) is False


def test_find_covering_picks_matching():
    a1 = _auth(id="A1", target="10.0.0.0/24")
    a2 = _auth(id="A2", target="192.168.0.0/24")
    found = find_covering([a1, a2], target="192.168.0.7", tier=ACTIVE_INVASIVE)
    assert found is not None and found.id == "A2"


# --- decide (the enforcement point) ---------------------------------------
def test_decide_out_of_scope_denied():
    d = decide(tier=PASSIVE, target="evil.org", scope_allowlist={"acme.com"})
    assert d.allow is False and "out_of_scope" in d.reason


def test_decide_passive_in_scope_allowed():
    d = decide(tier=PASSIVE, target="api.acme.com", scope_allowlist={"acme.com"})
    assert d.allow is True


def test_decide_noninvasive_is_default_ceiling():
    d = decide(tier=ACTIVE_NONINVASIVE, target="api.acme.com", scope_allowlist={"acme.com"})
    assert d.allow is True


def test_decide_invasive_denied_without_authorization():
    d = decide(tier=ACTIVE_INVASIVE, target="10.0.0.5", scope_allowlist={"10.0.0.0/24"})
    assert d.allow is False and "needs_authorization" in d.reason


def test_decide_invasive_allowed_with_authorization():
    d = decide(
        tier=ACTIVE_INVASIVE,
        target="10.0.0.5",
        scope_allowlist={"10.0.0.0/24"},
        authorizations=[_auth()],
    )
    assert d.allow is True and "authorized by" in d.reason


def test_decide_invasive_authorization_must_be_in_scope_target():
    # Authorization covers a different subnet than the (in-scope) target.
    d = decide(
        tier=ACTIVE_INVASIVE,
        target="10.0.0.5",
        scope_allowlist={"10.0.0.0/24"},
        authorizations=[_auth(target="192.168.0.0/24")],
    )
    assert d.allow is False and "needs_authorization" in d.reason
