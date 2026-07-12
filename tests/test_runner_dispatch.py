"""Tests for the runner's enforcement dispatch path.

Exercises scope/tier/authorization enforcement and auditing through the same
``dispatch`` that both attack-runners use, plus the built-in tool wiring.
"""

from datetime import datetime, timedelta, timezone

import pytest

from spellbook.safety.classify import ACTIVE_INVASIVE, ACTIVE_NONINVASIVE, PASSIVE
from spellbook.control.ingest.model import Posture
from spellbook.control.safety.authorization import Authorization
from spellbook.runner.audit import AuditSink
from spellbook.runner.dispatch import RunContext, dispatch
from spellbook.runner.tools import registry
from spellbook.runner.tools.registry import Tool


@pytest.fixture
def fake_tools():
    """Register throwaway tools of each tier; unregister after the test."""
    calls: list[str] = []
    registry.register(Tool("t_passive", PASSIVE, frozenset({Posture.EXTERNAL}),
                           handler=lambda t, p: calls.append(t) or {"ran": "passive"}))
    registry.register(Tool("t_invasive", ACTIVE_INVASIVE, frozenset({Posture.EXTERNAL}),
                           handler=lambda t, p: calls.append(t) or {"ran": "invasive"}))
    registry.register(Tool("t_boom", PASSIVE, frozenset({Posture.EXTERNAL}),
                           handler=lambda t, p: (_ for _ in ()).throw(RuntimeError("boom"))))
    registry.register(Tool("t_internal", PASSIVE, frozenset({Posture.INTERNAL}),
                           handler=lambda t, p: {"ran": "internal"}))
    yield calls
    for name in ("t_passive", "t_invasive", "t_boom", "t_internal"):
        registry.unregister(name)


def _ctx(**kw):
    base = dict(posture=Posture.EXTERNAL, scope_allowlist={"acme.com"}, audit=AuditSink())
    base.update(kw)
    return RunContext(**base)


def _auth_for(target):
    return Authorization(
        id="A1", target=target, max_tier=ACTIVE_INVASIVE, authorized_by="andy",
        blast_radius_note="lab", expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )


def test_passive_in_scope_runs(fake_tools):
    ctx = _ctx()
    res = dispatch(ctx, "t_passive", "api.acme.com")
    assert res.allowed and res.observation == {"ran": "passive"}
    assert fake_tools == ["api.acme.com"]
    assert ctx.audit.events[-1].allowed is True


def test_out_of_scope_denied_and_handler_not_called(fake_tools):
    ctx = _ctx()
    res = dispatch(ctx, "t_passive", "evil.org")
    assert res.allowed is False and "out_of_scope" in res.reason
    assert fake_tools == []                      # handler never ran
    assert ctx.audit.events[-1].allowed is False


def test_invasive_denied_without_authorization(fake_tools):
    ctx = _ctx()
    res = dispatch(ctx, "t_invasive", "api.acme.com")
    assert res.allowed is False and "needs_authorization" in res.reason
    assert fake_tools == []


def test_invasive_allowed_with_authorization(fake_tools):
    ctx = _ctx(authorizations=[_auth_for("acme.com")])
    res = dispatch(ctx, "t_invasive", "api.acme.com")
    assert res.allowed and res.observation == {"ran": "invasive"}


def test_posture_mismatch_denied(fake_tools):
    ctx = _ctx(posture=Posture.EXTERNAL)
    res = dispatch(ctx, "t_internal", "api.acme.com")
    assert res.allowed is False and "posture_mismatch" in res.reason


def test_unknown_tool_denied(fake_tools):
    res = dispatch(_ctx(), "nope", "api.acme.com")
    assert res.allowed is False and res.reason == "unknown_tool"


def test_handler_error_is_surfaced_and_audited(fake_tools):
    ctx = _ctx()
    res = dispatch(ctx, "t_boom", "api.acme.com")
    assert res.allowed is True and res.error == "boom" and res.observation is None
    assert res.reason == "handler_error"          # not the policy-allow reason
    assert ctx.audit.events[-1].detail == {"error": "boom"}


# --- built-in tool wiring -------------------------------------------------
def test_builtin_tools_registered_with_expected_tiers():
    import spellbook.runner.tools  # noqa: F401  (ensure import side effects)
    assert registry.get("reachability").tier == PASSIVE
    assert registry.get("http_probe").tier == ACTIVE_NONINVASIVE
    assert registry.get("run_poc").tier == ACTIVE_INVASIVE


def test_tools_for_posture_filters():
    from spellbook.runner.tools import tools_for  # re-export check
    external = {t.name for t in tools_for(Posture.EXTERNAL)}
    assert {"reachability", "http_probe", "run_poc"} <= external
