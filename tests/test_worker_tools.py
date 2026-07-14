"""The SDK-MCP bridge: every runner tool routes through dispatch() → decide().

Invokes each in-process SDK tool's handler directly (no live model) and asserts
the server-side enforcement — scope, posture, tier/authorization — still runs, and
that a handler exception is surfaced (allowed=True, error set) rather than denied.
"""

import json
from datetime import datetime, timedelta, timezone

import anyio
import pytest

from spellbook.control.ingest.model import Posture
from spellbook.control.safety.authorization import Authorization
from spellbook.runner.audit import AuditSink
from spellbook.runner.dispatch import RunContext
from spellbook.runner.tools import registry
from spellbook.safety.classify import ACTIVE_INVASIVE
from spellbook.worker import tools as wt


def _ctx(posture=Posture.EXTERNAL, scope={"acme.com"}, authorizations=()):
    return RunContext(posture=posture, scope_allowlist=set(scope),
                      authorizations=list(authorizations), audit=AuditSink())


def _by_name(ctx):
    return {t.name: t for t in wt.build_sdk_tools(ctx)}


def _call(sdk_tool, **args) -> dict:
    out = anyio.run(lambda: sdk_tool.handler(args))
    return json.loads(out["content"][0]["text"])


def test_allowed_tool_names_are_namespaced():
    ctx = _ctx()
    names = wt.allowed_tool_names(ctx)
    assert names and all(n.startswith("mcp__runner__") for n in names)


def test_in_scope_call_is_allowed_and_audited():
    ctx = _ctx()
    tool = _by_name(ctx)["http_probe"]
    res = _call(tool, target="api.acme.com", params={})
    assert res["allowed"] is True
    assert ctx.audit.events and ctx.audit.events[-1].allowed is True


def test_out_of_scope_call_is_denied():
    ctx = _ctx(scope={"other.com"})
    res = _call(_by_name(ctx)["http_probe"], target="api.acme.com")
    assert res["allowed"] is False and "out_of_scope" in res["reason"]


def test_exploit_tier_denied_without_authorization():
    ctx = _ctx()
    # run_poc is the active-invasive tool; no covering authorization → denied.
    res = _call(_by_name(ctx)["run_poc"], target="api.acme.com", params={})
    assert res["allowed"] is False and "needs_authorization" in res["reason"]


def test_exploit_tier_allowed_with_authorization():
    auth = Authorization(id="A1", target="acme.com", max_tier=ACTIVE_INVASIVE,
                         authorized_by="andy", blast_radius_note="lab",
                         expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
    ctx = _ctx(authorizations=[auth])
    res = _call(_by_name(ctx)["run_poc"], target="api.acme.com", params={})
    assert res["allowed"] is True


def test_handler_error_is_surfaced_not_denied(monkeypatch):
    ctx = _ctx()
    tool_name = "http_probe"
    original = registry.get(tool_name)

    def boom(target, params):
        raise RuntimeError("kaboom")

    monkeypatch.setitem(registry._REGISTRY, tool_name,
                        registry.Tool(name=original.name, tier=original.tier,
                                      postures=original.postures, handler=boom))
    res = _call(_by_name(ctx)[tool_name], target="api.acme.com")
    assert res["allowed"] is True and "kaboom" in (res["error"] or "")


def test_posture_scopes_the_tool_set():
    ext = {t.name for t in wt.build_sdk_tools(_ctx(posture=Posture.EXTERNAL))}
    internal = {t.name for t in wt.build_sdk_tools(_ctx(posture=Posture.INTERNAL))}
    assert ext and internal and ext != internal
