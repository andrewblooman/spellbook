"""Smoke tests for the runner MCP server binding + env context loading."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from spellbook.safety.classify import ACTIVE_INVASIVE
from spellbook.control.ingest.model import Posture
from spellbook.runner.dispatch import RunContext
from spellbook.runner import server


def test_context_from_env_reads_posture_and_scope(monkeypatch):
    monkeypatch.setenv("SPELLBOOK_POSTURE", "internal")
    monkeypatch.setenv("SPELLBOOK_SCOPE", "Acme.com, 10.0.0.0/24")
    monkeypatch.delenv("SPELLBOOK_AUTHORIZATIONS", raising=False)
    ctx = server.context_from_env()
    assert ctx.posture is Posture.INTERNAL
    assert ctx.scope_allowlist == {"acme.com", "10.0.0.0/24"}
    assert list(ctx.authorizations) == []


def test_authorizations_from_env_parses_file(tmp_path, monkeypatch):
    path = tmp_path / "auth.json"
    path.write_text(json.dumps([{
        "id": "A1", "target": "10.0.0.0/24", "max_tier": ACTIVE_INVASIVE,
        "authorized_by": "andy", "blast_radius_note": "lab",
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
    }]))
    monkeypatch.setenv("SPELLBOOK_AUTHORIZATIONS", str(path))
    auths = server.authorizations_from_env()
    assert len(auths) == 1 and auths[0].id == "A1"


def test_build_server_registers_posture_tools():
    pytest.importorskip("mcp")
    import anyio

    ctx = RunContext(posture=Posture.EXTERNAL, scope_allowlist={"acme.com"})
    srv = server.build_server(ctx)
    tool_names = {t.name for t in anyio.run(srv.list_tools)}
    assert {"reachability", "http_probe", "run_poc"} <= tool_names
