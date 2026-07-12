"""Remote-MCP attack-runner server (deployed twice: external + internal).

Gemini's Managed Agent connects to this over streamable HTTP as a remote MCP
server. Each registered MCP tool is a thin wrapper that routes through
:func:`spellbook.runner.dispatch.dispatch`, so the enforced scope/tier/authorization
checks run server-side on every call.

**Per-run isolation is the security boundary.** The run's posture, scope
allowlist, and authorizations come from the *environment* (set by the control
plane when it launches this runner), never from the agent's tool arguments — the
agent cannot widen its own scope. Run one runner instance per run.
"""

from __future__ import annotations

import json
import os
from datetime import datetime

from spellbook.control.ingest.model import Posture
from spellbook.control.safety.authorization import Authorization
from spellbook.runner.audit import AuditSink
from spellbook.runner.dispatch import RunContext, dispatch
from spellbook.runner.tools import tools_for


def authorizations_from_env() -> list[Authorization]:
    """Load exploit-tier authorizations from the JSON file at ``SPELLBOOK_AUTHORIZATIONS``."""
    path = os.environ.get("SPELLBOOK_AUTHORIZATIONS")
    if not path or not os.path.exists(path):
        return []
    with open(path) as fh:
        raw = json.load(fh)
    return [
        Authorization(
            id=a["id"], target=a["target"], max_tier=a["max_tier"],
            authorized_by=a["authorized_by"], blast_radius_note=a["blast_radius_note"],
            expires_at=datetime.fromisoformat(a["expires_at"]),
        )
        for a in raw
    ]


def context_from_env(audit: AuditSink | None = None) -> RunContext:
    """Build the per-run enforcement context from the control-plane-set environment."""
    posture = Posture(os.environ.get("SPELLBOOK_POSTURE", "external"))
    scope = {h.strip().lower() for h in os.environ.get("SPELLBOOK_SCOPE", "").split(",") if h.strip()}
    return RunContext(
        posture=posture,
        scope_allowlist=scope,
        authorizations=authorizations_from_env(),
        audit=audit or AuditSink(),
    )


def build_server(ctx: RunContext, name: str = "spellbook-runner"):
    """Construct a FastMCP server exposing the tools valid for ``ctx.posture``."""
    from mcp.server.fastmcp import FastMCP  # lazily imported; only needed to serve

    server = FastMCP(name)

    for tool in tools_for(ctx.posture):
        def make_handler(tool_name: str):
            def handler(target: str, params: dict | None = None) -> dict:
                """Run a bounded validation tool (enforced server-side)."""
                result = dispatch(ctx, tool_name, target, params or {})
                return {
                    "allowed": result.allowed,
                    "reason": result.reason,
                    "observation": result.observation,
                    "error": result.error,
                }
            return handler

        server.add_tool(
            make_handler(tool.name),
            name=tool.name,
            description=f"{tool.description} [tier={tool.tier}]",
        )
    return server


def main() -> None:  # pragma: no cover - process entrypoint
    ctx = context_from_env()
    server = build_server(ctx)
    server.run(transport="streamable-http")


if __name__ == "__main__":  # pragma: no cover
    main()
