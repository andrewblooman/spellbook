"""MCP server configuration.

Milestone 0 wires only the Wiz MCP server (the issue data source). GitHub /
Linear / Notion are deferred. Credentials come from the environment, never the
case file. The exact Wiz issue-tool name is unconfirmed upstream — callers can
override it via ``WIZ_MCP_ISSUE_TOOL``.
"""

from __future__ import annotations

import os

# Default guess; override with WIZ_MCP_ISSUE_TOOL once confirmed against the server.
DEFAULT_WIZ_ISSUE_TOOL = "get_issue"


def wiz_issue_tool() -> str:
    return os.environ.get("WIZ_MCP_ISSUE_TOOL", DEFAULT_WIZ_ISSUE_TOOL)


def wiz_configured() -> bool:
    return bool(os.environ.get("WIZ_CLIENT_ID") and os.environ.get("WIZ_CLIENT_SECRET"))


def mcp_servers(case=None) -> dict:
    """Return the mcp_servers config. Empty if Wiz creds are not present."""
    if not wiz_configured():
        return {}
    return {
        "wiz": {
            "command": "npx",
            "args": ["-y", "mcp-server-wiz"],
            "env": {
                "WIZ_CLIENT_ID": os.environ["WIZ_CLIENT_ID"],
                "WIZ_CLIENT_SECRET": os.environ["WIZ_CLIENT_SECRET"],
            },
        },
    }
