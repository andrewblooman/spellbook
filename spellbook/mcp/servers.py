"""MCP server configuration.

Wiz is the issue data source; GitHub / Linear / Notion are *business-context*
sources the analyst can read to understand ownership and intent behind an issue
(who owns the repo, is there a ticket, is this a known/accepted risk?).

Every server is gated on its own credentials in the environment — never the case
file — so the offline ``--subject-file`` path keeps working with none of them set.
The read/write split is enforced by ``safety/classify.py`` (any MCP tool whose name
contains create/update/delete/comment/… is denied), so adding these read-mostly
servers does not widen what the agent can *change*.

Tool/package names are best-effort and overridable via env, mirroring the Wiz
issue-tool override (the exact names are not guaranteed stable upstream).
"""

from __future__ import annotations

import os

# Default guesses; override with WIZ_MCP_*_TOOL once confirmed against the server.
DEFAULT_WIZ_ISSUE_TOOL = "get_issue"
DEFAULT_WIZ_LIST_TOOL = "list_issues"


def wiz_issue_tool() -> str:
    return os.environ.get("WIZ_MCP_ISSUE_TOOL", DEFAULT_WIZ_ISSUE_TOOL)


def wiz_list_tool() -> str:
    return os.environ.get("WIZ_MCP_LIST_TOOL", DEFAULT_WIZ_LIST_TOOL)


def wiz_configured() -> bool:
    return bool(os.environ.get("WIZ_CLIENT_ID") and os.environ.get("WIZ_CLIENT_SECRET"))


def _wiz_server() -> dict | None:
    if not wiz_configured():
        return None
    return {
        "command": "npx",
        "args": ["-y", "mcp-server-wiz"],
        "env": {
            "WIZ_CLIENT_ID": os.environ["WIZ_CLIENT_ID"],
            "WIZ_CLIENT_SECRET": os.environ["WIZ_CLIENT_SECRET"],
        },
    }


def _github_server() -> dict | None:
    token = os.environ.get("GITHUB_PERSONAL_ACCESS_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        return None
    return {
        "command": "npx",
        "args": ["-y", os.environ.get("GITHUB_MCP_PACKAGE", "@modelcontextprotocol/server-github")],
        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": token},
    }


def _notion_server() -> dict | None:
    token = os.environ.get("NOTION_API_KEY") or os.environ.get("NOTION_TOKEN")
    if not token:
        return None
    return {
        "command": "npx",
        "args": ["-y", os.environ.get("NOTION_MCP_PACKAGE", "@notionhq/notion-mcp-server")],
        "env": {"NOTION_API_KEY": token},
    }


def _linear_server() -> dict | None:
    token = os.environ.get("LINEAR_API_KEY")
    if not token:
        return None
    return {
        "command": "npx",
        "args": ["-y", os.environ.get("LINEAR_MCP_PACKAGE", "linear-mcp-server")],
        "env": {"LINEAR_API_KEY": token},
    }


# name → factory. Wiz is the data source; the rest are business context.
_SERVERS = {
    "wiz": _wiz_server,
    "github": _github_server,
    "notion": _notion_server,
    "linear": _linear_server,
}


def mcp_servers(case=None) -> dict:
    """Return the configured MCP servers (only those with creds present)."""
    servers = {}
    for name, factory in _SERVERS.items():
        config = factory()
        if config is not None:
            servers[name] = config
    return servers


def context_sources() -> list[str]:
    """Names of configured business-context sources (github/notion/linear)."""
    return [name for name in ("github", "notion", "linear") if _SERVERS[name]() is not None]
