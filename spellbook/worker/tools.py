"""Expose the runner's bounded tools to the Claude Agent SDK as an in-process MCP server.

Each registered runner :class:`~spellbook.runner.tools.registry.Tool` becomes an
in-process SDK MCP tool whose body routes through
:func:`~spellbook.runner.dispatch.dispatch`. So the enforced chain —
posture → :func:`~spellbook.control.safety.decide.decide` → audit → handler —
runs server-side on **every** call, exactly as the remote-MCP runner did, now
co-located in the worker process. A denied call never touches the network.

The tool surface is identical to what the runner exported over remote MCP: a
single ``target`` plus a free-form ``params`` object. The tool name the model
sees is ``mcp__runner__<tool.name>``.
"""

from __future__ import annotations

import json

from claude_agent_sdk import McpSdkServerConfig, SdkMcpTool, create_sdk_mcp_server, tool

from spellbook.runner import tools as _tools  # noqa: F401  (import populates the registry)
from spellbook.runner.dispatch import RunContext, dispatch
from spellbook.runner.tools import registry

SERVER_NAME = "runner"


def _text_result(payload: dict) -> dict:
    """Wrap a dispatch result as the SDK MCP tool-result content shape."""
    return {"content": [{"type": "text", "text": json.dumps(payload)}]}


def _input_schema(t: registry.Tool) -> dict:
    """JSON Schema for a runner tool call: an owned-asset target + free-form params."""
    return {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "The owned-asset target (host / IP / CIDR / asset id) to act on.",
            },
            "params": {
                "type": "object",
                "description": "Tool-specific parameters.",
                "default": {},
            },
        },
        "required": ["target"],
    }


def _make_sdk_tool(ctx: RunContext, t: registry.Tool) -> SdkMcpTool:
    """Bind one registry tool to an SDK tool that enforces via ``dispatch``."""

    @tool(t.name, f"{t.description} [tier={t.tier}]", _input_schema(t))
    async def _handler(args: dict) -> dict:
        target = args.get("target", "")
        params = args.get("params") or {}
        result = dispatch(ctx, t.name, target, params)
        return _text_result({
            "allowed": result.allowed,
            "reason": result.reason,
            "observation": result.observation,
            "error": result.error,
        })

    return _handler


def build_sdk_tools(ctx: RunContext) -> list[SdkMcpTool]:
    """The SDK tools valid for ``ctx.posture``, each enforcing via ``dispatch``."""
    return [_make_sdk_tool(ctx, t) for t in registry.tools_for(ctx.posture)]


def build_runner_server(ctx: RunContext) -> McpSdkServerConfig:
    """An in-process MCP server exposing the tools valid for ``ctx.posture``."""
    return create_sdk_mcp_server(name=SERVER_NAME, tools=build_sdk_tools(ctx))


def allowed_tool_names(ctx: RunContext) -> list[str]:
    """The ``mcp__runner__<name>`` ids to pass as ``allowed_tools`` for this posture."""
    return [f"mcp__{SERVER_NAME}__{t.name}" for t in registry.tools_for(ctx.posture)]
