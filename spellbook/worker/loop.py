"""The Claude Agent SDK validation loop.

Drives one validation run: build :class:`ClaudeAgentOptions` (system prompt +
in-process runner tools + a defense-in-depth PreToolUse allowlist gate), send the
finding as the opening user turn, stream the agent to completion, and parse the
final JSON into a :class:`~spellbook.control.agent.schema.Verdict`.

The message-producing call is an injectable ``QueryFn`` (default
:func:`claude_agent_sdk.query`) so the launch/collect/parse orchestration is
unit-tested with a fake — no live model, no ``claude`` CLI. This mirrors the
``InteractionsBackend`` seam the Gemini client used.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol

from claude_agent_sdk import ClaudeAgentOptions, HookMatcher, query

from spellbook.control.agent import prompts
from spellbook.control.agent.schema import Verdict
from spellbook.control.ingest.model import AttackPath, Finding, Posture
from spellbook.runner.dispatch import RunContext
from spellbook.worker.tools import allowed_tool_names, build_runner_server

DEFAULT_MODEL = "claude-opus-4-8"

# Built-in Claude Code tools the exploit-validation agent must never touch. Its
# only capabilities are the bounded runner tools; the filesystem/exec/web tools
# are irrelevant and are denied explicitly rather than left to permission prompts.
_DISALLOWED_BUILTINS = [
    "Bash", "Write", "Edit", "MultiEdit", "NotebookEdit",
    "WebSearch", "WebFetch", "Task", "KillShell",
]


@dataclass
class AgentRun:
    """The parsed outcome of one validation loop."""

    verdict: Verdict | None = None
    raw_output: str | None = None
    error: str | None = None


class QueryFn(Protocol):
    """The slice of :func:`claude_agent_sdk.query` this loop depends on."""

    def __call__(self, *, prompt: str, options: ClaudeAgentOptions) -> AsyncIterator[Any]: ...


def _pre_tool_use_gate(allowed: set[str]) -> Callable[..., Awaitable[dict]]:
    """Defense-in-depth: deny any tool that is not an allowlisted runner tool.

    The real tier/scope/authorization enforcement runs inside each runner tool via
    ``dispatch`` → ``decide``; this hook just guarantees the agent cannot reach a
    built-in tool even if the allow/disallow lists are ever misconfigured.
    """

    async def gate(input_data: dict, tool_use_id: str | None, context: Any) -> dict:
        tool = input_data.get("tool_name", "")
        decision = "allow" if tool in allowed else "deny"
        reason = "allowlisted runner tool" if decision == "allow" else f"{tool!r} not permitted"
        return {"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }}

    return gate


def build_options(ctx: RunContext, *, model: str = DEFAULT_MODEL,
                  max_turns: int = 40) -> ClaudeAgentOptions:
    """Options that lock the agent to the runner tools and its posture prompt."""
    allowed = allowed_tool_names(ctx)
    return ClaudeAgentOptions(
        model=model,
        system_prompt=prompts.system_prompt(ctx.posture),
        mcp_servers={"runner": build_runner_server(ctx)},
        allowed_tools=allowed,
        disallowed_tools=_DISALLOWED_BUILTINS,
        permission_mode="default",  # never bypassPermissions — the gate must run
        setting_sources=[],  # hermetic: don't load user/project settings or skills
        max_turns=max_turns,
        hooks={"PreToolUse": [HookMatcher(matcher=".*", hooks=[_pre_tool_use_gate(set(allowed))])]},
    )


def extract_final_text(messages: list[Any]) -> str | None:
    """The agent's final output text: prefer a ``ResultMessage.result``, else the
    last assistant turn's text blocks. Duck-typed so tests need no heavy SDK objects.
    """
    result = next((getattr(m, "result", None) for m in reversed(messages)
                   if getattr(m, "result", None)), None)
    if result:
        return result
    for message in reversed(messages):
        content = getattr(message, "content", None)
        if isinstance(content, list):
            texts = [b.text for b in content if getattr(b, "text", None)]
            if texts:
                return "".join(texts)
    return None


def _parse_verdict(text: str | None) -> Verdict | None:
    if not text:
        return None
    try:
        return Verdict.model_validate_json(text)
    except ValueError:
        return None


class AgentValidator:
    """Runs the SDK loop for a finding × posture and returns a parsed verdict."""

    def __init__(self, *, query_fn: QueryFn = query, model: str = DEFAULT_MODEL,
                 max_turns: int = 40) -> None:
        self._query = query_fn
        self.model = model
        self.max_turns = max_turns

    async def run(self, *, finding: Finding, posture: Posture, ctx: RunContext,
                  attack_path: AttackPath | None = None) -> AgentRun:
        options = build_options(ctx, model=self.model, max_turns=self.max_turns)
        prompt = prompts.finding_input(finding, attack_path)
        try:
            messages = [m async for m in self._query(prompt=prompt, options=options)]
        except Exception as exc:  # CLI/transport failure — surface, don't crash the worker
            return AgentRun(error=f"agent_error: {exc}")

        text = extract_final_text(messages)
        verdict = _parse_verdict(text)
        error = None if verdict is not None else "verdict_parse_failed"
        return AgentRun(verdict=verdict, raw_output=text, error=error)
