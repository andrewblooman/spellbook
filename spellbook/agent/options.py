"""Build ClaudeAgentOptions for a case + mode.

Ties together: filesystem skills (via ``setting_sources`` + ``cwd``), the passive
tool allowlist, the safety hooks, and the MCP data sources. ``permission_mode`` is
always ``default`` — never ``bypassPermissions``, since the gate must run.
"""

from __future__ import annotations

from pathlib import Path

from claude_agent_sdk import ClaudeAgentOptions, HookMatcher

from spellbook.agent.hooks import make_post_tool_use_audit, make_pre_tool_use_gate
from spellbook.agent.prompts import build_system_prompt
from spellbook.case.store import CaseStore
from spellbook.mcp.servers import mcp_servers
from spellbook.safety.scope import extract_hosts

# Repo root holds .claude/skills: this file is spellbook/agent/options.py → parents[2].
REPO_ROOT = Path(__file__).resolve().parents[2]

# Tools the agent may ever use. Anything not listed is denied by default; Bash
# still passes the PreToolUse gate. Destructive built-ins are simply never granted.
PASSIVE_TOOLS = ["Skill", "Read", "Grep", "Glob", "Bash"]


def _subject_scope(case) -> set[str]:
    """Owned-asset hosts derived from the case subject (repo URLs, endpoints)."""
    hosts: set[str] = set()
    for value in (case.subject or {}).values():
        if isinstance(value, str):
            hosts |= extract_hosts(value)
    return hosts


def build_options(store: CaseStore, mode: str) -> ClaudeAgentOptions:
    case = store.case
    interactive = mode == "interactive"
    scope = _subject_scope(case)

    pre_gate = make_pre_tool_use_gate(mode, scope_allowlist=scope, store=store)
    post_audit = make_post_tool_use_audit(store)

    return ClaudeAgentOptions(
        cwd=str(REPO_ROOT),
        setting_sources=["user", "project"],
        allowed_tools=PASSIVE_TOOLS,
        disallowed_tools=[],
        permission_mode="default",
        system_prompt=build_system_prompt(case, mode),
        model="claude-sonnet-4-6",
        max_turns=None if interactive else 40,
        include_partial_messages=interactive,
        mcp_servers=mcp_servers(case),
        hooks={
            "PreToolUse": [
                HookMatcher(matcher="Bash", hooks=[pre_gate]),
                HookMatcher(matcher="mcp__.*", hooks=[pre_gate]),
            ],
            "PostToolUse": [HookMatcher(matcher=".*", hooks=[post_audit])],
        },
    )
