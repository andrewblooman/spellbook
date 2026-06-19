"""PreToolUse safety gate and PostToolUse audit/redact hooks.

The hooks are built by *factory functions* bound (via closure) to the run's
mode and the case store. The SDK's ``HookContext`` does not carry our
application mode, so we cannot read it from ``context`` — we capture it here.

Decision table the gate enforces:
    passive            → allow (after scope check)
    active_noninvasive → ask  (interactive) | deny (auto/unattended)
    active_invasive    → deny (always)
    out-of-scope host  → deny (always)
"""

from __future__ import annotations

import re

from spellbook.case.store import CaseStore
from spellbook.safety.classify import (
    ACTIVE_INVASIVE,
    ACTIVE_NONINVASIVE,
    PASSIVE,
    classify_bash,
    classify_mcp,
)
from spellbook.safety.scope import in_scope

# Coarse secret patterns redacted from MCP tool output before it re-enters context.
# (Shell checks keep secrets out at the source, e.g. `gitleaks --redact`.)
_SECRET_RE = re.compile(
    r"(?i)(?:aws_secret|api[_-]?key|secret|token|password|authorization)\s*[=:]\s*\S+"
    r"|AKIA[0-9A-Z]{16}"
    r"|gh[pousr]_[0-9A-Za-z]{30,}"
    r"|-----BEGIN[ A-Z]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z]*PRIVATE KEY-----"
)


def _pre_decision(decision: str, reason: str) -> dict:
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,  # "allow" | "ask" | "deny"
        "permissionDecisionReason": reason,
    }}


def make_pre_tool_use_gate(mode: str, scope_allowlist: set[str] | None = None,
                           store: CaseStore | None = None):
    """Build the PreToolUse gate bound to this run's mode + scope + store."""
    interactive = mode == "interactive"
    allowlist = scope_allowlist or set()

    async def pre_tool_use_gate(input_data, tool_use_id, context):
        tool = input_data.get("tool_name", "")
        args = input_data.get("tool_input", {}) or {}

        if tool == "Bash":
            command = args.get("command", "")
            if not in_scope(command, allowlist):
                return _log_and_return(
                    "deny", f"Bash: target not on owned-asset allowlist", tool, command)
            cls = classify_bash(command)
            subject = command
        elif tool.startswith("mcp__"):
            cls = classify_mcp(tool)
            subject = tool
        else:
            cls = PASSIVE
            subject = tool

        if cls == ACTIVE_INVASIVE:
            return _log_and_return(
                "deny", f"{tool}: state-changing/destructive, blocked by policy", tool, subject)
        if cls == ACTIVE_NONINVASIVE:
            if interactive:
                return _log_and_return(
                    "ask", f"{tool}: non-destructive but active — confirm before running",
                    tool, subject)
            return _log_and_return(
                "deny", f"{tool}: needs human approval, none available in unattended mode",
                tool, subject)
        return _pre_decision("allow", "passive read-only")

    def _log_and_return(decision, reason, tool, subject):
        if store is not None:
            store.append_audit(f"GATE {decision.upper()}\t{tool}\t{reason}\t{subject!r}")
        return _pre_decision(decision, reason)

    return pre_tool_use_gate


def make_post_tool_use_audit(store: CaseStore):
    """Build the PostToolUse hook: record evidence + audit, redact MCP secrets."""

    async def post_tool_use_audit(input_data, tool_use_id, context):
        tool = input_data.get("tool_name", "")
        args = input_data.get("tool_input", {}) or {}
        response = input_data.get("tool_response", "")
        command = args.get("command", "") if tool == "Bash" else tool

        if tool == "Bash":
            side_effect = classify_bash(command)
        elif tool.startswith("mcp__"):
            side_effect = classify_mcp(tool)
        else:
            side_effect = PASSIVE

        raw = response if isinstance(response, str) else str(response)
        store.append_evidence(tool=tool, command=command,
                              side_effect=side_effect, raw=raw)
        store.append_audit(f"RAN\t{tool}\t{side_effect}\t{command!r}")

        # MCP tool output can be replaced before it re-enters the model context.
        if tool.startswith("mcp__") and _SECRET_RE.search(raw):
            redacted = _SECRET_RE.sub("[REDACTED]", raw)
            return {"hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "updatedToolOutput": redacted,
            }}
        return {}

    return post_tool_use_audit
