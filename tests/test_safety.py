"""Tests for the safety classifier, scope check, and PreToolUse gate.

These are the load-bearing safety guarantees and run without the SDK.
"""

import anyio
import pytest

from spellbook.safety.classify import (
    ACTIVE_INVASIVE,
    ACTIVE_NONINVASIVE,
    PASSIVE,
    classify_bash,
    classify_mcp,
)
from spellbook.safety.scope import in_scope
from spellbook.agent.hooks import make_pre_tool_use_gate


# --- classify_bash --------------------------------------------------------
@pytest.mark.parametrize("cmd,expected", [
    ("gitleaks detect --source .", PASSIVE),
    ("git log --oneline", PASSIVE),
    ("gh repo view acme/app", PASSIVE),
    ("curl https://example.com", ACTIVE_NONINVASIVE),
    ("trufflehog git file://.", ACTIVE_NONINVASIVE),
    ("somenewtool --scan", ACTIVE_NONINVASIVE),       # unknown binary → cautious
    ("rm -rf /tmp/x", ACTIVE_INVASIVE),
    ("terraform apply", ACTIVE_INVASIVE),
    ("aws s3 rm s3://b", ACTIVE_INVASIVE),
    ("gitleaks detect --write report", ACTIVE_INVASIVE),  # invasive flag
    ("git commit '", ACTIVE_INVASIVE),                # unparseable → refuse
])
def test_classify_bash(cmd, expected):
    assert classify_bash(cmd) == expected


# --- classify_mcp ---------------------------------------------------------
@pytest.mark.parametrize("tool,expected", [
    ("mcp__wiz__get_issue", PASSIVE),
    ("mcp__wiz__list_issues", PASSIVE),
    ("mcp__github__create_pull_request", ACTIVE_INVASIVE),
    ("mcp__linear__update_ticket", ACTIVE_INVASIVE),
    ("mcp__github__add_comment", ACTIVE_INVASIVE),
])
def test_classify_mcp(tool, expected):
    assert classify_mcp(tool) == expected


# --- scope ----------------------------------------------------------------
def test_scope_local_command_in_scope():
    assert in_scope("gitleaks detect --source /tmp/x") is True


def test_scope_allowlisted_host():
    assert in_scope("curl https://api.acme.com/x", {"acme.com"}) is True


def test_scope_unowned_host_denied():
    assert in_scope("curl https://evil.example.org", {"acme.com"}) is False


# --- the gate -------------------------------------------------------------
def _decision(gate, tool, tool_input):
    out = anyio.run(gate, {"tool_name": tool, "tool_input": tool_input}, "tid", {})
    return out["hookSpecificOutput"]["permissionDecision"]


def test_gate_passive_allowed():
    gate = make_pre_tool_use_gate("interactive")
    assert _decision(gate, "Bash", {"command": "gitleaks detect --source ."}) == "allow"


def test_gate_noninvasive_asks_interactive():
    gate = make_pre_tool_use_gate("interactive", scope_allowlist={"example.com"})
    assert _decision(gate, "Bash", {"command": "curl https://example.com"}) == "ask"


def test_gate_noninvasive_denied_auto():
    gate = make_pre_tool_use_gate("auto", scope_allowlist={"example.com"})
    assert _decision(gate, "Bash", {"command": "curl https://example.com"}) == "deny"


def test_gate_invasive_always_denied():
    for mode in ("interactive", "auto"):
        gate = make_pre_tool_use_gate(mode)
        assert _decision(gate, "Bash", {"command": "rm -rf /"}) == "deny"


def test_gate_out_of_scope_denied():
    gate = make_pre_tool_use_gate("interactive", scope_allowlist={"acme.com"})
    assert _decision(gate, "Bash", {"command": "curl https://evil.org"}) == "deny"


def test_gate_mcp_write_denied():
    gate = make_pre_tool_use_gate("interactive")
    assert _decision(gate, "mcp__github__create_pull_request", {}) == "deny"
