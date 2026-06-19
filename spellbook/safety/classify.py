"""Deterministic side-effect classification for tool calls.

This is the load-bearing safety IP: the model's instructions are advisory, but
this classifier (driven by the ``PreToolUse`` gate in :mod:`spellbook.agent.hooks`)
is what actually decides whether a tool call is allowed. Three levels:

- ``passive``            — read-only, no outbound state change (allowed)
- ``active_noninvasive`` — non-destructive but reaches out / validates live state
                           (ask in interactive, deny in unattended)
- ``active_invasive``    — state-changing or destructive (always denied)
"""

from __future__ import annotations

import shlex

PASSIVE = "passive"
ACTIVE_NONINVASIVE = "active_noninvasive"
ACTIVE_INVASIVE = "active_invasive"

# Binaries that only read. Extend as new passive check skills are added.
PASSIVE_BINARIES = {
    "git", "gh", "trivy", "grype", "osv-scanner", "syft",
    "semgrep", "gitleaks", "checkov", "httpx", "tlsx", "jq",
}
# Non-destructive but reaches out / validates live state — gate behind approval.
NONINVASIVE_BINARIES = {"trufflehog", "nuclei", "subfinder", "gcloud", "curl"}
# Never. Hard deny regardless of context.
INVASIVE_MARKERS = {
    "rm", "dd", "mkfs", "terraform", "kubectl", "psql",
    "aws", "shutdown", "iptables",
}
INVASIVE_FLAGS = {"--delete", "--force", "apply", "destroy", "drop", "--write"}


def classify_bash(command: str) -> str:
    """Classify a shell command by its worst-case side effect."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return ACTIVE_INVASIVE  # unparseable → refuse

    binaries = {t for t in tokens if "/" not in t and not t.startswith("-")}
    if binaries & INVASIVE_MARKERS or set(tokens) & INVASIVE_FLAGS:
        return ACTIVE_INVASIVE
    if binaries & NONINVASIVE_BINARIES:
        return ACTIVE_NONINVASIVE
    if binaries & PASSIVE_BINARIES:
        return PASSIVE
    return ACTIVE_NONINVASIVE  # unknown binary → cautious default


def classify_mcp(tool_name: str) -> str:
    """Classify an MCP tool call by name.

    Read tools are passive; anything that looks write-capable is invasive.
    Drafting a PR/ticket is intentionally a separate, explicit command — never
    something the agent does mid-investigation.
    """
    lowered = tool_name.lower()
    write_markers = ("create", "update", "delete", "write", "merge", "comment", "set_", "post")
    if any(w in lowered for w in write_markers):
        return ACTIVE_INVASIVE
    return PASSIVE
