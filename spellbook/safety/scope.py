"""Owned-asset allowlist checks for network-touching commands.

Even a "passive" command (``curl``, ``httpx``, ``gh``) can reach out to an
arbitrary host. Untrusted issue/repo text could try to steer the agent into
probing third-party infrastructure. This module enforces that any host a command
targets is on an explicit owned-asset allowlist — default-deny otherwise.

The allowlist is assembled from the ``SPELLBOOK_SCOPE`` env var (comma-separated
hosts / GitHub orgs) plus hosts derived from the case subject (its repo/host).
A command that targets no network host (e.g. ``gitleaks`` over a local clone)
is always in scope.
"""

from __future__ import annotations

import os
import re
from urllib.parse import urlparse

# Matches http(s) URLs and bare host:port / domain-looking tokens.
_URL_RE = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
_HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)


def scope_from_env() -> set[str]:
    raw = os.environ.get("SPELLBOOK_SCOPE", "")
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def extract_hosts(command: str) -> set[str]:
    """Pull candidate network hosts out of a shell command."""
    hosts: set[str] = set()
    rest = command
    for url in _URL_RE.findall(command):
        netloc = urlparse(url).netloc.split("@")[-1].split(":")[0]
        if netloc:
            hosts.add(netloc.lower())
        rest = rest.replace(url, " ")
    # Bare domains not already captured as part of a URL.
    for m in _HOST_RE.findall(rest):
        hosts.add(m.lower())
    return hosts


def host_allowed(host: str, allowlist: set[str]) -> bool:
    """True if ``host`` is an allowlisted domain or a subdomain of one."""
    # Exact match or a subdomain/suffix match of an allowlisted entry.
    return any(host == a or host.endswith("." + a) for a in allowlist)


# Backwards-compatible private alias (kept for existing callers/tests).
_host_allowed = host_allowed


def in_scope(command: str, allowlist: set[str] | None = None) -> bool:
    """True if every network host the command targets is on the allowlist.

    Commands that touch no network host are always in scope.
    """
    allow = (allowlist or set()) | scope_from_env()
    hosts = extract_hosts(command)
    if not hosts:
        return True
    return all(_host_allowed(h, allow) for h in hosts)
