"""The Spellbook launch banner."""

from __future__ import annotations

_BANNER = r"""
   _____ _____  ______ _      _      ____   ____   ____  _  __
  / ____|  __ \|  ____| |    | |    |  _ \ / __ \ / __ \| |/ /
 | (___ | |__) | |__  | |    | |    | |_) | |  | | |  | | ' /
  \___ \|  ___/|  __| | |    | |    |  _ <| |  | | |  | |  <
  ____) | |    | |____| |____| |____| |_) | |__| | |__| | . \
 |_____/|_|    |______|______|______|____/ \____/ \____/|_|\_\
"""

_TAGLINE = "  evidence-backed, safety-gated triage for Wiz cloud-security issues"


def banner() -> str:
    """Return the multi-line launch banner (no trailing newline)."""
    return f"{_BANNER}\n{_TAGLINE}"
