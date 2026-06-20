"""Manual, deterministic evidence collection — no agent in the loop.

Lets an analyst run a passive open-source check (currently gitleaks) directly
against a local repo and record the raw output as case evidence. This is the
"deterministic tools" half of the workflow: reproducible, no model reasoning,
secrets redacted at the source.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

# name → (binary, argv builder). Add deterministic checks here.
CHECKS = ["gitleaks"]


class CheckError(Exception):
    """Raised when a check cannot run (missing binary, bad source, timeout)."""


def run_gitleaks(source: Path, timeout: float = 120.0) -> tuple[str, str]:
    """Run `gitleaks detect --redact` on a local path. Returns (command, output).

    gitleaks exits non-zero when it finds leaks; that is a normal result, not an
    error, so we capture output regardless of return code. Secrets are redacted by
    gitleaks itself (`--redact`) before they ever reach us.
    """
    if shutil.which("gitleaks") is None:
        raise CheckError("gitleaks is not installed (see https://github.com/gitleaks/gitleaks).")
    source = source.expanduser()
    if not source.exists():
        raise CheckError(f"{source} does not exist.")

    argv = ["gitleaks", "detect", "--source", str(source), "--no-banner", "--redact"]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise CheckError(f"gitleaks timed out after {timeout}s.") from exc
    output = (proc.stdout or "") + (proc.stderr or "")
    return " ".join(argv), output
