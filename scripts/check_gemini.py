#!/usr/bin/env python3.14
"""Opt-in Gemini connectivity check — ONE minimal free-tier call.

Confirms your API key + `google-genai` SDK + network reach Google, *without*
touching the Interactions API / Managed Agents (those need the paid tier). Run it
yourself when you're ready to spend a few free-tier tokens:

    python3.14 scripts/check_gemini.py

It reads GEMINI_API_KEY (or GOOGLE_API_KEY) from the environment or a local .env
file, makes one tiny `generate_content` call on the cheapest model, and prints
only status + token usage. It never prints the key.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Cheapest, free-tier-eligible model — enough to prove connectivity.
MODEL = "gemini-2.5-flash-lite"


def load_dotenv(path: Path) -> None:
    """Minimal .env loader: KEY=VALUE lines, no override of existing env."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def main() -> int:
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    if not (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")):
        print("✗ No GEMINI_API_KEY / GOOGLE_API_KEY found (env or .env).")
        return 2

    try:
        from google import genai
    except ImportError:
        print("✗ google-genai not installed. Run: pip install 'google-genai>=2.3'")
        return 2

    print(f"→ one free-tier call to {MODEL} (say 'ok' in ≤5 tokens)…")
    try:
        client = genai.Client()
        resp = client.models.generate_content(
            model=MODEL,
            contents="Reply with the single word: ok",
            config={"max_output_tokens": 5},
        )
    except Exception as exc:  # noqa: BLE001 — surface any auth/network/SDK failure
        print(f"✗ call failed: {type(exc).__name__}: {exc}")
        return 1

    usage = getattr(resp, "usage_metadata", None)
    print(f"✓ key + SDK + network OK. reply={ (resp.text or '').strip()!r}")
    if usage is not None:
        print(f"  tokens: prompt={getattr(usage,'prompt_token_count',None)} "
              f"total={getattr(usage,'total_token_count',None)}")
    print("\nNote: this did NOT test the Interactions API / Managed Agents "
          "(our real path) — that needs the paid tier.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
