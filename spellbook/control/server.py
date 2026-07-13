"""Env-driven control-plane entrypoint — the production/Docker wiring.

:func:`create_app` (``control/app.py``) takes an injected orchestrator + store so
it stays testable against fakes; this module is the *composition root* that builds
those from the environment, exactly as ``runner/server.py`` builds a ``RunContext``
from ``SPELLBOOK_*``. Serve it with ``python -m spellbook.control.server``.

Environment:
- ``SPELLBOOK_DATABASE_URL``      SQLAlchemy URL (default: local sqlite file).
- ``GEMINI_API_KEY``/``GOOGLE_API_KEY``  when set, live Gemini runs are enabled;
                                  otherwise the app runs read/ingest/seed-only and
                                  *starting a new run* raises a clear error.
- ``SPELLBOOK_RUNNER_EXTERNAL_URL`` / ``SPELLBOOK_RUNNER_INTERNAL_URL``  remote-MCP
                                  attack-runner endpoints, per posture.
- ``SPELLBOOK_RUNNER_TOKEN``      bearer token the agent presents to the runner.
- ``SPELLBOOK_SCOPE``             owned-asset allowlist (see ``scope_from_env``).
- ``SPELLBOOK_SEED``              ``1`` to load demo data on startup (idempotent).
"""

from __future__ import annotations

import os

from spellbook.control.agent.google_agent import (
    GenAIInteractionsBackend, GoogleAgentClient, RunnerEndpoint,
)
from spellbook.control.app import create_app
from spellbook.control.ingest.model import Posture
from spellbook.control.orchestrator import Orchestrator
from spellbook.control.seed import seed
from spellbook.control.store.store import Store, init_engine
from spellbook.safety.scope import scope_from_env


class DisabledAgent:
    """Stand-in agent used when no Gemini key is configured.

    Reads and ingestion work fine; only *launching a live run* is unavailable, and
    it fails loudly rather than silently doing nothing.
    """

    _MSG = "live agent runs are disabled: set GEMINI_API_KEY (or GOOGLE_API_KEY) to enable them"

    def launch(self, **_: object) -> str:
        raise RuntimeError(self._MSG)

    def run_to_completion(self, *_: object, **__: object):
        raise RuntimeError(self._MSG)


def _build_agent():
    """Real Gemini-backed client if a key is present, else the disabled stand-in."""
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        return DisabledAgent()
    from google import genai  # lazy: only needed for live runs

    client = genai.Client(api_key=api_key)
    return GoogleAgentClient(GenAIInteractionsBackend(client))


def _runner_minter():
    """Map a posture to its configured remote-MCP attack-runner endpoint."""
    token = os.environ.get("SPELLBOOK_RUNNER_TOKEN", "")
    urls = {
        Posture.EXTERNAL: os.environ.get("SPELLBOOK_RUNNER_EXTERNAL_URL", ""),
        Posture.INTERNAL: os.environ.get("SPELLBOOK_RUNNER_INTERNAL_URL", ""),
    }

    def mint(posture: Posture) -> RunnerEndpoint:
        url = urls.get(posture, "")
        if not url:
            raise RuntimeError(f"no runner URL configured for posture {posture.value!r}")
        return RunnerEndpoint(url, {"Authorization": f"Bearer {token}"})

    return mint


def create_app_from_env():
    """Build the FastAPI app with store/agent/runner/scope resolved from the env."""
    store = Store(init_engine(os.environ.get("SPELLBOOK_DATABASE_URL", "sqlite:///./spellbook.db")))
    if os.environ.get("SPELLBOOK_SEED") == "1":
        seed(store)
    orchestrator = Orchestrator(
        store=store,
        agent=_build_agent(),
        runner_minter=_runner_minter(),
        scope_provider=scope_from_env,
    )
    return create_app(orchestrator, store)


def main() -> None:  # pragma: no cover - process entrypoint
    import uvicorn

    uvicorn.run(
        create_app_from_env(),
        host=os.environ.get("SPELLBOOK_HOST", "0.0.0.0"),
        port=int(os.environ.get("SPELLBOOK_PORT", "8000")),
        log_level=os.environ.get("SPELLBOOK_LOG_LEVEL", "info"),
    )


if __name__ == "__main__":  # pragma: no cover
    main()
