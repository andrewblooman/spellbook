"""Env-driven control-plane entrypoint — the production/Docker wiring.

:func:`create_app` (``control/app.py``) takes an injected orchestrator + store so
it stays testable against fakes; this module is the *composition root* that builds
those from the environment. Serve it with ``python -m spellbook.control.server``.

The agent loop runs in a separate Cloud Run **agent-worker** inside the VPC (see
``spellbook/worker/``); it claims dispatched runs and posts results via the
``/internal`` API, bearer-authed with ``SPELLBOOK_WORKER_TOKEN``.

Environment:
- ``SPELLBOOK_DATABASE_URL``   SQLAlchemy URL (default: local sqlite file).
- ``SPELLBOOK_WORKER_TOKEN``   shared bearer the agent-workers present on ``/internal``.
- ``SPELLBOOK_SCOPE``          owned-asset allowlist (see ``scope_from_env``).
- ``SPELLBOOK_SEED``           ``1`` to load demo data on startup (idempotent).
"""

from __future__ import annotations

import os

from spellbook.control.app import create_app
from spellbook.control.orchestrator import Orchestrator
from spellbook.control.seed import seed
from spellbook.control.store.store import Store, init_engine
from spellbook.safety.scope import scope_from_env


def create_app_from_env():
    """Build the FastAPI app with store/scope/worker-token resolved from the env."""
    store = Store(init_engine(os.environ.get("SPELLBOOK_DATABASE_URL", "sqlite:///./spellbook.db")))
    if os.environ.get("SPELLBOOK_SEED") == "1":
        seed(store)
    orchestrator = Orchestrator(store=store, scope_provider=scope_from_env)
    return create_app(orchestrator, store,
                      worker_token=os.environ.get("SPELLBOOK_WORKER_TOKEN") or None)


def main() -> None:  # pragma: no cover - process entrypoint
    import uvicorn

    # Cloud Run injects ``PORT``; fall back to SPELLBOOK_PORT, then 8000.
    port = int(os.environ.get("PORT") or os.environ.get("SPELLBOOK_PORT", "8000"))
    uvicorn.run(
        create_app_from_env(),
        host=os.environ.get("SPELLBOOK_HOST", "0.0.0.0"),
        port=port,
        log_level=os.environ.get("SPELLBOOK_LOG_LEVEL", "info"),
    )


if __name__ == "__main__":  # pragma: no cover
    main()
