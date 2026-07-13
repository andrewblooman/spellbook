"""The vetted PoC catalog — the *only* exploits ``run_poc`` will execute.

This is the load-bearing safety idea of M2: even once :func:`~spellbook.control.safety.decide.decide`
has unlocked the ``active_invasive`` tier with a valid :class:`Authorization`, the
agent may only ask for a PoC **by name** from this fixed catalog. It can never
hand over arbitrary code or a command to run — the blast radius is bounded to
what a human vetted here, not to what the model dreamt up. (This is the M2 analog
of "``decide()`` is the boundary, not the prompt".)

Each catalog PoC is **proof-of-exploitability, not a destructive payload**: it
demonstrates access (an auth wall that isn't there, an unauthenticated data-store
command that answers) using the bounded primitives of
:class:`~spellbook.runner.tools.poc_executor.PocExecutor`. Add a PoC by registering
a :class:`Poc`; keep it non-destructive and bounded.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from spellbook.runner.tools.poc_executor import PocExecutor

# run(target, params, executor) -> result dict (must include executed + success)
PocRun = Callable[[str, dict, PocExecutor], dict]


@dataclass(frozen=True)
class Poc:
    name: str
    run: PocRun
    description: str = ""
    params_schema: dict = field(default_factory=dict)


_CATALOG: dict[str, Poc] = {}


def register(poc: Poc) -> Poc:
    _CATALOG[poc.name] = poc
    return poc


def unregister(name: str) -> None:
    _CATALOG.pop(name, None)


def get(name: str) -> Poc | None:
    return _CATALOG.get(name)


def names() -> list[str]:
    return sorted(_CATALOG)


# --- built-in bounded PoCs -------------------------------------------------
def _http_auth_bypass(target: str, params: dict, ex: PocExecutor) -> dict:
    """Prove a protected path serves content with **no** credentials."""
    path = params.get("path", "/admin")
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    url = url.rstrip("/") + "/" + path.lstrip("/")
    res = ex.http("GET", url)
    if res.error:
        return {"poc": "http_auth_bypass", "executed": True, "success": False,
                "proof": None, "detail": {"url": url, "error": res.error}}
    # Success == the protected path returns a 2xx body without ever being challenged.
    success = 200 <= res.status < 300 and "www-authenticate" not in {k.lower() for k in res.headers}
    return {
        "poc": "http_auth_bypass", "executed": True, "success": success,
        "proof": f"GET {url} -> {res.status} with no auth challenge" if success else None,
        "detail": {"url": url, "status": res.status},
    }


def _datastore_unauth(target: str, params: dict, ex: PocExecutor) -> dict:
    """Prove a data store (Redis-style) answers an **unauthenticated** command."""
    port = int(params.get("port", 6379))
    probe = params.get("command", "PING").upper().encode() + b"\r\n"
    try:
        reply = ex.tcp_send(target, port, probe, read_bytes=128)
    except OSError as exc:
        return {"poc": "datastore_unauth", "executed": True, "success": False,
                "proof": None, "detail": {"port": port, "error": str(exc)}}
    text = reply.decode(errors="replace").strip()
    # A "-NOAUTH"/"-AUTH" error means auth *is* enforced; anything else answered us.
    success = bool(text) and not text.upper().startswith(("-NOAUTH", "-ERR AUTH"))
    return {
        "poc": "datastore_unauth", "executed": True, "success": success,
        "proof": f"{target}:{port} answered {text!r} without auth" if success else None,
        "detail": {"port": port, "reply": text[:80]},
    }


register(Poc(
    name="http_auth_bypass", run=_http_auth_bypass,
    description="Prove a protected HTTP path serves 2xx with no auth challenge.",
    params_schema={"type": "object", "properties": {"path": {"type": "string", "default": "/admin"}}},
))

register(Poc(
    name="datastore_unauth", run=_datastore_unauth,
    description="Prove a Redis-style data store answers a command with no authentication.",
    params_schema={
        "type": "object",
        "properties": {
            "port": {"type": "integer", "default": 6379},
            "command": {"type": "string", "default": "PING"},
        },
    },
))
