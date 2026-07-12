"""Non-destructive HTTP probing.

An unauthenticated GET that inspects status/headers is ``active_noninvasive``:
it reaches a live host and can reveal an open admin panel, a missing auth wall, or
a fingerprintable vulnerable service — without changing any state.
"""

from __future__ import annotations

import httpx

from spellbook.safety.classify import ACTIVE_NONINVASIVE
from spellbook.control.ingest.model import Posture
from spellbook.runner.tools.registry import Tool, register


def http_probe(target: str, params: dict) -> dict:
    """GET ``target`` (or a URL derived from it); report status + telltale headers."""
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    path = params.get("path", "")
    if path:
        url = url.rstrip("/") + "/" + path.lstrip("/")
    timeout = float(params.get("timeout", 5.0))
    try:
        resp = httpx.get(url, timeout=timeout, follow_redirects=False)
    except httpx.HTTPError as exc:
        return {"url": url, "reachable": False, "error": str(exc)}
    return {
        "url": url,
        "reachable": True,
        "status": resp.status_code,
        "server": resp.headers.get("server"),
        "www_authenticate": resp.headers.get("www-authenticate"),
        "location": resp.headers.get("location"),
    }


register(Tool(
    name="http_probe",
    tier=ACTIVE_NONINVASIVE,
    postures=frozenset({Posture.EXTERNAL, Posture.INTERNAL}),
    handler=http_probe,
    description="Unauthenticated HTTP GET: status + auth/server headers (no state change).",
    params_schema={
        "type": "object",
        "properties": {
            "path": {"type": "string", "default": ""},
            "timeout": {"type": "number", "default": 5.0},
        },
    },
))
