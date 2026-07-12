"""Passive network-reachability tool.

A TCP connect probe is the most basic exploitability signal: an "exploitable"
finding on a service you cannot even reach is not exploitable from this vantage.
Because it only opens (and immediately closes) a socket, it is ``passive``.
"""

from __future__ import annotations

import socket

from spellbook.safety.classify import PASSIVE
from spellbook.control.ingest.model import Posture
from spellbook.runner.tools.registry import Tool, register


def reachability(target: str, params: dict) -> dict:
    """TCP-connect to ``target`` on ``port``; report open/closed (never raises)."""
    port = int(params.get("port", 443))
    timeout = float(params.get("timeout", 3.0))
    try:
        conn = socket.create_connection((target, port), timeout=timeout)
        conn.close()
        return {"host": target, "port": port, "open": True}
    except OSError as exc:
        return {"host": target, "port": port, "open": False, "error": str(exc)}


register(Tool(
    name="reachability",
    tier=PASSIVE,
    postures=frozenset({Posture.EXTERNAL, Posture.INTERNAL}),
    handler=reachability,
    description="TCP-connect probe: is host:port reachable from this vantage?",
    params_schema={
        "type": "object",
        "properties": {
            "port": {"type": "integer", "default": 443},
            "timeout": {"type": "number", "default": 3.0},
        },
    },
))
