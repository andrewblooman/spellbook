"""The bounded tool contract for the attack-runner.

Every runner tool declares its side-effect **tier** and the **postures** it is
valid in *up front*, as data. The dispatcher (:mod:`spellbook.runner.dispatch`)
reads the declared tier to make its enforcement decision — the tier is never
inferred from a binary name or trusted from the agent. This fixed, self-describing
contract is exactly what the worker exports to the agent as in-process SDK MCP tools
(:mod:`spellbook.worker.tools`).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from spellbook.control.ingest.model import Posture

# handler(target, params) -> observation dict
Handler = Callable[[str, dict], dict]


@dataclass(frozen=True)
class Tool:
    name: str
    tier: str                       # one of spellbook.safety.classify constants
    postures: frozenset[Posture]
    handler: Handler
    description: str = ""
    params_schema: dict = field(default_factory=dict)  # JSON-schema for MCP export


_REGISTRY: dict[str, Tool] = {}


def register(tool: Tool) -> Tool:
    """Register (or replace) a tool by name."""
    _REGISTRY[tool.name] = tool
    return tool


def unregister(name: str) -> None:
    _REGISTRY.pop(name, None)


def get(name: str) -> Tool | None:
    return _REGISTRY.get(name)


def names() -> list[str]:
    return sorted(_REGISTRY)


def tools_for(posture: Posture) -> list[Tool]:
    """Tools valid in ``posture``, sorted by name."""
    return [t for t in (_REGISTRY[n] for n in names()) if posture in t.postures]
