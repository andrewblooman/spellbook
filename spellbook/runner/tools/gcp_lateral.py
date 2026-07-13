"""Internal ("shields down", assumed-breach) lateral-movement tools — M1.

These run only in the ``INTERNAL`` posture: the runner sits *inside* the VPC, so
its vantage is that of an attacker who already has a foothold. They answer the
question external probing can't — "given a breach here, how far does it reach?":

- ``metadata_token``   — read the instance's borrowed service-account identity
  from the GCE metadata server (the classic first move after a foothold);
- ``iam_blast_radius`` — measure that SA's blast radius via read-only
  ``testIamPermissions`` (which high-impact permissions does it actually hold?);
- ``east_west_reach``  — TCP-sweep an internal host for reachable service ports
  (east-west movement the internet vantage can never see).

The ``target`` handed to every tool is the **owned internal asset** (host/IP), so
:func:`~spellbook.control.safety.decide.decide` enforces scope on it exactly as
for the external tools — the metadata/IAM surface is reached *on behalf of* that
in-scope asset, never as a scope target of its own. Live GCP access goes through
the injectable :mod:`~spellbook.runner.tools.gcp_backend`.
"""

from __future__ import annotations

import hashlib
import socket

from spellbook.safety.classify import ACTIVE_NONINVASIVE
from spellbook.control.ingest.model import Posture
from spellbook.runner.tools.gcp_backend import BLAST_RADIUS_PERMISSIONS, get_backend
from spellbook.runner.tools.registry import Tool, register

_INTERNAL = frozenset({Posture.INTERNAL})

# Common east-west service ports worth knowing an attacker can reach internally.
_DEFAULT_EAST_WEST_PORTS = (22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017)


def metadata_token(target: str, params: dict) -> dict:
    """Read ``target``'s borrowed SA identity from the metadata server.

    Surfaces a **fingerprint** of the access token, never the token itself — the
    exploitability signal ("a live credential is reachable from here") without
    handing the agent a usable bearer token.
    """
    backend = get_backend()
    identity = backend.identity()
    token = backend.access_token()
    fingerprint = hashlib.sha256(token.value.encode()).hexdigest()[:12] if token.value else None
    return {
        "target": target,
        "service_account": identity.email,
        "project_id": identity.project_id,
        "zone": identity.zone,
        "scopes": list(identity.scopes),
        "token_available": bool(token.value),
        "token_fingerprint": fingerprint,   # sha256[:12]; the raw token stays in the runner
        "token_expires_in": token.expires_in,
    }


def iam_blast_radius(target: str, params: dict) -> dict:
    """Measure the borrowed SA's blast radius with read-only ``testIamPermissions``."""
    backend = get_backend()
    resource = params.get("resource") or backend.identity().project_id
    tested = list(params.get("permissions") or BLAST_RADIUS_PERMISSIONS)
    granted = backend.test_permissions(resource, tested)
    return {
        "target": target,
        "resource": resource,
        "tested": tested,
        "granted": granted,
        "blast_radius": len(granted),
        "escalation_possible": any(
            p.startswith(("iam.", "resourcemanager.projects.setIamPolicy")) for p in granted
        ),
    }


def east_west_reach(target: str, params: dict) -> dict:
    """TCP-sweep ``target`` for reachable internal service ports (never raises)."""
    ports = params.get("ports") or list(_DEFAULT_EAST_WEST_PORTS)
    timeout = float(params.get("timeout", 2.0))
    open_ports: list[int] = []
    for port in ports:
        try:
            conn = socket.create_connection((target, int(port)), timeout=timeout)
            conn.close()
            open_ports.append(int(port))
        except OSError:
            continue
    return {"host": target, "scanned": [int(p) for p in ports], "open_ports": open_ports}


register(Tool(
    name="metadata_token",
    tier=ACTIVE_NONINVASIVE,
    postures=_INTERNAL,
    handler=metadata_token,
    description="Read the instance's borrowed GCP SA identity + token fingerprint (metadata server).",
    params_schema={"type": "object", "properties": {}},
))

register(Tool(
    name="iam_blast_radius",
    tier=ACTIVE_NONINVASIVE,
    postures=_INTERNAL,
    handler=iam_blast_radius,
    description="Read-only testIamPermissions: which high-impact permissions the borrowed SA holds.",
    params_schema={
        "type": "object",
        "properties": {
            "resource": {"type": "string", "description": "project id (default: instance's project)"},
            "permissions": {"type": "array", "items": {"type": "string"}},
        },
    },
))

register(Tool(
    name="east_west_reach",
    tier=ACTIVE_NONINVASIVE,
    postures=_INTERNAL,
    handler=east_west_reach,
    description="TCP-sweep an internal host for reachable service ports (east-west movement).",
    params_schema={
        "type": "object",
        "properties": {
            "ports": {"type": "array", "items": {"type": "integer"}},
            "timeout": {"type": "number", "default": 2.0},
        },
    },
))
