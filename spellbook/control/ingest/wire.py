"""JSON (de)serialisation for the control-plane ↔ agent-worker internal API.

The worker runs in a separate Cloud Run service, so the run's inputs (finding,
attack path, scope, authorizations) cross a process boundary as JSON. Keeping the
round-trip in one place means the ``claim`` response the control plane emits and
the objects the worker reconstructs can never drift apart. ``Verdict`` uses its own
pydantic (de)serialisation and is not duplicated here.
"""

from __future__ import annotations

from datetime import datetime

from spellbook.control.ingest.model import (
    Asset, AttackPath, AttackStep, Finding, Posture, Source, Vector,
)
from spellbook.control.safety.authorization import Authorization


def finding_to_dict(finding: Finding) -> dict:
    a = finding.asset
    return {
        "id": finding.id, "source": finding.source.value, "vector": finding.vector.value,
        "severity": finding.severity, "title": finding.title, "raw": finding.raw,
        "asset": {"id": a.id, "cloud": a.cloud, "project": a.project,
                  "host": a.host, "network_location": a.network_location},
    }


def finding_from_dict(d: dict) -> Finding:
    a = d["asset"]
    return Finding(
        id=d["id"], source=Source(d["source"]), vector=Vector(d["vector"]),
        severity=d["severity"], title=d.get("title", ""), raw=d.get("raw") or {},
        asset=Asset(id=a["id"], cloud=a.get("cloud", "gcp"), project=a.get("project"),
                    host=a.get("host"), network_location=a.get("network_location")),
    )


def attack_path_to_dict(path: AttackPath | None) -> dict | None:
    if path is None:
        return None
    return {
        "id": path.id, "finding_id": path.finding_id, "name": path.name,
        "source": path.source.value, "entry_point": path.entry_point, "impact": path.impact,
        "raw": path.raw,
        "steps": [
            {"index": s.index, "technique": s.technique, "description": s.description,
             "from_entity": s.from_entity, "to_entity": s.to_entity,
             "posture": s.posture.value, "suggested_tool": s.suggested_tool, "tier": s.tier}
            for s in path.steps
        ],
    }


def attack_path_from_dict(d: dict | None) -> AttackPath | None:
    if d is None:
        return None
    return AttackPath(
        id=d["id"], finding_id=d["finding_id"], name=d.get("name", ""),
        source=Source(d.get("source", "manual")), entry_point=d.get("entry_point", ""),
        impact=d.get("impact", ""), raw=d.get("raw") or {},
        steps=[AttackStep(index=s["index"], technique=s["technique"],
                          description=s.get("description", ""), from_entity=s.get("from_entity", ""),
                          to_entity=s.get("to_entity", ""), posture=Posture(s["posture"]),
                          suggested_tool=s.get("suggested_tool"), tier=s["tier"])
               for s in d.get("steps", [])],
    )


def authorization_to_dict(auth: Authorization) -> dict:
    return {
        "id": auth.id, "target": auth.target, "max_tier": auth.max_tier,
        "authorized_by": auth.authorized_by, "blast_radius_note": auth.blast_radius_note,
        "expires_at": auth.expires_at.isoformat(),
    }


def authorization_from_dict(d: dict) -> Authorization:
    return Authorization(
        id=d["id"], target=d["target"], max_tier=d["max_tier"],
        authorized_by=d["authorized_by"], blast_radius_note=d["blast_radius_note"],
        expires_at=datetime.fromisoformat(d["expires_at"]),
    )
