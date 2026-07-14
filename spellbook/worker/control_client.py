"""HTTP client the worker uses to talk to the spellbook control plane.

Two calls: ``claim`` a dispatched run for this posture, and ``post_result`` when
the loop finishes. Bearer-authed with ``SPELLBOOK_WORKER_TOKEN`` over the control
plane's VPC-internal API. The claim response is the *only* source of the run's
posture / scope / authorizations — the worker never derives them from the model.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from spellbook.control.agent.schema import Verdict
from spellbook.control.ingest.model import AttackPath, Finding, Posture
from spellbook.control.ingest.wire import (
    attack_path_from_dict, authorization_from_dict, finding_from_dict,
)
from spellbook.control.safety.authorization import Authorization
from spellbook.runner.audit import AuditEvent


@dataclass
class ClaimedRun:
    """A run the control plane handed to this worker (server-authoritative inputs)."""

    run_id: str
    finding: Finding
    posture: Posture
    scope: set[str]
    authorizations: list[Authorization]
    attack_path: AttackPath | None = None


class ControlClient:
    def __init__(self, base_url: str, token: str, *, client: httpx.Client | None = None,
                 timeout: float = 30.0) -> None:
        self._base = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}"}
        self._client = client or httpx.Client(timeout=timeout)

    def claim(self, posture: Posture) -> ClaimedRun | None:
        """Claim one dispatched run for ``posture``; ``None`` when the queue is empty."""
        resp = self._client.get(f"{self._base}/internal/runs/claim",
                                params={"posture": posture.value}, headers=self._headers)
        if resp.status_code == 204:
            return None
        resp.raise_for_status()
        d = resp.json()
        return ClaimedRun(
            run_id=d["run_id"],
            finding=finding_from_dict(d["finding"]),
            posture=Posture(d["posture"]),
            scope={h.lower() for h in d.get("scope", [])},
            authorizations=[authorization_from_dict(a) for a in d.get("authorizations", [])],
            attack_path=attack_path_from_dict(d.get("attack_path")),
        )

    def post_result(self, run_id: str, *, verdict: Verdict | None, error: str | None,
                    audit_events: list[AuditEvent]) -> None:
        """Report the verdict (or error) + the run's audit trail back to the control plane."""
        body = {
            "verdict": verdict.model_dump(mode="json") if verdict is not None else None,
            "error": error,
            "audit": [
                {"tool": e.tool, "target": e.target, "tier": e.tier, "posture": e.posture,
                 "allowed": e.allowed, "reason": e.reason, "detail": e.detail}
                for e in audit_events
            ],
        }
        resp = self._client.post(f"{self._base}/internal/runs/{run_id}/result",
                                 json=body, headers=self._headers)
        resp.raise_for_status()
