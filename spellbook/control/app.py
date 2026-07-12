"""FastAPI control plane — the web surface over the orchestrator + store.

Endpoints (M0):
- ``POST /findings``           ingest a finding (manual, or normalised from Wiz)
- ``POST /authorizations``     create a signed exploit-tier authorization
- ``POST /runs``               start a validation run (gated pre-launch)
- ``POST /runs/{id}/complete`` poll the agent to completion, persist the verdict
- ``GET  /runs`` / ``/runs/{id}``  list / fetch runs with verdict + evidence + audit

The app is built by :func:`create_app` with an injected orchestrator + store, so
it runs under ``TestClient`` with fakes (no GCP, no Gemini). ``complete`` is
synchronous for M0; production would background it or use the interaction webhook.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

# The zero-build single-page UI lives at the repo root: <repo>/web/index.html
_WEB_INDEX = Path(__file__).resolve().parents[2] / "web" / "index.html"

from spellbook.control.ingest.model import Asset, Finding, Posture, Source, Vector
from spellbook.control.orchestrator import Orchestrator
from spellbook.control.safety.authorization import Authorization
from spellbook.control.store.models import Run
from spellbook.control.store.store import Store
from spellbook.safety.classify import ACTIVE_NONINVASIVE


# --- request models -------------------------------------------------------
class FindingIn(BaseModel):
    id: str
    vector: Vector
    severity: str
    asset_id: str
    source: Source = Source.MANUAL
    title: str = ""
    host: str | None = None
    project: str | None = None
    cloud: str = "gcp"
    network_location: str | None = None
    raw: dict = Field(default_factory=dict)

    def to_finding(self) -> Finding:
        return Finding(
            id=self.id, source=self.source, vector=self.vector, severity=self.severity,
            title=self.title, raw=self.raw,
            asset=Asset(id=self.asset_id, cloud=self.cloud, project=self.project,
                        host=self.host, network_location=self.network_location),
        )


class AuthorizationIn(BaseModel):
    id: str
    target: str
    max_tier: str
    authorized_by: str
    blast_radius_note: str
    expires_at: datetime


class RunIn(BaseModel):
    finding_id: str
    posture: Posture
    tier: str = ACTIVE_NONINVASIVE
    authorization_id: str | None = None


# --- serialisation --------------------------------------------------------
def _run_out(run: Run) -> dict[str, Any]:
    return {
        "id": run.id,
        "finding_id": run.finding_id,
        "posture": run.posture,
        "tier": run.tier,
        "status": run.status,
        "agent_job_id": run.agent_job_id,
        "authorization_id": run.authorization_id,
        "verdict": run.verdict_label,
        "confidence": run.confidence,
        "verdict_detail": run.verdict,
        "error": run.error,
        "evidence": [
            {"tool": e.tool, "target": e.target, "observation": e.observation,
             "interpretation": e.interpretation}
            for e in run.evidence
        ],
        "audit": [
            {"ts": a.ts.isoformat(), "tool": a.tool, "target": a.target, "tier": a.tier,
             "allowed": a.allowed, "reason": a.reason}
            for a in run.audit
        ],
    }


def create_app(orchestrator: Orchestrator, store: Store) -> FastAPI:
    app = FastAPI(title="Spellbook", summary="Wiz finding exploitability validation")

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def index() -> str:
        if _WEB_INDEX.exists():
            return _WEB_INDEX.read_text()
        return "<h1>Spellbook</h1><p>UI not found; API is at /docs</p>"

    @app.post("/findings", status_code=201)
    def ingest_finding(body: FindingIn) -> dict:
        store.save_finding(body.to_finding())
        return {"id": body.id}

    @app.post("/authorizations", status_code=201)
    def create_authorization(body: AuthorizationIn) -> dict:
        try:
            auth = Authorization(**body.model_dump())
        except ValueError as exc:  # missing blast-radius note / naive expiry / bad tier
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        store.save_authorization(auth)
        return {"id": auth.id}

    @app.post("/runs", status_code=201)
    def start_run(body: RunIn) -> dict:
        finding = store.get_finding(body.finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail=f"unknown finding {body.finding_id!r}")
        run_id = orchestrator.start_run(
            finding, body.posture, tier=body.tier, authorization_id=body.authorization_id,
        )
        return _run_out(store.get_run(run_id))

    @app.post("/runs/{run_id}/complete")
    def complete_run(run_id: str) -> dict:
        run = orchestrator.complete_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail=f"unknown run {run_id!r}")
        return _run_out(run)

    @app.get("/runs/{run_id}")
    def get_run(run_id: str) -> dict:
        run = store.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail=f"unknown run {run_id!r}")
        return _run_out(run)

    @app.get("/runs")
    def list_runs() -> list[dict]:
        return [_run_out(r) for r in store.list_runs()]

    return app
