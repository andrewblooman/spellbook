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
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# The Vite/React SPA builds to <repo>/web/dist. In dev the SPA runs on the Vite
# server; in prod FastAPI serves the built bundle from here.
_WEB_DIST = Path(__file__).resolve().parents[2] / "web" / "dist"
_WEB_INDEX = _WEB_DIST / "index.html"

from spellbook.control.ingest.model import (
    Asset, AttackPath, AttackStep, Finding, Posture, Source, Vector,
)
from spellbook.control.ingest.wiz_api import WizAPIError, WizClient, ingest_from_wiz
from spellbook.control.orchestrator import Orchestrator
from spellbook.control.safety.authorization import Authorization
from spellbook.control.store.models import FindingRecord, Run
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
    attack_path_id: str | None = None


class AttackStepIn(BaseModel):
    technique: str
    description: str = ""
    from_entity: str = ""
    to_entity: str = ""
    posture: Posture = Posture.EXTERNAL
    suggested_tool: str | None = None
    tier: str = ACTIVE_NONINVASIVE


class AttackPathIn(BaseModel):
    """Manually define an attack path (for something not in Wiz) + its finding."""

    id: str
    finding: FindingIn
    name: str = ""
    entry_point: str = ""
    impact: str = ""
    steps: list[AttackStepIn] = Field(default_factory=list)

    def to_attack_path(self) -> AttackPath:
        return AttackPath(
            id=self.id, finding_id=self.finding.id, name=self.name, source=Source.MANUAL,
            entry_point=self.entry_point, impact=self.impact,
            steps=[
                AttackStep(index=i, technique=s.technique, description=s.description,
                           from_entity=s.from_entity, to_entity=s.to_entity,
                           posture=s.posture, suggested_tool=s.suggested_tool, tier=s.tier)
                for i, s in enumerate(self.steps)
            ],
        )


class WizIngestIn(BaseModel):
    first: int = 20


# --- serialisation --------------------------------------------------------
def _run_out(run: Run) -> dict[str, Any]:
    return {
        "id": run.id,
        "finding_id": run.finding_id,
        "attack_path_id": run.attack_path_id,
        "posture": run.posture,
        "tier": run.tier,
        "status": run.status,
        "created_at": run.created_at.isoformat() if run.created_at else None,
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
        "step_results": [
            {"step_index": sr.step_index, "status": sr.status, "tool": sr.tool,
             "observation": sr.observation, "interpretation": sr.interpretation}
            for sr in run.step_results
        ],
        "audit": [
            {"ts": a.ts.isoformat(), "tool": a.tool, "target": a.target, "tier": a.tier,
             "allowed": a.allowed, "reason": a.reason}
            for a in run.audit
        ],
    }


def _finding_out(rec: FindingRecord) -> dict[str, Any]:
    return {
        "id": rec.id, "source": rec.source, "vector": rec.vector, "severity": rec.severity,
        "title": rec.title, "host": rec.host, "target": rec.target, "cloud": rec.cloud,
        "project": rec.project,
    }


def _path_out(path: AttackPath) -> dict[str, Any]:
    return {
        "id": path.id, "finding_id": path.finding_id, "name": path.name,
        "source": path.source.value, "entry_point": path.entry_point, "impact": path.impact,
        "steps": [
            {"index": s.index, "technique": s.technique, "description": s.description,
             "from_entity": s.from_entity, "to_entity": s.to_entity,
             "posture": s.posture.value, "suggested_tool": s.suggested_tool, "tier": s.tier}
            for s in path.steps
        ],
    }


def create_app(orchestrator: Orchestrator, store: Store) -> FastAPI:
    app = FastAPI(title="Spellbook", summary="Wiz finding exploitability validation")

    if (_WEB_DIST / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=_WEB_DIST / "assets"), name="assets")

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def index() -> str:
        if _WEB_INDEX.exists():
            return _WEB_INDEX.read_text()
        return ("<h1>Spellbook</h1><p>SPA not built. Run <code>npm --prefix web ci &amp;&amp; "
                "npm --prefix web run build</code>, or use the Vite dev server.</p>")

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

    @app.post("/wiz/ingest", status_code=201)
    def wiz_ingest(body: WizIngestIn) -> dict:
        try:
            ids = ingest_from_wiz(WizClient(), store, first=body.first)
        except WizAPIError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return {"ingested": ids}

    @app.post("/attack-paths", status_code=201)
    def create_attack_path(body: AttackPathIn) -> dict:
        store.save_finding(body.finding.to_finding())
        store.save_attack_path(body.to_attack_path())
        return {"id": body.id, "finding_id": body.finding.id}

    @app.get("/attack-paths/{path_id}")
    def get_attack_path(path_id: str) -> dict:
        path = store.get_attack_path(path_id)
        if path is None:
            raise HTTPException(status_code=404, detail=f"unknown attack path {path_id!r}")
        out = _path_out(path)
        out["step_results"] = [  # merged across every run of this path
            {"step_index": sr.step_index, "status": sr.status, "tool": sr.tool,
             "observation": sr.observation, "interpretation": sr.interpretation}
            for sr in store.path_step_results(path_id)
        ]
        return out

    @app.get("/findings")
    def list_findings() -> list[dict]:
        return [_finding_out(f) for f in store.list_findings()]

    @app.get("/findings/{finding_id}")
    def get_finding(finding_id: str) -> dict:
        finding = store.get_finding(finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail=f"unknown finding {finding_id!r}")
        out = {"id": finding.id, "source": finding.source.value, "vector": finding.vector.value,
               "severity": finding.severity, "title": finding.title,
               "target": finding.asset.target, "host": finding.asset.host,
               "project": finding.asset.project, "cloud": finding.asset.cloud}
        out["attack_paths"] = [_path_out(p) for p in store.attack_paths_for_finding(finding_id)]
        return out

    @app.post("/runs", status_code=201)
    def start_run(body: RunIn) -> dict:
        finding = store.get_finding(body.finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail=f"unknown finding {body.finding_id!r}")
        attack_path = store.get_attack_path(body.attack_path_id) if body.attack_path_id else None
        if body.attack_path_id and attack_path is None:
            raise HTTPException(status_code=404, detail=f"unknown attack path {body.attack_path_id!r}")
        run_id = orchestrator.start_run(
            finding, body.posture, tier=body.tier, authorization_id=body.authorization_id,
            attack_path=attack_path,
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
