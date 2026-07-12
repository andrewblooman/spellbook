"""Repository over the SQLAlchemy models — the control plane's persistence API.

Keeps ORM/session mechanics in one place so the orchestrator and API talk in
domain terms (findings, runs, verdicts, authorizations).
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import selectinload, sessionmaker
from sqlalchemy.pool import StaticPool

from spellbook.control.agent.schema import Verdict
from spellbook.control.ingest.model import Asset, Finding, Posture, Source, Vector
from spellbook.control.safety.authorization import Authorization
from spellbook.control.store.models import (
    AuditRecord,
    AuthorizationRecord,
    Base,
    Evidence,
    FindingRecord,
    Run,
)


def init_engine(url: str = "sqlite://", echo: bool = False) -> Engine:
    """Create an engine and initialise the schema.

    Bare ``sqlite://`` is an in-memory DB shared across sessions (StaticPool),
    which is what the tests use.
    """
    kwargs: dict = {"echo": echo, "future": True}
    if url in ("sqlite://", "sqlite:///:memory:"):
        kwargs |= {"connect_args": {"check_same_thread": False}, "poolclass": StaticPool}
    engine = create_engine(url, **kwargs)
    Base.metadata.create_all(engine)
    return engine


class Store:
    def __init__(self, engine: Engine) -> None:
        self._session = sessionmaker(engine, expire_on_commit=False, future=True)

    # --- findings ---------------------------------------------------------
    def save_finding(self, finding: Finding) -> None:
        with self._session.begin() as s:
            s.merge(FindingRecord(
                id=finding.id, source=finding.source.value, vector=finding.vector.value,
                severity=finding.severity, title=finding.title, target=finding.asset.target,
                asset_id=finding.asset.id, host=finding.asset.host, cloud=finding.asset.cloud,
                project=finding.asset.project, network_location=finding.asset.network_location,
                raw=finding.raw,
            ))

    def get_finding(self, finding_id: str) -> Finding | None:
        with self._session() as s:
            rec = s.get(FindingRecord, finding_id)
        if rec is None:
            return None
        return Finding(
            id=rec.id, source=Source(rec.source), vector=Vector(rec.vector),
            severity=rec.severity, title=rec.title, raw=rec.raw or {},
            asset=Asset(id=rec.asset_id, cloud=rec.cloud, project=rec.project,
                        host=rec.host, network_location=rec.network_location),
        )

    # --- runs -------------------------------------------------------------
    def create_run(self, run_id: str, finding: Finding, posture: Posture, tier: str,
                   *, status: str = "pending", authorization_id: str | None = None) -> None:
        with self._session.begin() as s:
            s.add(Run(id=run_id, finding_id=finding.id, posture=posture.value, tier=tier,
                      status=status, authorization_id=authorization_id))

    def update_run(self, run_id: str, **fields) -> None:
        with self._session.begin() as s:
            run = s.get(Run, run_id)
            for key, value in fields.items():
                setattr(run, key, value)

    def record_verdict(self, run_id: str, verdict: Verdict) -> None:
        with self._session.begin() as s:
            run = s.get(Run, run_id)
            run.verdict_label = verdict.label.value
            run.confidence = verdict.confidence
            run.verdict = verdict.model_dump(mode="json")
            for i, step in enumerate(verdict.evidence_chain):
                s.add(Evidence(run_id=run_id, step_index=i, tool=step.tool, target=step.target,
                               observation=step.observation, interpretation=step.interpretation))

    _RUN_EAGER = (selectinload(Run.evidence), selectinload(Run.audit))

    def get_run(self, run_id: str) -> Run | None:
        with self._session() as s:
            return s.scalars(
                select(Run).where(Run.id == run_id).options(*self._RUN_EAGER)
            ).one_or_none()

    def list_runs(self) -> list[Run]:
        with self._session() as s:
            return list(s.scalars(
                select(Run).options(*self._RUN_EAGER).order_by(Run.created_at.desc())
            ))

    # --- audit ------------------------------------------------------------
    def add_audit(self, *, run_id: str | None, tool: str, target: str, tier: str,
                  posture: str, allowed: bool, reason: str, detail: dict | None = None) -> None:
        with self._session.begin() as s:
            s.add(AuditRecord(run_id=run_id, tool=tool, target=target, tier=tier,
                              posture=posture, allowed=allowed, reason=reason, detail=detail or {}))

    # --- authorizations ---------------------------------------------------
    def save_authorization(self, auth: Authorization) -> None:
        with self._session.begin() as s:
            s.merge(AuthorizationRecord(
                id=auth.id, target=auth.target, max_tier=auth.max_tier,
                authorized_by=auth.authorized_by, blast_radius_note=auth.blast_radius_note,
                expires_at=auth.expires_at,
            ))

    def active_authorizations(self, now: datetime | None = None) -> list[Authorization]:
        now = now or datetime.now(timezone.utc)
        with self._session() as s:
            records = s.scalars(select(AuthorizationRecord)).all()
        return [r.to_authorization() for r in records if r.to_authorization().expires_at > now]
