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
from spellbook.control.ingest.model import (
    Asset,
    AttackPath,
    AttackStep,
    Finding,
    Posture,
    Source,
    Vector,
)
from spellbook.control.safety.authorization import Authorization
from spellbook.control.store.models import (
    AttackPathRecord,
    AttackStepRecord,
    AuditRecord,
    AuthorizationRecord,
    Base,
    Evidence,
    FindingRecord,
    Run,
    StepResultRecord,
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

    def list_findings(self) -> list[FindingRecord]:
        with self._session() as s:
            return list(s.scalars(select(FindingRecord).order_by(FindingRecord.created_at.desc())))

    # --- attack paths -----------------------------------------------------
    def save_attack_path(self, path: AttackPath) -> None:
        """Upsert a path in place, replacing only its steps.

        Updating the existing row (rather than delete+recreate) keeps the
        ``attack_paths.id`` FK'd from runs/step-results intact; reassigning
        ``rec.steps`` lets cascade delete-orphan swap the child steps.
        """
        with self._session.begin() as s:
            rec = s.get(AttackPathRecord, path.id)
            if rec is None:
                rec = AttackPathRecord(id=path.id)
                s.add(rec)
            rec.finding_id = path.finding_id
            rec.name = path.name
            rec.source = path.source.value
            rec.entry_point = path.entry_point
            rec.impact = path.impact
            rec.raw = path.raw
            rec.steps = [
                AttackStepRecord(
                    step_index=step.index, technique=step.technique,
                    description=step.description, from_entity=step.from_entity,
                    to_entity=step.to_entity, posture=step.posture.value,
                    suggested_tool=step.suggested_tool, tier=step.tier)
                for step in path.steps
            ]

    @staticmethod
    def _to_attack_path(rec: AttackPathRecord) -> AttackPath:
        return AttackPath(
            id=rec.id, finding_id=rec.finding_id, name=rec.name,
            source=Source(rec.source), entry_point=rec.entry_point, impact=rec.impact,
            raw=rec.raw or {},
            steps=[AttackStep(index=st.step_index, technique=st.technique,
                              description=st.description, from_entity=st.from_entity,
                              to_entity=st.to_entity, posture=Posture(st.posture),
                              suggested_tool=st.suggested_tool, tier=st.tier)
                   for st in rec.steps])

    def get_attack_path(self, path_id: str) -> AttackPath | None:
        with self._session() as s:
            rec = s.scalars(
                select(AttackPathRecord).where(AttackPathRecord.id == path_id)
                .options(selectinload(AttackPathRecord.steps))
            ).one_or_none()
            return self._to_attack_path(rec) if rec is not None else None

    def attack_paths_for_finding(self, finding_id: str) -> list[AttackPath]:
        with self._session() as s:
            recs = s.scalars(
                select(AttackPathRecord).where(AttackPathRecord.finding_id == finding_id)
                .options(selectinload(AttackPathRecord.steps))
            ).all()
            return [self._to_attack_path(r) for r in recs]

    def path_step_results(self, path_id: str) -> list[StepResultRecord]:
        """The merged diagnosis: one best result per step across all runs of this path.

        A step is validated by whichever posture's run owns it, so across runs the same
        step index can carry a `skipped` (from the other posture) alongside a real result.
        Keep one per step: prefer non-`skipped`, then the latest record.
        """
        with self._session() as s:
            rows = list(s.scalars(
                select(StepResultRecord).where(StepResultRecord.path_id == path_id)
                .order_by(StepResultRecord.id)
            ))
        best: dict[int, StepResultRecord] = {}
        for r in rows:
            current = best.get(r.step_index)
            if current is None or (r.status != "skipped", r.id) >= (current.status != "skipped", current.id):
                best[r.step_index] = r
        return [best[i] for i in sorted(best)]

    # --- runs -------------------------------------------------------------
    def create_run(self, run_id: str, finding: Finding, posture: Posture, tier: str,
                   *, status: str = "pending", authorization_id: str | None = None,
                   attack_path_id: str | None = None) -> None:
        with self._session.begin() as s:
            s.add(Run(id=run_id, finding_id=finding.id, posture=posture.value, tier=tier,
                      status=status, authorization_id=authorization_id,
                      attack_path_id=attack_path_id))

    @staticmethod
    def _require_run(s, run_id: str) -> Run:
        run = s.get(Run, run_id)
        if run is None:
            raise LookupError(f"unknown run {run_id!r}")
        return run

    def update_run(self, run_id: str, **fields) -> None:
        with self._session.begin() as s:
            run = self._require_run(s, run_id)
            for key, value in fields.items():
                setattr(run, key, value)

    def record_verdict(self, run_id: str, verdict: Verdict) -> None:
        with self._session.begin() as s:
            run = self._require_run(s, run_id)
            run.verdict_label = verdict.label.value
            run.confidence = verdict.confidence
            run.verdict = verdict.model_dump(mode="json")
            for i, step in enumerate(verdict.evidence_chain):
                s.add(Evidence(run_id=run_id, step_index=i, tool=step.tool, target=step.target,
                               observation=step.observation, interpretation=step.interpretation))
            for sr in verdict.step_results:
                s.add(StepResultRecord(
                    run_id=run_id, path_id=run.attack_path_id, step_index=sr.step_index,
                    status=sr.status.value, observation=sr.observation,
                    interpretation=sr.interpretation))

    def claim_dispatched_run(self, posture: Posture) -> Run | None:
        """Atomically hand the oldest ``dispatched`` run for ``posture`` to a worker.

        Flips it ``dispatched`` → ``running`` inside one transaction so two workers
        can't claim the same run. ``FOR UPDATE SKIP LOCKED`` is used where the dialect
        supports it (Postgres); SQLAlchemy omits it on SQLite, where the StaticPool's
        single connection already serialises claims.
        """
        with self._session.begin() as s:
            run = s.scalars(
                select(Run)
                .where(Run.status == "dispatched", Run.posture == posture.value)
                .order_by(Run.created_at).limit(1)
                .with_for_update(skip_locked=True)
            ).one_or_none()
            if run is None:
                return None
            run.status = "running"
            run_id = run.id
        return self.get_run(run_id)

    _RUN_EAGER = (selectinload(Run.evidence), selectinload(Run.audit),
                  selectinload(Run.step_results))

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
        auths = (r.to_authorization() for r in records)
        return [a for a in auths if a.expires_at > now]
