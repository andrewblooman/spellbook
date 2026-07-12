"""SQLAlchemy 2.0 models for the control-plane store.

The persistent record of every validation run: the finding it targeted, the run's
posture/tier/status, the parsed verdict, its evidence chain, the audit trail, and
the signed authorizations that gate the exploit tier. SQLite (tests) and Postgres
(prod) differ only by connection URL.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from spellbook.control.safety.authorization import Authorization


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    """SQLite drops tzinfo on read; treat naive timestamps as UTC."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


class Base(DeclarativeBase):
    pass


class FindingRecord(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    source: Mapped[str] = mapped_column(String)
    vector: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String)
    title: Mapped[str] = mapped_column(String, default="")
    target: Mapped[str] = mapped_column(String)  # denormalised host-or-id, for scope queries
    asset_id: Mapped[str] = mapped_column(String)
    host: Mapped[str | None] = mapped_column(String, nullable=True)
    cloud: Mapped[str] = mapped_column(String, default="gcp")
    project: Mapped[str | None] = mapped_column(String, nullable=True)
    network_location: Mapped[str | None] = mapped_column(String, nullable=True)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"))
    attack_path_id: Mapped[str | None] = mapped_column(ForeignKey("attack_paths.id"), nullable=True)
    posture: Mapped[str] = mapped_column(String)
    tier: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="pending")
    agent_job_id: Mapped[str | None] = mapped_column(String, nullable=True)
    authorization_id: Mapped[str | None] = mapped_column(String, nullable=True)
    verdict_label: Mapped[str | None] = mapped_column(String, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    verdict: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="run", cascade="all, delete-orphan", order_by="Evidence.step_index",
    )
    audit: Mapped[list["AuditRecord"]] = relationship(
        back_populates="run", cascade="all, delete-orphan", order_by="AuditRecord.ts",
    )
    step_results: Mapped[list["StepResultRecord"]] = relationship(
        back_populates="run", cascade="all, delete-orphan", order_by="StepResultRecord.step_index",
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"))
    step_index: Mapped[int] = mapped_column(Integer)
    tool: Mapped[str] = mapped_column(String)
    target: Mapped[str] = mapped_column(String)
    observation: Mapped[str] = mapped_column(String)
    interpretation: Mapped[str] = mapped_column(String)

    run: Mapped[Run] = relationship(back_populates="evidence")


class AuditRecord(Base):
    __tablename__ = "audit"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    tool: Mapped[str] = mapped_column(String)
    target: Mapped[str] = mapped_column(String)
    tier: Mapped[str] = mapped_column(String)
    posture: Mapped[str] = mapped_column(String)
    allowed: Mapped[bool] = mapped_column(Boolean)
    reason: Mapped[str] = mapped_column(String)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)

    run: Mapped[Run | None] = relationship(back_populates="audit")


class AttackPathRecord(Base):
    __tablename__ = "attack_paths"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"))
    name: Mapped[str] = mapped_column(String, default="")
    source: Mapped[str] = mapped_column(String, default="manual")
    entry_point: Mapped[str] = mapped_column(String, default="")
    impact: Mapped[str] = mapped_column(String, default="")
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    steps: Mapped[list["AttackStepRecord"]] = relationship(
        back_populates="path", cascade="all, delete-orphan", order_by="AttackStepRecord.step_index",
    )


class AttackStepRecord(Base):
    __tablename__ = "attack_steps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    path_id: Mapped[str] = mapped_column(ForeignKey("attack_paths.id"))
    step_index: Mapped[int] = mapped_column(Integer)
    technique: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(String, default="")
    from_entity: Mapped[str] = mapped_column(String, default="")
    to_entity: Mapped[str] = mapped_column(String, default="")
    posture: Mapped[str] = mapped_column(String)
    suggested_tool: Mapped[str | None] = mapped_column(String, nullable=True)
    tier: Mapped[str] = mapped_column(String)

    path: Mapped[AttackPathRecord] = relationship(back_populates="steps")


class StepResultRecord(Base):
    __tablename__ = "step_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"))
    path_id: Mapped[str | None] = mapped_column(ForeignKey("attack_paths.id"), nullable=True)
    step_index: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String)
    tool: Mapped[str] = mapped_column(String, default="")
    observation: Mapped[str] = mapped_column(String, default="")
    interpretation: Mapped[str] = mapped_column(String, default="")

    run: Mapped["Run"] = relationship(back_populates="step_results")


class AuthorizationRecord(Base):
    __tablename__ = "authorizations"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    target: Mapped[str] = mapped_column(String)
    max_tier: Mapped[str] = mapped_column(String)
    authorized_by: Mapped[str] = mapped_column(String)
    blast_radius_note: Mapped[str] = mapped_column(String)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    def to_authorization(self) -> Authorization:
        return Authorization(
            id=self.id, target=self.target, max_tier=self.max_tier,
            authorized_by=self.authorized_by, blast_radius_note=self.blast_radius_note,
            expires_at=_aware(self.expires_at),
        )
