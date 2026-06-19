"""Case, evidence, and verdict schema.

A *case* is the unit of triage for one Wiz issue. Evidence is appended by the
``PostToolUse`` hook as the investigation runs; the verdict is produced at the
end (Milestone 1 — left optional here).
"""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EvidenceItem(BaseModel):
    id: str
    tool: str
    command: str
    side_effect: str  # passive | active_noninvasive | active_invasive
    raw_ref: str = ""  # path under evidence/, secrets redacted
    findings: list = Field(default_factory=list)
    confidence: float = 0.0
    ts: str = Field(default_factory=_now)


class Verdict(BaseModel):
    status: str  # confirmed | refuted | inconclusive
    risk_score: float = 0.0
    confidence: float = 0.0
    rationale: str = ""  # references EvidenceItem ids
    validated_signals: list = Field(default_factory=list)
    asserted_signals: list = Field(default_factory=list)


class Case(BaseModel):
    id: str
    wiz_issue_id: str
    mode: str  # interactive | auto
    created_at: str = Field(default_factory=_now)
    subject: dict = Field(default_factory=dict)  # resource, repo, image, account, exposure
    evidence: list[EvidenceItem] = Field(default_factory=list)
    verdict: Verdict | None = None
    audit_log_ref: str = "audit.log"
