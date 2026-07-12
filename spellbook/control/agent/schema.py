"""The structured exploitability verdict the agent must return.

Delivered as JSON (``response_mime_type='application/json'``) and parsed with
pydantic. The same schema is embedded in the system prompt so the model returns a
shape we can validate, regardless of the exact structured-output surface of the
Interactions API.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from spellbook.control.ingest.model import StepStatus


class VerdictLabel(str, Enum):
    EXPLOITABLE = "EXPLOITABLE"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
    INCONCLUSIVE = "INCONCLUSIVE"


class EvidenceStep(BaseModel):
    """One link in the evidence chain: a tool call and what it proved."""

    tool: str
    target: str
    observation: str = Field(description="What the tool returned, summarised.")
    interpretation: str = Field(description="What this implies about exploitability.")


class StepVerdict(BaseModel):
    """The validation outcome for one attack-path step (per-step diagnosis)."""

    step_index: int
    status: StepStatus
    observation: str = ""
    interpretation: str = ""


class Verdict(BaseModel):
    label: VerdictLabel
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    evidence_chain: list[EvidenceStep] = Field(default_factory=list)
    reproduction: str = Field(default="", description="Steps to reproduce, if exploitable.")
    attack_path: list[str] = Field(
        default_factory=list,
        description="For the internal posture: the ordered lateral-movement pivots.",
    )
    step_results: list[StepVerdict] = Field(
        default_factory=list,
        description="Per-step validation of the attack path (one entry per validated step).",
    )
