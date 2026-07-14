"""The structured exploitability verdict the agent must return.

The agent concludes with a single JSON object matching this schema, which the
worker parses with pydantic. The same schema is embedded in the system prompt
(:mod:`spellbook.control.agent.prompts`) so the model returns a shape we can
validate — provider-agnostic, independent of any structured-output surface.
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
