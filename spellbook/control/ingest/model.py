"""Normalised finding model, shared by Wiz ingestion and manual entry.

A :class:`Finding` is the unit of work: it names an owned :class:`Asset`, the
attack :class:`Vector` to validate, and carries the raw source payload for
evidence. The orchestrator pairs a finding with a :class:`Posture` (external vs
internal vantage) to produce one agent run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from spellbook.safety.classify import ACTIVE_NONINVASIVE


class Posture(str, Enum):
    """Where the validation agent's *hands* (the runner) sit."""

    EXTERNAL = "external"  # shields up — internet vantage, outside the VPC
    INTERNAL = "internal"  # shields down — assumed-breach, inside the VPC


class Vector(str, Enum):
    CVE = "cve"
    MISCONFIG = "misconfig"
    EXPOSED_SERVICE = "exposed_service"
    IAM = "iam"


class Source(str, Enum):
    WIZ = "wiz"
    MANUAL = "manual"


@dataclass(frozen=True)
class Asset:
    """An owned target. ``target`` is what scope/authorization checks resolve on."""

    id: str
    cloud: str = "gcp"
    project: str | None = None
    host: str | None = None          # DNS name or IP for network-facing assets
    network_location: str | None = None  # subnet / CIDR the asset lives in

    @property
    def target(self) -> str:
        """The primary scope target: prefer a reachable host, else the asset id."""
        return self.host or self.id


@dataclass(frozen=True)
class Finding:
    id: str
    source: Source
    asset: Asset
    vector: Vector
    severity: str
    title: str = ""
    raw: dict = field(default_factory=dict)


class StepStatus(str, Enum):
    """The validation outcome for a single attack-path step."""

    VALIDATED = "validated"      # the step works — the chain holds here
    REFUTED = "refuted"          # the step is blocked — the chain breaks here
    INCONCLUSIVE = "inconclusive"
    SKIPPED = "skipped"          # not attempted (e.g. wrong posture for this run)


# Common technique labels (loose, MITRE-ish). Kept as plain strings so Wiz-imported
# and hand-written paths aren't constrained to a fixed vocabulary.
TECHNIQUES = (
    "public_exposure", "exploit_cve", "auth_bypass", "credential_theft",
    "iam_privesc", "lateral_move", "data_access",
)


@dataclass(frozen=True)
class AttackStep:
    """One link in a linear attack path: a technique moving from one entity to the next."""

    index: int
    technique: str
    description: str = ""
    from_entity: str = ""
    to_entity: str = ""
    posture: Posture = Posture.EXTERNAL
    suggested_tool: str | None = None     # runner tool that would validate this step
    tier: str = ACTIVE_NONINVASIVE


@dataclass(frozen=True)
class AttackPath:
    """An ordered chain of steps from entry point to impact, tied to a finding."""

    id: str
    finding_id: str
    name: str = ""
    source: Source = Source.MANUAL
    entry_point: str = ""
    impact: str = ""
    steps: list[AttackStep] = field(default_factory=list)
    raw: dict = field(default_factory=dict)
