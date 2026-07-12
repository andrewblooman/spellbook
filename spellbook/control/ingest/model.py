"""Normalised finding model, shared by Wiz ingestion and manual entry.

A :class:`Finding` is the unit of work: it names an owned :class:`Asset`, the
attack :class:`Vector` to validate, and carries the raw source payload for
evidence. The orchestrator pairs a finding with a :class:`Posture` (external vs
internal vantage) to produce one agent run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


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
