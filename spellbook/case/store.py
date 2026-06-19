"""Local case store: ``cases/<id>/`` holding case.json, evidence/, audit.log.

Everything the investigation produces is persisted here so a case can be shown,
exported, or replayed later. The store is deliberately filesystem-only for
Milestone 0 (standalone, no platform handoff).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from spellbook.case.model import Case, EvidenceItem

# Repo root holds the cases/ dir: this file is spellbook/case/store.py → parents[2].
CASES_ROOT = Path(__file__).resolve().parents[2] / "cases"


class CaseStore:
    def __init__(self, case: Case, root: Path | None = None):
        self.case = case
        self.dir = (root or CASES_ROOT) / case.id
        self.evidence_dir = self.dir / "evidence"
        self.audit_path = self.dir / case.audit_log_ref
        self._evidence_seq = len(case.evidence)

    # --- lifecycle ---------------------------------------------------------
    @classmethod
    def open_or_resume(cls, case_id: str, wiz_issue_id: str, mode: str,
                       root: Path | None = None) -> "CaseStore":
        base = root or CASES_ROOT
        case_json = base / case_id / "case.json"
        if case_json.exists():
            case = Case.model_validate_json(case_json.read_text())
            case.mode = mode  # mode may differ between runs
        else:
            case = Case(id=case_id, wiz_issue_id=wiz_issue_id, mode=mode)
        store = cls(case, root=root)
        store.evidence_dir.mkdir(parents=True, exist_ok=True)
        store.save()
        return store

    def save(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "case.json").write_text(self.case.model_dump_json(indent=2))

    # --- writes during investigation --------------------------------------
    def append_audit(self, line: str) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        self.dir.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a") as fh:
            fh.write(f"{ts}\t{line}\n")

    def append_evidence(self, tool: str, command: str, side_effect: str,
                        raw: str, findings: list | None = None,
                        confidence: float = 0.0) -> EvidenceItem:
        self._evidence_seq += 1
        eid = f"E{self._evidence_seq:03d}"
        raw_ref = ""
        if raw:
            raw_ref = f"evidence/{eid}.txt"
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
            (self.dir / raw_ref).write_text(raw)
        item = EvidenceItem(
            id=eid, tool=tool, command=command, side_effect=side_effect,
            raw_ref=raw_ref, findings=findings or [], confidence=confidence,
        )
        self.case.evidence.append(item)
        self.save()
        return item
