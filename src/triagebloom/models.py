from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class NormalizedEvent:
    """A vendor-neutral representation of a security event."""

    event_id: str
    timestamp: datetime
    category: str
    event_type: str
    outcome: str
    user: str | None = None
    source_ip: str | None = None
    device: str | None = None
    command_line: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        data.pop("raw", None)
        return data


@dataclass(slots=True)
class Finding:
    """An explainable security finding produced by a detection rule."""

    rule_id: str
    title: str
    severity: str
    confidence: int
    risk_score: int
    mitre_technique: str
    mitre_tactic: str
    summary: str
    evidence_event_ids: list[str]
    entities: dict[str, list[str]]
    why_it_triggered: list[str]
    next_steps: list[str]
    first_seen: datetime
    last_seen: datetime

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["first_seen"] = self.first_seen.isoformat()
        data["last_seen"] = self.last_seen.isoformat()
        return data


@dataclass(slots=True)
class AnalysisResult:
    source_file: str
    generated_at: datetime
    events_processed: int
    findings: list[Finding]
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_file": self.source_file,
            "generated_at": self.generated_at.isoformat(),
            "events_processed": self.events_processed,
            "finding_count": len(self.findings),
            "metadata": self.metadata,
            "findings": [finding.to_dict() for finding in self.findings],
        }
