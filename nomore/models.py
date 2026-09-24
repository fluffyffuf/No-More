from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __str__(self) -> str:
        return self.value


@dataclass
class Finding:
    title: str
    severity: Severity = Severity.INFO
    confidence: str = "low"
    affected_asset: str = ""
    affected_url: str = ""
    parameter: str = ""
    evidence: list[str] = field(default_factory=list)
    description: str = ""
    impact: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    detection_method: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "n/a"

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": str(self.severity),
            "confidence": self.confidence,
            "affected_asset": self.affected_asset,
            "affected_url": self.affected_url,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": self.references,
            "detection_method": self.detection_method,
            "timestamp": self.timestamp,
            "source": self.source,
        }
