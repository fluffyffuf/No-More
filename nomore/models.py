from __future__ import annotations

import hashlib
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

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.index(self.value)


SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


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

    def fingerprint(self) -> str:
        """Stable identity used to de-duplicate findings and diff scans."""
        raw = "|".join([self.title, self.affected_asset, self.affected_url, self.parameter])
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        known = {name for name in cls.__dataclass_fields__}
        values = {key: value for key, value in data.items() if key in known}
        values["severity"] = Severity(str(values.get("severity", "INFO")).upper())
        return cls(**values)

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
            "fingerprint": self.fingerprint(),
        }
