"""Domain models used throughout the dashboard."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Iterable, List, Optional


class Severity(Enum):
    """Standard severity levels normalised across providers."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        normalised = value.strip().upper()
        try:
            return cls[normalised]
        except KeyError:
            # Map AWS/GitHub variants to our enum.
            mapping = {
                "CRITICAL": cls.CRITICAL,
                "HIGH": cls.HIGH,
                "MEDIUM": cls.MEDIUM,
                "LOW": cls.LOW,
                "INFORMATIONAL": cls.INFORMATIONAL,
                "INFO": cls.INFORMATIONAL,
            }
            if normalised in mapping:
                return mapping[normalised]
            raise ValueError(f"Unknown severity: {value}")


@dataclass
class SecurityFinding:
    """Normalized security finding representation."""

    provider: str
    id: str
    title: str
    severity: Severity
    description: Optional[str] = None
    url: Optional[str] = None
    resource: Optional[str] = None
    created_at: Optional[datetime] = None

    def short_dict(self) -> dict:
        """Return a serializable view used in reports and cache files."""
        data = {
            "provider": self.provider,
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
        }
        if self.description:
            data["description"] = self.description
        if self.url:
            data["url"] = self.url
        if self.resource:
            data["resource"] = self.resource
        if self.created_at:
            data["created_at"] = self.created_at.isoformat()
        return data

    @classmethod
    def from_dict(cls, payload: dict) -> "SecurityFinding":
        created = payload.get("created_at")
        return cls(
            provider=payload["provider"],
            id=payload["id"],
            title=payload["title"],
            severity=Severity.from_string(payload["severity"]),
            description=payload.get("description"),
            url=payload.get("url"),
            resource=payload.get("resource"),
            created_at=datetime.fromisoformat(created) if created else None,
        )


def merge_findings(*finding_sets: Iterable[SecurityFinding]) -> List[SecurityFinding]:
    """Return a single list containing all findings from provided iterables."""

    merged: List[SecurityFinding] = []
    for findings in finding_sets:
        merged.extend(list(findings))
    return merged
