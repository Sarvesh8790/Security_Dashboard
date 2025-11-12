"""Utilities to build a consolidated security dashboard."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Iterable, Mapping, MutableMapping

from .models import SecurityFinding, Severity


class DashboardReport:
    """Generate simple aggregate metrics suitable for console dashboards."""

    def __init__(self, findings: Iterable[SecurityFinding]):
        self._findings = list(findings)
        self.generated_at = datetime.utcnow()

    @property
    def total_findings(self) -> int:
        return len(self._findings)

    @property
    def findings_by_provider(self) -> Mapping[str, int]:
        counts: MutableMapping[str, int] = Counter()
        for finding in self._findings:
            counts[finding.provider] += 1
        return dict(counts)

    @property
    def findings_by_severity(self) -> Mapping[Severity, int]:
        counts: MutableMapping[Severity, int] = Counter()
        for finding in self._findings:
            counts[finding.severity] += 1
        return dict(counts)

    def findings_by_provider_and_severity(self) -> Mapping[str, Mapping[Severity, int]]:
        nested: MutableMapping[str, MutableMapping[Severity, int]] = defaultdict(Counter)
        for finding in self._findings:
            nested[finding.provider][finding.severity] += 1
        return {provider: dict(severity_counts) for provider, severity_counts in nested.items()}

    def to_rows(self) -> list[dict]:
        """Return rows suitable for rendering in a tabular view."""
        rows = []
        grouped = self.findings_by_provider_and_severity()
        for provider, severity_counts in grouped.items():
            row = {"Provider": provider, "Total": sum(severity_counts.values())}
            for severity in Severity:
                row[severity.value.title()] = severity_counts.get(severity, 0)
            rows.append(row)
        rows.sort(key=lambda item: item["Total"], reverse=True)
        return rows
