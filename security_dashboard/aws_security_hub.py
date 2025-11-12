"""Integration helpers for AWS Security Hub."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional

try:  # pragma: no cover - optional dependency
    import boto3
    from botocore.config import Config as BotoConfig
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:  # pragma: no cover - optional dependency
    boto3 = None  # type: ignore[assignment]

    class BotoConfig:  # type: ignore[override]
        """Fallback configuration placeholder when botocore is unavailable."""

        pass

    class BotoCoreError(Exception):
        pass

    class ClientError(Exception):
        pass

from .models import SecurityFinding, Severity


@dataclass
class SecurityHubFindingFilter:
    """Simplified representation of the Security Hub finding filters."""

    severity_labels: Optional[List[str]] = None
    product_name: Optional[str] = None

    def to_boto(self) -> dict:
        filters: dict = {}
        if self.severity_labels:
            filters["SeverityLabel"] = [
                {"Value": label, "Comparison": "EQUALS"}
                for label in self.severity_labels
            ]
        if self.product_name:
            filters["ProductName"] = [
                {"Value": self.product_name, "Comparison": "EQUALS"}
            ]
        return filters


class SecurityHubIngestor:
    """Ingest findings from AWS Security Hub."""

    def __init__(
        self,
        *,
        region_name: str,
        profile_name: Optional[str] = None,
        boto_config: Optional[BotoConfig] = None,
    ) -> None:
        if boto3 is None:  # pragma: no cover - optional dependency
            raise ImportError(
                "boto3 is required to query AWS Security Hub. Install the project "
                "dependencies or run the CLI with --sample-data."
            )

        session_kwargs = {}
        if profile_name:
            session_kwargs["profile_name"] = profile_name
        self._session = boto3.Session(**session_kwargs)  # type: ignore[arg-type]
        self._client = self._session.client(
            "securityhub", region_name=region_name, config=boto_config
        )

    def fetch_findings(
        self, *, filters: Optional[SecurityHubFindingFilter] = None, max_results: int = 1000
    ) -> Iterable[SecurityFinding]:
        """Yield Security Hub findings converted to :class:`SecurityFinding`."""

        params = {"MaxResults": min(max_results, 100)}
        if filters:
            params["Filters"] = filters.to_boto()
        paginator = self._client.get_paginator("get_findings")
        collected = 0
        try:
            for page in paginator.paginate(**params):
                for raw in page.get("Findings", []):
                    yield self._convert_finding(raw)
                    collected += 1
                    if collected >= max_results:
                        return
        except (ClientError, BotoCoreError) as exc:  # pragma: no cover - network
            raise RuntimeError(f"Unable to retrieve Security Hub findings: {exc}") from exc

    @staticmethod
    def _convert_finding(payload: dict) -> SecurityFinding:
        severity_label = payload.get("Severity", {}).get("Label", "INFORMATIONAL")
        resources = payload.get("Resources", [])
        resource_id = resources[0].get("Id") if resources else None
        return SecurityFinding(
            provider="AWS Security Hub",
            id=payload["Id"],
            title=payload.get("Title", "(no title)"),
            severity=Severity.from_string(severity_label),
            description=payload.get("Description"),
            url=payload.get("Remediation", {})
            .get("Recommendation", {})
            .get("Url"),
            resource=resource_id,
            created_at=datetime.fromisoformat(payload["FirstObservedAt"]) if payload.get("FirstObservedAt") else None,
        )
