"""Integration helpers for GitHub Advanced Security (GHAS)."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator, Optional

try:  # pragma: no cover - optional dependency
    import requests
except ImportError:  # pragma: no cover - optional dependency
    requests = None  # type: ignore[assignment]

from .models import SecurityFinding, Severity


@dataclass
class GitHubQuery:
    """Parameters that control how GHAS alerts are queried."""

    owner: str
    repo: Optional[str] = None
    state: str = "open"
    severity: Optional[str] = None


class GitHubAdvancedSecurityIngestor:
    """Ingest Code Scanning, Secret Scanning, and Dependabot alerts from GitHub."""

    def __init__(self, *, token: str, api_url: str = "https://api.github.com") -> None:
        if requests is None:  # pragma: no cover - optional dependency
            raise ImportError(
                "The requests package is required to query GitHub. Install the project "
                "dependencies or run the CLI with --sample-data."
            )
        self._token = token
        self._api_url = api_url.rstrip("/")
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )

    def fetch_code_scanning_alerts(self, query: GitHubQuery) -> Iterable[SecurityFinding]:
        endpoint = self._build_endpoint("code-scanning/alerts", query)
        yield from self._paginate_alerts(endpoint, provider="GitHub Code Scanning")

    def fetch_secret_scanning_alerts(self, query: GitHubQuery) -> Iterable[SecurityFinding]:
        endpoint = self._build_endpoint("secret-scanning/alerts", query)
        yield from self._paginate_alerts(endpoint, provider="GitHub Secret Scanning")

    def fetch_dependabot_alerts(self, query: GitHubQuery) -> Iterable[SecurityFinding]:
        endpoint = self._build_endpoint("dependabot/alerts", query)
        yield from self._paginate_alerts(endpoint, provider="GitHub Dependabot")

    def _build_endpoint(self, resource: str, query: GitHubQuery) -> str:
        if query.repo:
            return f"{self._api_url}/repos/{query.owner}/{query.repo}/{resource}"
        return f"{self._api_url}/orgs/{query.owner}/{resource}"

    def _paginate_alerts(self, endpoint: str, provider: str) -> Iterator[SecurityFinding]:
        url = endpoint
        while url:
            response = self._session.get(url, timeout=30)
            if response.status_code != 200:  # pragma: no cover - network
                raise RuntimeError(
                    f"GitHub API returned {response.status_code}: {response.text}"
                )
            for raw in response.json():
                yield self._convert_alert(raw, provider=provider)
            url = self._extract_next_link(response.headers.get("Link"))

    @staticmethod
    def _convert_alert(payload: dict, *, provider: str) -> SecurityFinding:
        severity = payload.get("rule", {}).get("severity") or payload.get("security_vulnerability", {}).get("severity", "low")
        html_url = payload.get("html_url") or payload.get("url")
        created = payload.get("created_at") or payload.get("created")
        return SecurityFinding(
            provider=provider,
            id=str(payload.get("number") or payload.get("id")),
            title=payload.get("rule", {}).get("description") or payload.get("summary", "(no title)"),
            severity=Severity.from_string(severity),
            description=payload.get("most_recent_instance", {})
            .get("message", {})
            .get("text"),
            url=html_url,
            resource=payload.get("most_recent_instance", {})
            .get("location", {})
            .get("path"),
            created_at=datetime.fromisoformat(created.replace("Z", "+00:00")) if created else None,
        )

    @staticmethod
    def _extract_next_link(link_header: Optional[str]) -> Optional[str]:
        if not link_header:
            return None
        for part in link_header.split(","):
            section = part.split(";")
            if len(section) != 2:
                continue
            url_part, rel_part = section
            if 'rel="next"' in rel_part:
                return url_part.strip()[1:-1]
        return None
