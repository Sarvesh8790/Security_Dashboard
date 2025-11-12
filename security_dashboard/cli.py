"""Command line interface for the security dashboard."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable, List

from .aws_security_hub import SecurityHubFindingFilter, SecurityHubIngestor
from .config import DashboardConfig
from .dashboard import DashboardReport
from .github import GitHubAdvancedSecurityIngestor, GitHubQuery
from .models import SecurityFinding, Severity

SAMPLE_DATA_PATH = Path(__file__).resolve().parent.parent / "examples" / "sample_findings.json"


def load_sample_findings() -> List[SecurityFinding]:
    if not SAMPLE_DATA_PATH.exists():
        raise FileNotFoundError(f"Sample data file not found: {SAMPLE_DATA_PATH}")
    with SAMPLE_DATA_PATH.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return [SecurityFinding.from_dict(item) for item in payload]


def run_from_live_sources(args: argparse.Namespace) -> List[SecurityFinding]:
    config = DashboardConfig.from_env(require_github=args.include_github)
    findings: List[SecurityFinding] = []

    security_hub = SecurityHubIngestor(
        region_name=config.aws.region_name,
        profile_name=args.aws_profile or config.aws.profile_name,
    )
    filters = None
    if args.severity:
        filters = SecurityHubFindingFilter(severity_labels=[args.severity.upper()])
    findings.extend(
        list(security_hub.fetch_findings(filters=filters, max_results=args.max_results))
    )

    if config.github:
        github = GitHubAdvancedSecurityIngestor(
            token=config.github.token, api_url=config.github.api_url
        )
        query = GitHubQuery(
            owner=config.github.owner or args.github_owner,
            repo=config.github.repo or args.github_repo,
            state=args.github_state,
        )
        if not query.owner:
            raise ValueError(
                "GitHub owner must be provided via --github-owner or GITHUB_OWNER env var."
            )
        if args.include_code_scanning:
            findings.extend(list(github.fetch_code_scanning_alerts(query)))
        if args.include_secret_scanning:
            findings.extend(list(github.fetch_secret_scanning_alerts(query)))
        if args.include_dependabot:
            findings.extend(list(github.fetch_dependabot_alerts(query)))
    return findings


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Security Dashboard for AWS and GitHub")
    parser.add_argument(
        "--sample-data",
        action="store_true",
        help="Load findings from the bundled sample JSON file instead of real services.",
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=200,
        help="Maximum number of Security Hub findings to retrieve.",
    )
    parser.add_argument("--aws-profile", help="AWS named profile to use for authentication.")
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
        help="Filter AWS Security Hub findings by severity.",
    )
    parser.add_argument(
        "--include-github",
        dest="include_github",
        action="store_true",
        help="Include GitHub Advanced Security data in the dashboard.",
    )
    parser.add_argument(
        "--include-code-scanning",
        action="store_true",
        help="Pull GitHub Code Scanning alerts.",
    )
    parser.add_argument(
        "--include-secret-scanning",
        action="store_true",
        help="Pull GitHub Secret Scanning alerts.",
    )
    parser.add_argument(
        "--include-dependabot",
        action="store_true",
        help="Pull GitHub Dependabot alerts.",
    )
    parser.add_argument(
        "--github-owner",
        help="GitHub organisation or user that owns the repository or organisation.",
    )
    parser.add_argument("--github-repo", help="Optional GitHub repository name.")
    parser.add_argument(
        "--github-state",
        default="open",
        choices=["open", "fixed", "dismissed"],
        help="State of GitHub alerts to query.",
    )
    parser.add_argument(
        "--output-json",
        action="store_true",
        help="Emit the normalized findings as JSON for downstream processing.",
    )
    return parser


def render_report(findings: Iterable[SecurityFinding], *, output_json: bool = False) -> None:
    if output_json:
        print(json.dumps([finding.short_dict() for finding in findings], indent=2))
        return

    report = DashboardReport(findings)
    rows = report.to_rows()
    if not rows:
        print("No findings retrieved. Check your filters and data sources.")
        return

    headers = ["Provider", "Total"] + [severity.value.title() for severity in Severity]
    column_widths = {header: len(header) for header in headers}
    for row in rows:
        for header in headers:
            column_widths[header] = max(column_widths[header], len(str(row.get(header, 0))))

    def format_row(row_values: Iterable[str]) -> str:
        parts = []
        for header, value in zip(headers, row_values):
            parts.append(str(value).ljust(column_widths[header]))
        return " | ".join(parts)

    print(format_row(headers))
    print("-+-".join("-" * column_widths[header] for header in headers))
    for row in rows:
        ordered_values = [row.get(header, "0") for header in headers]
        print(format_row(ordered_values))


def main(argv: list[str] | None = None) -> None:
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    if args.sample_data:
        findings = load_sample_findings()
    else:
        findings = run_from_live_sources(args)

    render_report(findings, output_json=args.output_json)


if __name__ == "__main__":
    main()
