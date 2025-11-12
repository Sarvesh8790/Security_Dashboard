from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from security_dashboard.dashboard import DashboardReport
from security_dashboard.models import SecurityFinding, Severity


def build_finding(provider: str, severity: Severity) -> SecurityFinding:
    return SecurityFinding(provider=provider, id=f"{provider}-{severity.value}", title="", severity=severity)


def test_dashboard_report_aggregates_by_provider_and_severity():
    findings = [
        build_finding("AWS Security Hub", Severity.CRITICAL),
        build_finding("AWS Security Hub", Severity.CRITICAL),
        build_finding("AWS Security Hub", Severity.LOW),
        build_finding("GitHub", Severity.HIGH),
    ]

    report = DashboardReport(findings)

    assert report.total_findings == 4
    assert report.findings_by_provider == {"AWS Security Hub": 3, "GitHub": 1}
    assert report.findings_by_severity[Severity.CRITICAL] == 2

    rows = report.to_rows()
    assert rows[0]["Provider"] == "AWS Security Hub"
    assert rows[0]["Critical"] == 2
    assert rows[0]["Low"] == 1
