import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from security_dashboard import cli


def test_load_sample_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    sample = tmp_path / "sample.json"
    sample.write_text(
        json.dumps(
            [
                {
                    "provider": "Demo",
                    "id": "1",
                    "title": "Example",
                    "severity": "LOW",
                }
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "SAMPLE_DATA_PATH", sample)

    findings = cli.load_sample_findings()

    assert len(findings) == 1
    assert findings[0].provider == "Demo"


def test_render_report_outputs_table(capsys: pytest.CaptureFixture[str]):
    findings = cli.load_sample_findings()
    cli.render_report(findings)
    output = capsys.readouterr().out
    assert "Provider" in output
    assert "AWS Security Hub" in output
