import json
from pathlib import Path

from vanguard.core.models import AuditFinding, AuditReport, Severity
from vanguard.utils.exporter import ReportExporter


def test_exporter_markdown_and_json(tmp_path: Path) -> None:
    report = AuditReport(
        target_url="https://example.com",
        duration_seconds=1.234,
        findings=[
            AuditFinding(
                category="Security",
                item="Test Header",
                severity=Severity.PASS,
                status="OK",
                description="All good",
                remediation="None",
                reference="RFC 1234",
            ),
            AuditFinding(
                category="DNS",
                item="SPF",
                severity=Severity.HIGH,
                status="Missing",
                description="No SPF",
                remediation="Add SPF",
            ),
        ],
    )

    md_file = tmp_path / "test_report.md"
    json_file = tmp_path / "test_report.json"

    res_md = ReportExporter.to_markdown(report, str(md_file))
    assert Path(res_md).exists()
    content_md = md_file.read_text(encoding="utf-8")
    assert "🛡️ Laporan Audit Postur Keamanan" in content_md
    assert "https://example.com" in content_md
    assert "Test Header" in content_md

    res_json = ReportExporter.to_json(report, str(json_file))
    assert Path(res_json).exists()
    content_json = json.loads(json_file.read_text(encoding="utf-8"))
    assert content_json["target_url"] == "https://example.com"
    assert content_json["score"] == 84
    assert len(content_json["findings"]) == 2
