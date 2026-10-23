import json
from dataclasses import asdict
from pathlib import Path

from vanguard.core.models import AuditReport, Severity


class ReportExporter:
    """Utilitas ekspor laporan hasil audit ke format Markdown (.md) dan JSON (.json)."""

    @staticmethod
    def to_markdown(report: AuditReport, output_path: str = "LAPORAN_AUDIT_VANGUARD.md") -> str:
        path = Path(output_path)
        counts = report.count_by_severity()

        lines = [
            "# 🛡️ Laporan Audit Postur Keamanan (VanguardAudit Enterprise)",
            "",
            "## 1. Ringkasan Eksekutif",
            f"- **Target Pemeriksaan:** `{report.target_url}`",
            f"- **Waktu Pelaksanaan:** {report.timestamp}",
            f"- **Durasi Pemeriksaan:** {report.duration_seconds:.2f} detik",
            f"- **Skor Postur Keamanan:** **{report.score}/100** (Grade: **{report.grade}**)",
            "",
            "### Statistik Temuan Berdasarkan Tingkat Keparahan",
            f"- ✅ **PASS:** {counts[Severity.PASS]} komponen",
            f"- ℹ️ **INFO:** {counts[Severity.INFO]} komponen",
            f"- 🟡 **LOW:** {counts[Severity.LOW]} komponen",
            f"- 🟠 **MEDIUM:** {counts[Severity.MEDIUM]} komponen",
            f"- 🔴 **HIGH:** {counts[Severity.HIGH]} komponen",
            "",
            "---",
            "",
            "## 2. Tabel Detail Pemeriksaan & Panduan Mitigasi",
            "",
            "| Kategori | Komponen | Severity | Status | Analisis Temuan | Rekomendasi Perbaikan (Remediation) | Standar / Referensi |",
            "| :--- | :--- | :---: | :--- | :--- | :--- | :--- |",
        ]

        for f in report.findings:
            lines.append(
                f"| {f.category} | **{f.item}** | `{f.severity.value}` | {f.status} | {f.description} | {f.remediation} | {f.reference} |"
            )

        lines.extend(
            [
                "",
                "---",
                "*Laporan ini dihasilkan secara otomatis oleh **VanguardAudit Enterprise Defensive Inspector**.*",
            ]
        )

        path.write_text("\n".join(lines), encoding="utf-8")
        return str(path.resolve())

    @staticmethod
    def to_json(report: AuditReport, output_path: str = "LAPORAN_AUDIT_VANGUARD.json") -> str:
        path = Path(output_path)
        payload = {
            "target_url": report.target_url,
            "timestamp": report.timestamp,
            "duration_seconds": round(report.duration_seconds, 3),
            "score": report.score,
            "grade": report.grade,
            "summary_counts": {k.value: v for k, v in report.count_by_severity().items()},
            "findings": [asdict(f) for f in report.findings],
        }
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(path.resolve())
