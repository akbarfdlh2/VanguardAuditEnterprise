import argparse
import asyncio
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table
from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, DataTable, Footer, Header, Input, Static

from vanguard.auditors.base import BaseAuditor
from vanguard.auditors.dns_auditor import DNSAuditor
from vanguard.auditors.endpoint_auditor import EndpointAuditor
from vanguard.auditors.governance_auditor import GovernanceAuditor
from vanguard.auditors.headers_auditor import HeadersAuditor
from vanguard.auditors.ssl_auditor import SSLAuditor
from vanguard.core.config import APP_NAME, APP_VERSION
from vanguard.core.models import AuditFinding, AuditReport, Severity
from vanguard.utils.exporter import ReportExporter


async def execute_all_auditors(target_url: str) -> AuditReport:
    start_time = time.perf_counter()
    report = AuditReport(target_url=target_url)

    auditors: list[BaseAuditor] = [
        SSLAuditor(),
        HeadersAuditor(),
        DNSAuditor(),
        GovernanceAuditor(),
        EndpointAuditor(),
    ]

    results = await asyncio.gather(*(auditor.run(target_url) for auditor in auditors))
    for finding_list in results:
        report.findings.extend(finding_list)

    report.duration_seconds = time.perf_counter() - start_time
    return report


class VanguardAuditApp(App[None]):
    CSS_PATH = Path(__file__).parent / "ui" / "styles.tcss"

    BINDINGS = [
        ("r", "run_audit", "Mulai Audit"),
        ("m", "export_md", "Simpan .MD"),
        ("j", "export_json", "Simpan .JSON"),
        ("c", "clear_results", "Bersihkan"),
        ("q", "quit", "Keluar"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.current_report: AuditReport | None = None
        self.displayed_findings: list[AuditFinding] = []
        self.active_filter: str = "ALL"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Horizontal(id="control-bar"):
            yield Input(
                placeholder="Masukkan URL/Domain milik Anda (contoh: https://example.com)",
                id="url-input",
            )
            yield Button(
                "🔍 Mulai Audit (R)", variant="primary", id="btn-audit", classes="action-btn"
            )
            yield Button("📄 Export .MD (M)", variant="success", id="btn-md", classes="action-btn")
            yield Button(
                "📦 Export .JSON (J)", variant="warning", id="btn-json", classes="action-btn"
            )

        with Horizontal(id="filter-bar"):
            yield Button("Semua Kategori", id="flt-all", variant="primary", classes="filter-btn")
            yield Button("DNS & Email", id="flt-dns", variant="default", classes="filter-btn")
            yield Button("HTTP Headers", id="flt-headers", variant="default", classes="filter-btn")
            yield Button("SSL / TLS", id="flt-ssl", variant="default", classes="filter-btn")
            yield Button("Governance", id="flt-gov", variant="default", classes="filter-btn")
            yield Button(
                "Endpoints & API", id="flt-endpoints", variant="default", classes="filter-btn"
            )

        with Horizontal(id="metrics-row"):
            yield Static(
                "🎯 Target: [dim]Belum dipilih[/]", id="target-card", classes="metric-card"
            )
            yield Static("🛡️ Skor Keamanan: [dim]- / 100[/]", id="score-card", classes="metric-card")
            yield Static(
                "📊 Ringkasan: [dim]Menunggu eksekusi audit[/]",
                id="stats-card",
                classes="metric-card",
            )

        yield DataTable(id="results-table")
        yield Static(
            "💡 [bold cyan]Panduan Interaktif:[/] Masukkan domain Anda di atas lalu tekan Enter. Gunakan tombol filter kategori atau klik baris pada tabel untuk membaca penjelasan teknis, referensi RFC, dan panduan perbaikan lengkap.",
            id="detail-panel",
        )
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"{APP_NAME} v{APP_VERSION} // Defensive Security Posture & DNS/TLS Inspector"
        table = self.query_one("#results-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns(
            "No", "Kategori", "Komponen Pemeriksaan", "Severity", "Status", "Standar/RFC"
        )

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""
        if btn_id == "btn-audit":
            await self.action_run_audit()
        elif btn_id == "btn-md":
            self.action_export_md()
        elif btn_id == "btn-json":
            self.action_export_json()
        elif btn_id.startswith("flt-"):
            filter_map = {
                "flt-all": "ALL",
                "flt-dns": "DNS Security",
                "flt-headers": "HTTP Headers",
                "flt-ssl": "SSL/TLS",
                "flt-gov": "Governance",
                "flt-endpoints": "API & Endpoints",
            }
            self.active_filter = filter_map.get(btn_id, "ALL")
            self._refresh_table_view()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "url-input":
            await self.action_run_audit()

    async def action_run_audit(self) -> None:
        raw_url = self.query_one("#url-input", Input).value.strip()
        detail_panel = self.query_one("#detail-panel", Static)
        table = self.query_one("#results-table", DataTable)

        if not raw_url:
            detail_panel.update(
                "[bold red]⚠️ Mohon masukkan URL atau nama domain terlebih dahulu.[/]"
            )
            return

        if not raw_url.startswith(("http://", "https://")):
            raw_url = f"https://{raw_url}"
            self.query_one("#url-input", Input).value = raw_url

        parsed = urlparse(raw_url)
        if not parsed.netloc:
            detail_panel.update(
                "[bold red]⚠️ Format URL tidak valid! Contoh yang benar: https://domainanda.com[/]"
            )
            return

        table.clear()
        self.query_one("#target-card", Static).update(f"🎯 Target: [bold white]{raw_url}[/]")
        self.query_one("#score-card", Static).update("🛡️ Skor: [bold yellow]⏳ Memindai...[/]")
        detail_panel.update(
            "[bold yellow]⏳ Menjalankan pemeriksaan paralel (SSL/TLS, HTTP Headers, SPF/DMARC/DNSSEC, RFC 9116)...[/]"
        )

        report = await execute_all_auditors(raw_url)
        self.current_report = report
        self.active_filter = "ALL"
        self._update_metrics(report)
        self._refresh_table_view()

    def _update_metrics(self, report: AuditReport) -> None:
        score_card = self.query_one("#score-card", Static)
        stats_card = self.query_one("#stats-card", Static)

        score = report.score
        color = "green" if score >= 80 else ("yellow" if score >= 55 else "red")
        score_card.update(
            f"🛡️ Skor Postur: [bold {color}]{score}/100[/] (Grade: [bold {color}]{report.grade}[/])"
        )

        counts = report.count_by_severity()
        stats_card.update(
            f"📊 [green]PASS:{counts[Severity.PASS]}[/] | "
            f"[red]HIGH:{counts[Severity.HIGH]}[/] | "
            f"[orange3]MED:{counts[Severity.MEDIUM]}[/] | "
            f"[yellow]LOW:{counts[Severity.LOW]}[/] ({report.duration_seconds:.2f}s)"
        )

    def _refresh_table_view(self) -> None:
        if not self.current_report:
            return

        table = self.query_one("#results-table", DataTable)
        detail_panel = self.query_one("#detail-panel", Static)
        table.clear()

        self.displayed_findings = self.current_report.filter_by_category(self.active_filter)

        severity_styles = {
            Severity.PASS: "bold green",
            Severity.INFO: "bold cyan",
            Severity.LOW: "bold yellow",
            Severity.MEDIUM: "bold orange3",
            Severity.HIGH: "bold red",
        }

        for idx, f in enumerate(self.displayed_findings, start=1):
            badge = Text(f" {f.severity.value} ", style=severity_styles[f.severity])
            table.add_row(str(idx), f.category, f.item, badge, f.status, f.reference)

        detail_panel.update(
            f"[bold green]✅ Menampilkan {len(self.displayed_findings)} item pemeriksaan (Filter: {self.active_filter}).[/] "
            "Pilih baris untuk melihat detail analisis dan rekomendasi mitigasi."
        )

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        row_index = event.cursor_row
        if 0 <= row_index < len(self.displayed_findings):
            finding = self.displayed_findings[row_index]
            detail_panel = self.query_one("#detail-panel", Static)
            detail_panel.update(
                f"📌 [bold white]{finding.category} -> {finding.item}[/]  |  "
                f"Status: [bold cyan]{finding.status}[/]  |  Ref: [italic]{finding.reference}[/]\n"
                f"📖 [bold]Analisis:[/] {finding.description}\n"
                f"🛠️ [bold green]Panduan Mitigasi:[/] {finding.remediation}"
            )

    def action_export_md(self) -> None:
        detail_panel = self.query_one("#detail-panel", Static)
        if not self.current_report:
            detail_panel.update("[bold red]⚠️ Belum ada hasil audit untuk diekspor![/]")
            return
        saved_path = ReportExporter.to_markdown(self.current_report)
        detail_panel.update(
            f"[bold green]✅ Laporan Markdown berhasil disimpan di:[/] {saved_path}"
        )

    def action_export_json(self) -> None:
        detail_panel = self.query_one("#detail-panel", Static)
        if not self.current_report:
            detail_panel.update("[bold red]⚠️ Belum ada hasil audit untuk diekspor![/]")
            return
        saved_path = ReportExporter.to_json(self.current_report)
        detail_panel.update(f"[bold green]✅ Laporan JSON berhasil disimpan di:[/] {saved_path}")

    def action_clear_results(self) -> None:
        self.current_report = None
        self.displayed_findings = []
        self.query_one("#results-table", DataTable).clear()
        self.query_one("#target-card", Static).update("🎯 Target: [dim]Belum dipilih[/]")
        self.query_one("#score-card", Static).update("🛡️ Skor Keamanan: [dim]- / 100[/]")
        self.query_one("#stats-card", Static).update(
            "📊 Ringkasan: [dim]Menunggu eksekusi audit[/]"
        )
        self.query_one("#detail-panel", Static).update(
            "Layar telah dibersihkan. Siap untuk audit berikutnya."
        )


def run_headless_cli(url: str, fail_under: int, export_md: bool, export_json: bool) -> int:
    console = Console()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    console.print(f"\n[bold cyan]🛡️ {APP_NAME} v{APP_VERSION} (Headless CI/CD Mode)[/]")
    console.print(f"🎯 Memulai pemeriksaan postur keamanan pada: [bold white]{url}[/] ...\n")

    report = asyncio.run(execute_all_auditors(url))

    rich_table = Table(
        title=f"Hasil Audit: {report.target_url} (Skor: {report.score}/100 | Grade: {report.grade})"
    )
    rich_table.add_column("Kategori", style="cyan")
    rich_table.add_column("Komponen", style="white")
    rich_table.add_column("Severity", justify="center")
    rich_table.add_column("Status")
    rich_table.add_column("Rekomendasi Mitigasi")

    for f in report.findings:
        rich_table.add_row(f.category, f.item, f.severity.value, f.status, f.remediation)

    console.print(rich_table)

    if export_md:
        md_file = ReportExporter.to_markdown(report)
        console.print(f"📄 Laporan Markdown disimpan ke: [bold green]{md_file}[/]")
    if export_json:
        json_file = ReportExporter.to_json(report)
        console.print(f"📦 Laporan JSON disimpan ke: [bold green]{json_file}[/]")

    if report.score < fail_under:
        console.print(
            f"\n[bold red]❌ CI/CD QUALITY GATE GAGAL:[/] Skor postur keamanan ({report.score}) berada di bawah ambang batas minimum ({fail_under})."
        )
        return 1

    console.print(
        f"\n[bold green]✅ CI/CD QUALITY GATE LULUS:[/] Skor postur keamanan ({report.score}) memenuhi ambang batas ({fail_under})."
    )
    return 0


def entrypoint() -> None:
    parser = argparse.ArgumentParser(
        description="VanguardAudit Enterprise - Defensive Web, SSL/TLS & DNS Security Posture Inspector"
    )
    parser.add_argument(
        "--headless", action="store_true", help="Jalankan dalam mode CLI tanpa TUI (untuk CI/CD)"
    )
    parser.add_argument(
        "--url", type=str, default="", help="Target URL atau domain (wajib jika --headless)"
    )
    parser.add_argument(
        "--fail-under",
        type=int,
        default=0,
        help="Gagalkan proses dengan exit code 1 jika skor di bawah nilai ini (contoh: 80)",
    )
    parser.add_argument(
        "--export-md", action="store_true", help="Ekspor laporan otomatis ke file Markdown (.md)"
    )
    parser.add_argument(
        "--export-json", action="store_true", help="Ekspor laporan otomatis ke file JSON (.json)"
    )

    args = parser.parse_args()

    if args.headless:
        if not args.url:
            print(
                "Error: Argumen --url wajib diisi saat menggunakan mode --headless.",
                file=sys.stderr,
            )
            sys.exit(2)
        sys.exit(run_headless_cli(args.url, args.fail_under, args.export_md, args.export_json))
    else:
        app = VanguardAuditApp()
        app.run()


if __name__ == "__main__":
    entrypoint()
