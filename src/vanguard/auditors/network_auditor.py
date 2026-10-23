import asyncio
import socket
from urllib.parse import urlparse

import httpx

from vanguard.auditors.base import BaseAuditor
from vanguard.core.config import DEFAULT_TIMEOUT, USER_AGENT
from vanguard.core.models import AuditFinding, Severity

SENSITIVE_PORTS: tuple[tuple[int, str, Severity, str, str], ...] = (
    (
        21,
        "FTP Service (Port 21)",
        Severity.HIGH,
        "Protokol transfer file tidak terenkripsi (cleartext).",
        "Nonaktifkan FTP atau ganti dengan SFTP/FTPS.",
    ),
    (
        22,
        "SSH Service (Port 22)",
        Severity.LOW,
        "Port administrasi SSH terbuka ke publik.",
        "Batasi akses SSH hanya melalui VPN atau IP whitelist firewall.",
    ),
    (
        23,
        "Telnet Service (Port 23)",
        Severity.HIGH,
        "Protokol remote shell tidak aman tanpa enkripsi.",
        "Matikan layanan Telnet dan ganti dengan SSH terotentikasi.",
    ),
    (
        80,
        "HTTP Cleartext (Port 80)",
        Severity.INFO,
        "Port web standar terbuka.",
        "Pastikan port 80 secara otomatis mengalihkan (HTTP 301) ke HTTPS.",
    ),
    (
        443,
        "HTTPS Transport (Port 443)",
        Severity.PASS,
        "Port web aman terenkripsi TLS.",
        "Port HTTPS aktif dan siap melayani koneksi aman.",
    ),
    (
        3306,
        "MySQL Database (Port 3306)",
        Severity.HIGH,
        "Database MySQL terekspos ke internet publik.",
        "Blokir port database dari akses publik via firewall atau private VPC subnet.",
    ),
    (
        5432,
        "PostgreSQL Database (Port 5432)",
        Severity.HIGH,
        "Database PostgreSQL terekspos ke internet publik.",
        "Blokir port database dari akses publik via firewall atau private VPC subnet.",
    ),
    (
        6379,
        "Redis Datastore (Port 6379)",
        Severity.HIGH,
        "In-memory database Redis terekspos ke publik.",
        "Bind Redis ke localhost (127.0.0.1) dan aktifkan kata sandi kuat.",
    ),
    (
        27017,
        "MongoDB Datastore (Port 27017)",
        Severity.HIGH,
        "Database NoSQL MongoDB terekspos ke internet publik.",
        "Isolasi MongoDB dalam jaringan privat tanpa IP publik.",
    ),
    (
        3389,
        "RDP Remote Desktop (Port 3389)",
        Severity.HIGH,
        "Remote Desktop Protocol Windows terbuka ke internet publik.",
        "Nonaktifkan eksposur RDP langsung ke internet publik dan gunakan VPN.",
    ),
    (
        8080,
        "HTTP Alternate (Port 8080)",
        Severity.INFO,
        "Port web sekunder/proxy terbuka.",
        "Pastikan layanan pada port ini terotentikasi dan aman.",
    ),
    (
        8443,
        "HTTPS Alternate (Port 8443)",
        Severity.INFO,
        "Port SSL web alternatif terbuka.",
        "Pastikan sertifikat dan enkripsi pada port ini terkonfigurasi dengan benar.",
    ),
)


class NetworkAuditor(BaseAuditor):
    @property
    def name(self) -> str:
        return "SecurityScorecard Network Security, Insecure Ports & Patching Cadence Auditor"

    async def run(self, target_url: str) -> list[AuditFinding]:
        findings: list[AuditFinding] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname or target_url

        port_tasks = [
            asyncio.to_thread(self._probe_single_port, hostname, port, label, sev, desc, rem)
            for port, label, sev, desc, rem in SENSITIVE_PORTS
        ]

        async with httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            enforce_task = self._check_https_enforcement(client, hostname)
            all_results = await asyncio.gather(*port_tasks, enforce_task, return_exceptions=True)

        for res in all_results:
            if isinstance(res, list):
                findings.extend(res)
            elif isinstance(res, AuditFinding):
                findings.append(res)

        return findings

    def _probe_single_port(
        self,
        host: str,
        port: int,
        label: str,
        severity: Severity,
        desc: str,
        remediation: str,
    ) -> list[AuditFinding]:
        out: list[AuditFinding] = []
        is_open, banner = self._raw_connect(host, port)

        if is_open:
            if port == 443:
                out.append(
                    AuditFinding(
                        category="Network Security",
                        item=label,
                        severity=Severity.PASS,
                        status="Terbuka (Aman)",
                        description=f"{desc} (Port 443 siap melayani koneksi TLS).",
                        remediation=remediation,
                        reference="SecurityScorecard Network Security",
                    )
                )
            elif port in (80, 8080, 8443):
                out.append(
                    AuditFinding(
                        category="Network Security",
                        item=label,
                        severity=Severity.INFO,
                        status="Port Terbuka",
                        description=f"{desc} Terdeteksi port {port} terbuka.",
                        remediation=remediation,
                        reference="SecurityScorecard Network Security",
                    )
                )
            elif port == 22:
                out.append(
                    AuditFinding(
                        category="Network Security",
                        item=label,
                        severity=Severity.LOW,
                        status="Port Terbuka ke Publik",
                        description="Port SSH 22 dapat diakses dari internet publik.",
                        remediation=remediation,
                        reference="SecurityScorecard Network Security",
                    )
                )
                if banner:
                    out.append(
                        AuditFinding(
                            category="Patching Cadence",
                            item="SSH Service Banner Disclosure (Port 22)",
                            severity=Severity.LOW,
                            status=f"Banner Terpublikasi: {banner[:40]}",
                            description=f"Layanan SSH mempublikasikan versi secara terbuka: '{banner}'. Mengindikasikan celah reconnaissance versi perangkat lunak untuk pencocokan CVE.",
                            remediation="Sembunyikan banner versi SSH atau filter akses port hanya melalui VPN bastion host.",
                            reference="SecurityScorecard Patching Cadence (CVSS v3.0 Service Vulnerability)",
                        )
                    )
            else:
                out.append(
                    AuditFinding(
                        category="Network Security",
                        item=label,
                        severity=severity,
                        status="Port Sensitif Terekspos",
                        description=f"PERINGATAN: {desc} Port {port} dapat diakses secara publik.",
                        remediation=remediation,
                        reference="SecurityScorecard Network Security (Insecure Open Ports)",
                    )
                )
        else:
            if severity == Severity.HIGH:
                out.append(
                    AuditFinding(
                        category="Network Security",
                        item=label,
                        severity=Severity.PASS,
                        status="Tertutup / Aman",
                        description=f"Port {port} tidak terbuka ke internet publik.",
                        remediation="Konfigurasi firewall sudah tepat.",
                        reference="SecurityScorecard Network Security",
                    )
                )

        return out

    def _raw_connect(self, host: str, port: int, timeout: float = 1.0) -> tuple[bool, str]:
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                banner = ""
                if port == 22:
                    sock.settimeout(1.0)
                    try:
                        raw = sock.recv(256)
                        banner = raw.decode("utf-8", errors="ignore").strip()
                    except Exception:
                        banner = ""
                return True, banner
        except (TimeoutError, OSError):
            return False, ""

    async def _check_https_enforcement(
        self, client: httpx.AsyncClient, hostname: str
    ) -> AuditFinding:
        try:
            resp = await client.get(f"http://{hostname}/", follow_redirects=False)
            status_code = resp.status_code
            loc = resp.headers.get("location", "")
            if status_code in (301, 302, 307, 308) and loc.startswith("https://"):
                return AuditFinding(
                    category="Application Security",
                    item="Site Enforces HTTPS",
                    severity=Severity.PASS,
                    status=f"Terenkripsi Paksa (HTTP {status_code})",
                    description=f"Permintaan HTTP port 80 otomatis dialihkan ke HTTPS: {loc}.",
                    remediation="Konfigurasi pengalihan HTTPS sudah aktif.",
                    reference="SecurityScorecard Application Security (Site does not enforce HTTPS)",
                )
            return AuditFinding(
                category="Application Security",
                item="Site Enforces HTTPS",
                severity=Severity.HIGH,
                status=f"Tidak Memaksa HTTPS (HTTP {status_code})",
                description="Situs menerima koneksi HTTP tanpa enkripsi atau tidak mengalihkan secara permanen ke HTTPS.",
                remediation="Konfigurasikan web server untuk mengalihkan seluruh lalu lintas HTTP port 80 ke HTTPS (HTTP 301 Redirect).",
                reference="SecurityScorecard Application Security (Site does not enforce HTTPS)",
            )
        except Exception:
            return AuditFinding(
                category="Application Security",
                item="Site Enforces HTTPS",
                severity=Severity.PASS,
                status="Port 80 Tidak Merespon",
                description="Layanan HTTP tidak terenkripsi tidak merespon pada port 80.",
                remediation="Tidak diperlukan tindakan.",
                reference="SecurityScorecard Application Security",
            )
