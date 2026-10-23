import asyncio
from urllib.parse import urljoin

import httpx

from vanguard.auditors.base import BaseAuditor
from vanguard.core.config import DEFAULT_TIMEOUT, USER_AGENT
from vanguard.core.models import AuditFinding, Severity

SENSITIVE_TARGETS: tuple[tuple[str, str, Severity, str], ...] = (
    (
        "/.env",
        "Environment Secret File (/.env)",
        Severity.HIGH,
        "OWASP A05:2021 Security Misconfiguration",
    ),
    (
        "/.git/HEAD",
        "Git Repository Metadata (/.git/HEAD)",
        Severity.HIGH,
        "OWASP A05:2021 Security Misconfiguration",
    ),
    (
        "/swagger-ui.html",
        "API Documentation (Swagger UI)",
        Severity.MEDIUM,
        "OWASP API3:2023 Broken Object Property Level Authorization",
    ),
    (
        "/openapi.json",
        "OpenAPI Specification (/openapi.json)",
        Severity.MEDIUM,
        "OWASP API8:2023 Security Misconfiguration",
    ),
    (
        "/actuator/env",
        "Spring Actuator Environment (/actuator/env)",
        Severity.HIGH,
        "OWASP A05:2021 Security Misconfiguration",
    ),
    (
        "/actuator/health",
        "Spring Actuator Health (/actuator/health)",
        Severity.LOW,
        "OWASP A05:2021 Security Misconfiguration",
    ),
    (
        "/debug/vars",
        "Go Expvar Debug Variables (/debug/vars)",
        Severity.HIGH,
        "OWASP A05:2021 Security Misconfiguration",
    ),
    (
        "/server-status",
        "Web Server Status (/server-status)",
        Severity.MEDIUM,
        "OWASP A05:2021 Security Misconfiguration",
    ),
)


class EndpointAuditor(BaseAuditor):
    @property
    def name(self) -> str:
        return "Unauthenticated Endpoints & Sensitive Path Exposure Auditor"

    async def run(self, target_url: str) -> list[AuditFinding]:
        findings: list[AuditFinding] = []
        base = target_url.rstrip("/") + "/"

        async with httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            tasks = [
                self._check_endpoint(client, base, path, item, sev, ref)
                for path, item, sev, ref in SENSITIVE_TARGETS
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, AuditFinding):
                    findings.append(res)

        return findings

    async def _check_endpoint(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        path: str,
        item_name: str,
        severity: Severity,
        reference: str,
    ) -> AuditFinding:
        target_endpoint = urljoin(base_url, path.lstrip("/"))
        try:
            resp = await client.get(target_endpoint)
            status_code = resp.status_code

            if status_code == 200:
                body_sample = resp.text[:120].strip().replace("\n", " ")
                return AuditFinding(
                    category="API & Endpoints",
                    item=item_name,
                    severity=severity,
                    status=f"Terekspos Tanpa Auth (HTTP {status_code})",
                    description=f"Endpoint dapat diakses publik tanpa kredensial/token: {target_endpoint} (Preview: {body_sample[:60]}...)",
                    remediation="Terapkan middleware autentikasi (401/403) atau blokir akses path ini pada konfigurasi web server/reverse proxy.",
                    reference=reference,
                )
            if status_code in (401, 403):
                return AuditFinding(
                    category="API & Endpoints",
                    item=item_name,
                    severity=Severity.PASS,
                    status=f"Terproteksi Auth (HTTP {status_code})",
                    description=f"Endpoint meminta otentikasi/otorisasi yang valid: {target_endpoint}.",
                    remediation="Konfigurasi otentikasi sudah aktif.",
                    reference=reference,
                )
            return AuditFinding(
                category="API & Endpoints",
                item=item_name,
                severity=Severity.PASS,
                status=f"Tidak Ditemukan (HTTP {status_code})",
                description=f"Endpoint tidak aktif atau mengembalikan status bukan 200 ({status_code}).",
                remediation="Tidak diperlukan tindakan.",
                reference=reference,
            )
        except Exception:
            return AuditFinding(
                category="API & Endpoints",
                item=item_name,
                severity=Severity.PASS,
                status="Tidak Dapat Diakses",
                description=f"Permintaan ke {target_endpoint} gagal atau terblokir.",
                remediation="Tidak diperlukan tindakan.",
                reference=reference,
            )
