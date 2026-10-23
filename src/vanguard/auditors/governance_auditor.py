from urllib.parse import urljoin

import httpx

from vanguard.auditors.base import BaseAuditor
from vanguard.core.config import DEFAULT_TIMEOUT, USER_AGENT
from vanguard.core.models import AuditFinding, Severity


class GovernanceAuditor(BaseAuditor):
    @property
    def name(self) -> str:
        return "RFC 9116 (security.txt) & Security Governance Auditor"

    async def run(self, target_url: str) -> list[AuditFinding]:
        findings: list[AuditFinding] = []
        sec_txt_url = urljoin(target_url.rstrip("/") + "/", ".well-known/security.txt")

        try:
            async with httpx.AsyncClient(
                timeout=DEFAULT_TIMEOUT,
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            ) as client:
                resp = await client.get(sec_txt_url)
                content_type = resp.headers.get("Content-Type", "").lower()
                body = resp.text

                if (
                    resp.status_code == 200
                    and "text/plain" in content_type
                    and "contact:" in body.lower()
                ):
                    has_expires = "expires:" in body.lower()
                    findings.append(
                        AuditFinding(
                            category="Governance",
                            item="RFC 9116 (/.well-known/security.txt)",
                            severity=Severity.PASS if has_expires else Severity.LOW,
                            status="Tersedia" if has_expires else "Tanpa Field 'Expires:'",
                            description=f"Kebijakan pengungkapan kerentanan ditemukan di {sec_txt_url}.",
                            remediation=(
                                "Sudah mematuhi standar RFC 9116."
                                if has_expires
                                else "Tambahkan field wajib 'Expires:' berformat ISO-8601 sesuai RFC 9116 Section 2.5.5."
                            ),
                            reference="RFC 9116",
                        )
                    )
                else:
                    findings.append(
                        AuditFinding(
                            category="Governance",
                            item="RFC 9116 (/.well-known/security.txt)",
                            severity=Severity.LOW,
                            status="Tidak Ditemukan",
                            description="File /.well-known/security.txt belum tersedia untuk memfasilitasi pelaporan celah keamanan.",
                            remediation="Buat file '/.well-known/security.txt' berisi atribut 'Contact: mailto:security@...' dan 'Expires: ...'.",
                            reference="RFC 9116",
                        )
                    )
        except Exception:
            findings.append(
                AuditFinding(
                    category="Governance",
                    item="RFC 9116 (/.well-known/security.txt)",
                    severity=Severity.INFO,
                    status="Tidak Dapat Diakses",
                    description="Gagal memeriksa ketersediaan /.well-known/security.txt.",
                    remediation="Sediakan /.well-known/security.txt sesuai standar RFC 9116.",
                    reference="RFC 9116",
                )
            )

        return findings
