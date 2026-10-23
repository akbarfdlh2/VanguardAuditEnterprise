import httpx

from vanguard.auditors.base import BaseAuditor
from vanguard.core.config import DEFAULT_TIMEOUT, REQUIRED_SECURITY_HEADERS, USER_AGENT
from vanguard.core.models import AuditFinding, Severity


class HeadersAuditor(BaseAuditor):
    @property
    def name(self) -> str:
        return "HTTP Security Headers, CORS & Cookie Hardening Auditor"

    async def run(self, target_url: str) -> list[AuditFinding]:
        findings: list[AuditFinding] = []

        try:
            async with httpx.AsyncClient(
                timeout=DEFAULT_TIMEOUT,
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            ) as client:
                response = await client.get(target_url)
                headers = response.headers

                for h_name, (sev, desc, rem, ref) in REQUIRED_SECURITY_HEADERS.items():
                    if h_name in headers:
                        val = headers[h_name]
                        short_val = val if len(val) <= 55 else f"{val[:52]}..."

                        if h_name == "Content-Security-Policy" and (
                            "'unsafe-inline'" in val.lower() or "'unsafe-eval'" in val.lower()
                        ):
                            findings.append(
                                AuditFinding(
                                    category="HTTP Headers",
                                    item=f"{h_name} (Directive Quality)",
                                    severity=Severity.LOW,
                                    status="Aktif (Mengandung unsafe-*)",
                                    description=f"CSP ditemukan tetapi mengizinkan 'unsafe-inline' atau 'unsafe-eval': {short_val}",
                                    remediation="Gunakan mekanisme cryptographic nonce ('nonce-...') atau hash ('sha256-...') sebagai pengganti 'unsafe-inline'.",
                                    reference=ref,
                                )
                            )
                        elif h_name == "Strict-Transport-Security" and (
                            "includesubdomains" not in val.lower() or "max-age" not in val.lower()
                        ):
                            findings.append(
                                AuditFinding(
                                    category="HTTP Headers",
                                    item=h_name,
                                    severity=Severity.LOW,
                                    status="HSTS Belum Memenuhi Best Practice",
                                    description=f"HSTS aktif ({short_val}), namun SecurityScorecard mewajibkan includeSubDomains dan max-age >= 31536000.",
                                    remediation="Tambahkan header: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
                                    reference="SecurityScorecard Application Security (HSTS Best Practices)",
                                )
                            )
                        elif (
                            h_name == "X-Content-Type-Options" and val.strip().lower() != "nosniff"
                        ):
                            findings.append(
                                AuditFinding(
                                    category="HTTP Headers",
                                    item=h_name,
                                    severity=Severity.MEDIUM,
                                    status=f"Nilai Tidak Sesuai ({short_val})",
                                    description="Header X-Content-Type-Options harus bernilai 'nosniff'.",
                                    remediation="Tambahkan header: 'X-Content-Type-Options: nosniff'",
                                    reference="SecurityScorecard Application Security (X-Content-Type-Options Best Practices)",
                                )
                            )
                        else:
                            findings.append(
                                AuditFinding(
                                    category="HTTP Headers",
                                    item=h_name,
                                    severity=Severity.PASS,
                                    status="Terkonfigurasi",
                                    description=f"Nilai header aktif: {short_val}",
                                    remediation="Konfigurasi sudah sesuai standar.",
                                    reference=ref,
                                )
                            )
                    else:
                        findings.append(
                            AuditFinding(
                                category="HTTP Headers",
                                item=h_name,
                                severity=sev,
                                status="Tidak Ditemukan",
                                description=desc,
                                remediation=rem,
                                reference=ref,
                            )
                        )

                acao = headers.get("Access-Control-Allow-Origin")
                acac = headers.get("Access-Control-Allow-Credentials", "").lower()
                if acao == "*":
                    sev = Severity.HIGH if acac == "true" else Severity.LOW
                    findings.append(
                        AuditFinding(
                            category="CORS Policy",
                            item="Access-Control-Allow-Origin",
                            severity=sev,
                            status="Wildcard (*)",
                            description="Kebijakan CORS mengizinkan akses lintas domain secara terbuka (*).",
                            remediation="Jika endpoint menyajikan data terautentikasi, batasi origin secara spesifik ke daftar domain tepercaya.",
                            reference="Fetch Standard / OWASP CORS",
                        )
                    )
                else:
                    findings.append(
                        AuditFinding(
                            category="CORS Policy",
                            item="Access-Control-Allow-Origin",
                            severity=Severity.PASS,
                            status=acao if acao else "Restriktif (Same-Origin)",
                            description="Kebijakan CORS tidak menggunakan wildcard terbuka.",
                            remediation="Tidak diperlukan tindakan.",
                            reference="Fetch Standard",
                        )
                    )

                for leak_hdr in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]:
                    if leak_hdr in headers:
                        val = headers[leak_hdr]
                        has_version_digits = any(c.isdigit() for c in val)
                        findings.append(
                            AuditFinding(
                                category="Info Exposure",
                                item=f"Header {leak_hdr}",
                                severity=Severity.LOW if has_version_digits else Severity.INFO,
                                status=f"Terekspos ({val[:35]})",
                                description="Respons HTTP menyertakan identitas web server atau nomor versi framework.",
                                remediation=f"Sembunyikan versi server (misal di Nginx: 'server_tokens off;' atau hapus header {leak_hdr}).",
                                reference="OWASP WSTG-INFO-02",
                            )
                        )

                raw_cookies = headers.get_list("set-cookie")
                for idx, cookie_str in enumerate(raw_cookies, start=1):
                    c_lower = cookie_str.lower()
                    cookie_name = cookie_str.split("=", 1)[0].strip()
                    missing: list[str] = []
                    if "secure" not in c_lower:
                        missing.append("Secure")
                    if "httponly" not in c_lower:
                        missing.append("HttpOnly")
                    if "samesite" not in c_lower:
                        missing.append("SameSite")

                    if missing:
                        findings.append(
                            AuditFinding(
                                category="Cookie Security",
                                item=f"Cookie '{cookie_name}' (#{idx})",
                                severity=Severity.MEDIUM,
                                status=f"Atribut Kurang ({', '.join(missing)})",
                                description="Cookie diatur tanpa atribut keamanan lengkap untuk mencegah pencurian sesi atau CSRF.",
                                remediation="Sertakan flag 'Secure; HttpOnly; SameSite=Lax' (atau Strict) saat mengirim Set-Cookie.",
                                reference="RFC 6265bis",
                            )
                        )
                    else:
                        findings.append(
                            AuditFinding(
                                category="Cookie Security",
                                item=f"Cookie '{cookie_name}' (#{idx})",
                                severity=Severity.PASS,
                                status="Terlindungi Lengkap",
                                description="Cookie memiliki atribut Secure, HttpOnly, dan SameSite.",
                                remediation="Tidak diperlukan tindakan.",
                                reference="RFC 6265bis",
                            )
                        )

        except httpx.RequestError as exc:
            findings.append(
                AuditFinding(
                    category="HTTP Headers",
                    item="Koneksi HTTP/HTTPS",
                    severity=Severity.HIGH,
                    status="Gagal Terhubung",
                    description=f"Tidak dapat menghubungi server target: {exc}",
                    remediation="Pastikan layanan web aktif, DNS dapat diresolusi, dan firewall mengizinkan koneksi.",
                    reference="Network Connectivity",
                )
            )

        return findings
