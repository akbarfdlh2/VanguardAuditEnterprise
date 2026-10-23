import asyncio
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from vanguard.auditors.base import BaseAuditor
from vanguard.core.models import AuditFinding, Severity


class SSLAuditor(BaseAuditor):
    @property
    def name(self) -> str:
        return "SSL/TLS Certificate, Cipher Suite & Protocol Inspector"

    async def run(self, target_url: str) -> list[AuditFinding]:
        return await asyncio.to_thread(self._sync_inspect_ssl, target_url)

    def _sync_inspect_ssl(self, target_url: str) -> list[AuditFinding]:
        findings: list[AuditFinding] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https" or not hostname:
            findings.append(
                AuditFinding(
                    category="SSL/TLS",
                    item="Enkripsi Transport (HTTPS)",
                    severity=Severity.HIGH,
                    status="Tidak Aktif (HTTP)",
                    description="Target diakses menggunakan protokol HTTP tanpa enkripsi TLS.",
                    remediation="Pasang sertifikat TLS valid dan aktifkan pengalihan otomatis (HTTP 301 Redirect) ke HTTPS.",
                    reference="RFC 8446 / OWASP TLS",
                )
            )
            return findings

        try:
            context = ssl.create_default_context()
            with (
                socket.create_connection((hostname, port), timeout=6.0) as sock,
                context.wrap_socket(sock, server_hostname=hostname) as ssock,
            ):
                cert = ssock.getpeercert()
                tls_version = ssock.version() or "Unknown"
                cipher_info = ssock.cipher()

                # 1. Validasi Versi Protokol TLS
                modern_tls = tls_version in ("TLSv1.2", "TLSv1.3")
                findings.append(
                    AuditFinding(
                        category="SSL/TLS",
                        item="Versi Protokol TLS",
                        severity=Severity.PASS if modern_tls else Severity.HIGH,
                        status=tls_version,
                        description=f"Sesi terenkripsi dinegosiasikan menggunakan protokol {tls_version}.",
                        remediation=(
                            "Protokol enkripsi sudah modern."
                            if modern_tls
                            else "Nonaktifkan SSLv3, TLSv1.0, dan TLSv1.1; hanya izinkan TLSv1.2 dan TLSv1.3."
                        ),
                        reference="RFC 8996 (Deprecating TLS 1.0/1.1)",
                    )
                )

                # 2. Validasi Kekuatan Cipher Suite
                if cipher_info:
                    cipher_name, _, secret_bits = cipher_info
                    bits = secret_bits or 0
                    has_pfs = (
                        "ECDHE" in cipher_name or "DHE" in cipher_name or tls_version == "TLSv1.3"
                    )
                    findings.append(
                        AuditFinding(
                            category="SSL/TLS",
                            item="Cipher Suite & Forward Secrecy",
                            severity=Severity.PASS
                            if (bits >= 128 and has_pfs)
                            else Severity.MEDIUM,
                            status=f"{cipher_name} ({bits}-bit)",
                            description=f"Algoritma sesi: {cipher_name} | Perfect Forward Secrecy (PFS): {'Ya' if has_pfs else 'Tidak'}",
                            remediation=(
                                "Cipher suite kuat dan mendukung Forward Secrecy."
                                if (bits >= 128 and has_pfs)
                                else "Utamakan cipher suite ECDHE dengan AES-GCM atau ChaCha20-Poly1305."
                            ),
                            reference="Mozilla Server Side TLS Guidelines",
                        )
                    )

                # 3. Validasi Masa Berlaku Sertifikat
                if cert and "notAfter" in cert:
                    not_after_str = str(cert["notAfter"])
                    exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=timezone.utc
                    )
                    days_remaining = (exp_date - datetime.now(timezone.utc)).days

                    if days_remaining > 30:
                        sev = Severity.PASS
                    elif days_remaining > 14:
                        sev = Severity.LOW
                    elif days_remaining > 0:
                        sev = Severity.MEDIUM
                    else:
                        sev = Severity.HIGH

                    findings.append(
                        AuditFinding(
                            category="SSL/TLS",
                            item="Masa Aktif Sertifikat",
                            severity=sev,
                            status=f"Sisa {days_remaining} hari",
                            description=f"Sertifikat berlaku hingga {exp_date.strftime('%Y-%m-%d %H:%M UTC')}.",
                            remediation=(
                                "Masa aktif sertifikat masih aman."
                                if days_remaining > 30
                                else "Segera perbarui sertifikat SSL/TLS dan pastikan daemon auto-renewal (misal Certbot/ACME) berjalan."
                            ),
                            reference="RFC 5280",
                        )
                    )

        except ssl.SSLCertVerificationError as exc:
            findings.append(
                AuditFinding(
                    category="SSL/TLS",
                    item="Verifikasi Rantai Sertifikat CA",
                    severity=Severity.HIGH,
                    status="Tidak Valid / Untrusted",
                    description=f"Verifikasi sertifikat gagal: {exc.verify_message}",
                    remediation="Pastikan sertifikat diterbitkan oleh CA tepercaya, menyertakan fullchain, dan sesuai dengan hostname.",
                    reference="RFC 5280",
                )
            )
        except Exception as exc:
            findings.append(
                AuditFinding(
                    category="SSL/TLS",
                    item="Jabat Tangan TLS (Port 443)",
                    severity=Severity.MEDIUM,
                    status="Gagal Memeriksa",
                    description=f"Tidak dapat melakukan koneksi TLS: {exc}",
                    remediation="Pastikan port HTTPS terbuka dan konfigurasi TLS pada reverse proxy sudah benar.",
                    reference="RFC 8446",
                )
            )

        return findings
