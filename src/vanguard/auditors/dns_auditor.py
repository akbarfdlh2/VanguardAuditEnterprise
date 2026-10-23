import asyncio
import re
from urllib.parse import urlparse

import dns.exception
import dns.resolver

from vanguard.auditors.base import BaseAuditor
from vanguard.core.config import COMMON_DKIM_SELECTORS, DEFAULT_TIMEOUT
from vanguard.core.models import AuditFinding, Severity

MULTI_PART_TLDS: frozenset[str] = frozenset(
    {
        "co.id",
        "ac.id",
        "go.id",
        "or.id",
        "sch.id",
        "co.uk",
        "org.uk",
        "com.au",
        "com.sg",
    }
)


class DNSAuditor(BaseAuditor):
    @property
    def name(self) -> str:
        return "Enterprise DNS & Email Security Auditor (SPF, DMARC, DKIM, MTA-STS, CAA, DNSSEC)"

    async def run(self, target_url: str) -> list[AuditFinding]:
        return await asyncio.to_thread(self._sync_audit_dns, target_url)

    @staticmethod
    def _extract_base_domain(hostname: str) -> str:
        parts = hostname.lower().strip(".").split(".")
        if len(parts) <= 2:
            return hostname
        last_two = ".".join(parts[-2:])
        if last_two in MULTI_PART_TLDS and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    @staticmethod
    def _parse_dmarc_tags(dmarc_raw: str) -> dict[str, str]:
        tags: dict[str, str] = {}
        for part in dmarc_raw.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()
        return tags

    @staticmethod
    def _count_spf_lookups(spf_raw: str) -> int:
        tokens = spf_raw.lower().split()
        lookup_count = 0
        for token in tokens[1:]:
            clean_token = token.lstrip("+-~?")
            if clean_token in ("a", "mx", "ptr") or clean_token.startswith(
                ("include:", "a:", "a/", "mx:", "mx/", "ptr:", "exists:", "redirect=")
            ):
                lookup_count += 1
        return lookup_count

    def _sync_audit_dns(self, target_url: str) -> list[AuditFinding]:
        findings: list[AuditFinding] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname

        if not hostname or hostname in ("localhost", "127.0.0.1", "::1"):
            findings.append(
                AuditFinding(
                    category="DNS Security",
                    item="Target DNS Resolution",
                    severity=Severity.INFO,
                    status="Dilewati (Localhost)",
                    description="Target adalah alamat loopback lokal sehingga pemeriksaan DNS publik dilewati.",
                    remediation="Gunakan nama domain publik untuk mengaudit postur SPF, DMARC, CAA, dan DNSSEC.",
                    reference="RFC 1035",
                )
            )
            return findings

        base_domain = self._extract_base_domain(hostname)
        resolver = dns.resolver.Resolver()
        resolver.lifetime = DEFAULT_TIMEOUT
        resolver.timeout = 4.0

        findings.extend(self._check_mx_records(resolver, base_domain))
        findings.extend(self._check_spf_record(resolver, base_domain))
        findings.extend(self._check_dmarc_record(resolver, base_domain))
        findings.extend(self._check_dkim_selectors(resolver, base_domain))
        findings.extend(self._check_mta_sts_and_tlsrpt(resolver, base_domain))
        findings.extend(self._check_caa_records(resolver, base_domain))
        findings.extend(self._check_dnssec(resolver, base_domain))

        return findings

    def _check_mx_records(self, resolver: dns.resolver.Resolver, domain: str) -> list[AuditFinding]:
        try:
            answers = resolver.resolve(domain, "MX")
            mx_servers = [str(r.exchange).rstrip(".") for r in answers]
            if len(mx_servers) == 1 and mx_servers[0] == "":
                return [
                    AuditFinding(
                        category="DNS Security",
                        item="MX Record (Null MX)",
                        severity=Severity.PASS,
                        status="Null MX (RFC 7505)",
                        description=f"Domain {domain} secara eksplisit mendeklarasikan tidak menerima email (0 .).",
                        remediation="Konfigurasi sudah sesuai dengan RFC 7505 untuk domain tanpa layanan email.",
                        reference="RFC 7505",
                    )
                ]
            return [
                AuditFinding(
                    category="DNS Security",
                    item="MX Record (Mail Server)",
                    severity=Severity.INFO,
                    status=f"{len(mx_servers)} Server Ditemukan",
                    description=f"Server MX aktif untuk {domain}: {', '.join(mx_servers[:3])}",
                    remediation="Pastikan seluruh server MX mendukung STARTTLS dan dilindungi oleh SPF/DMARC.",
                    reference="RFC 5321",
                )
            ]
        except Exception:
            return [
                AuditFinding(
                    category="DNS Security",
                    item="MX Record (Mail Server)",
                    severity=Severity.INFO,
                    status="Tidak Ada MX",
                    description=f"Tidak ditemukan MX record pada {domain}. Meskipun tidak menerima email, domain tetap wajib memiliki SPF 'v=spf1 -all' agar tidak dipalsukan.",
                    remediation="Tambahkan Null MX ('0 .') sesuai RFC 7505 serta TXT SPF 'v=spf1 -all'.",
                    reference="RFC 7505",
                )
            ]

    def _check_spf_record(self, resolver: dns.resolver.Resolver, domain: str) -> list[AuditFinding]:
        results: list[AuditFinding] = []
        spf_records: list[str] = []

        try:
            txt_answers = resolver.resolve(domain, "TXT")
            for rdata in txt_answers:
                txt_str = "".join(s.decode("utf-8", errors="ignore") for s in rdata.strings).strip()
                if txt_str.lower().startswith("v=spf1"):
                    spf_records.append(txt_str)
        except Exception:
            pass

        if not spf_records:
            results.append(
                AuditFinding(
                    category="DNS Security",
                    item="SPF Record (Existence)",
                    severity=Severity.HIGH,
                    status="Tidak Ditemukan",
                    description=f"Domain {domain} tidak memiliki catatan TXT SPF (v=spf1), sehingga rentan terhadap Email Spoofing.",
                    remediation="Tambahkan TXT record pada root domain: 'v=spf1 include:_spf.penyediaemail.com -all' (atau 'v=spf1 -all' jika tidak mengirim email).",
                    reference="RFC 7208",
                )
            )
            return results

        if len(spf_records) > 1:
            results.append(
                AuditFinding(
                    category="DNS Security",
                    item="SPF Multiple Records Check",
                    severity=Severity.HIGH,
                    status=f"Konflik ({len(spf_records)} SPF Records)",
                    description="Ditemukan lebih dari satu TXT record v=spf1. Sesuai RFC 7208 Section 3.2, hal ini menyebabkan hasil evaluasi PermError.",
                    remediation="Gabungkan seluruh aturan pengiriman email ke dalam SATU baris TXT record v=spf1 saja.",
                    reference="RFC 7208 Section 3.2",
                )
            )

        primary_spf = spf_records[0]
        lookup_count = self._count_spf_lookups(primary_spf)

        if "+all" in primary_spf.lower():
            pol_sev = Severity.HIGH
            pol_status = "Berbahaya (+all)"
            pol_desc = "Aturan SPF diakhiri dengan '+all' yang mengizinkan SEMUA IP di dunia mengirim email atas nama domain Anda!"
            pol_rem = "Segera ganti '+all' menjadi '-all' (HardFail) atau '~all' (SoftFail)."
        elif "?all" in primary_spf.lower():
            pol_sev = Severity.MEDIUM
            pol_status = "Netral (?all)"
            pol_desc = "Aturan SPF menggunakan '?all' (Neutral) yang tidak memberikan perlindungan terhadap pemalsuan email."
            pol_rem = "Perketat akhiran SPF menjadi '~all' (SoftFail) atau '-all' (HardFail)."
        elif "-all" in primary_spf.lower():
            pol_sev = Severity.PASS
            pol_status = "Ketat (-all HardFail)"
            pol_desc = f"SPF aktif dengan kebijakan HardFail (-all). Isi: {primary_spf[:60]}"
            pol_rem = "Kebijakan akhiran SPF sudah optimal."
        elif "~all" in primary_spf.lower():
            pol_sev = Severity.PASS
            pol_status = "Aman (~all SoftFail)"
            pol_desc = f"SPF aktif dengan kebijakan SoftFail (~all). Isi: {primary_spf[:60]}"
            pol_rem = "Sudah baik bila dikombinasikan dengan DMARC. Pertimbangkan '-all' jika seluruh pengirim sudah terpetakan."
        elif "redirect=" in primary_spf.lower():
            pol_sev = Severity.PASS
            pol_status = "Redirect Policy"
            pol_desc = (
                f"SPF mendelegasikan kebijakan melalui mekanisme redirect: {primary_spf[:60]}"
            )
            pol_rem = "Pastikan domain tujuan redirect memiliki akhiran '-all' atau '~all'."
        else:
            pol_sev = Severity.MEDIUM
            pol_status = "Tanpa Akhiran 'all'"
            pol_desc = "Record SPF tidak memiliki mekanisme penutup eksplisit (-all atau ~all)."
            pol_rem = "Tambahkan '-all' atau '~all' di bagian paling akhir string SPF."

        results.append(
            AuditFinding(
                category="DNS Security",
                item="SPF Enforcement Policy",
                severity=pol_sev,
                status=pol_status,
                description=pol_desc,
                remediation=pol_rem,
                reference="RFC 7208 Section 4.7",
            )
        )

        has_ptr = bool(re.search(r"\bptr\b", primary_spf.lower()))
        if lookup_count > 10:
            lookup_sev = Severity.MEDIUM
            lookup_status = f"Melebihi Batas ({lookup_count}/10)"
            lookup_rem = "Kurangi penggunaan 'include:' atau gunakan teknik SPF Flattening karena >10 DNS lookups memicu SPF PermError."
        elif has_ptr:
            lookup_sev = Severity.LOW
            lookup_status = f"{lookup_count}/10 Lookups (Ada 'ptr')"
            lookup_rem = "Hapus mekanisme 'ptr' karena telah dinyatakan usang (deprecated) oleh RFC 7208 Section 5.5."
        else:
            lookup_sev = Severity.PASS
            lookup_status = f"Optimal ({lookup_count}/10 Lookups)"
            lookup_rem = (
                "Jumlah kueri DNS tingkat pertama pada SPF masih berada di bawah batas maksimal 10."
            )

        results.append(
            AuditFinding(
                category="DNS Security",
                item="SPF DNS Lookup Limit",
                severity=lookup_sev,
                status=lookup_status,
                description=f"Mekanisme pemicu DNS lookup tingkat pertama terdeteksi sebanyak {lookup_count} kali.",
                remediation=lookup_rem,
                reference="RFC 7208 Section 4.6.4",
            )
        )

        return results

    def _check_dmarc_record(
        self, resolver: dns.resolver.Resolver, domain: str
    ) -> list[AuditFinding]:
        results: list[AuditFinding] = []
        dmarc_host = f"_dmarc.{domain}"
        dmarc_records: list[str] = []

        try:
            answers = resolver.resolve(dmarc_host, "TXT")
            for rdata in answers:
                txt_str = "".join(s.decode("utf-8", errors="ignore") for s in rdata.strings).strip()
                if txt_str.lower().startswith("v=dmarc1"):
                    dmarc_records.append(txt_str)
        except Exception:
            pass

        if not dmarc_records:
            results.append(
                AuditFinding(
                    category="DNS Security",
                    item="DMARC Policy (_dmarc)",
                    severity=Severity.HIGH,
                    status="Tidak Ditemukan",
                    description=f"Tidak ada TXT record DMARC pada {dmarc_host}. Penerima email tidak memiliki instruksi penolakan jika SPF/DKIM gagal.",
                    remediation=f"Tambahkan TXT record pada '{dmarc_host}' dengan nilai: 'v=DMARC1; p=quarantine; sp=quarantine; pct=100; rua=mailto:dmarc@{domain};'",
                    reference="RFC 7489",
                )
            )
            return results

        raw_dmarc = dmarc_records[0]
        tags = self._parse_dmarc_tags(raw_dmarc)
        policy = tags.get("p", "none").lower()
        sub_policy = tags.get("sp", policy).lower()
        pct = int(tags.get("pct", "100")) if tags.get("pct", "100").isdigit() else 100
        rua = tags.get("rua", "")

        if policy == "reject" and pct == 100:
            p_sev = Severity.PASS
            p_status = "Maksimal (p=reject, 100%)"
            p_rem = "Kebijakan penolakan DMARC sudah berada pada tingkat perlindungan tertinggi."
        elif policy == "quarantine" and pct == 100:
            p_sev = Severity.PASS
            p_status = "Aktif (p=quarantine, 100%)"
            p_rem = "Sudah memfilter spoofing ke folder Spam. Tingkatkan ke 'p=reject' setelah seluruh sumber email tervalidasi."
        elif policy in ("reject", "quarantine") and pct < 100:
            p_sev = Severity.LOW
            p_status = f"Parsial (p={policy}, pct={pct}%)"
            p_rem = (
                "Naikkan atribut 'pct=100' agar kebijakan DMARC diterapkan pada 100% trafik email."
            )
        else:
            p_sev = Severity.MEDIUM
            p_status = "Hanya Pantau (p=none)"
            p_rem = "Kebijakan 'p=none' hanya mengumpulkan laporan tanpa memblokir email palsu. Ubah ke 'p=quarantine' atau 'p=reject'."

        results.append(
            AuditFinding(
                category="DNS Security",
                item="DMARC Enforcement (p= & sp=)",
                severity=p_sev,
                status=f"{p_status} [sp={sub_policy}]",
                description=f"Record DMARC: {raw_dmarc[:65]}",
                remediation=p_rem,
                reference="RFC 7489 Section 6.3",
            )
        )

        if rua and "mailto:" in rua.lower():
            results.append(
                AuditFinding(
                    category="DNS Security",
                    item="DMARC Aggregate Reporting (rua)",
                    severity=Severity.PASS,
                    status="Terkonfigurasi",
                    description=f"Laporan agregat DMARC dikirim ke: {rua}",
                    remediation="Pantau laporan XML DMARC secara berkala untuk mendeteksi upaya penyalahgunaan domain.",
                    reference="RFC 7489 Section 6.2",
                )
            )
        else:
            results.append(
                AuditFinding(
                    category="DNS Security",
                    item="DMARC Aggregate Reporting (rua)",
                    severity=Severity.LOW,
                    status="Tanpa URI Pelaporan (rua)",
                    description="DMARC aktif tetapi tidak menyertakan tag 'rua=mailto:...' untuk menerima laporan visibilitas autentikasi email.",
                    remediation=f"Tambahkan '; rua=mailto:dmarc-reports@{domain}' pada record DMARC Anda.",
                    reference="RFC 7489 Section 6.2",
                )
            )

        return results

    def _check_dkim_selectors(
        self, resolver: dns.resolver.Resolver, domain: str
    ) -> list[AuditFinding]:
        found_selectors: list[str] = []
        for selector in COMMON_DKIM_SELECTORS:
            qname = f"{selector}._domainkey.{domain}"
            try:
                answers = resolver.resolve(qname, "TXT")
                for rdata in answers:
                    txt_val = "".join(s.decode("utf-8", errors="ignore") for s in rdata.strings)
                    if "p=" in txt_val.lower() or "v=dkim1" in txt_val.lower():
                        found_selectors.append(selector)
                        break
            except Exception:
                continue

        if found_selectors:
            return [
                AuditFinding(
                    category="DNS Security",
                    item="DKIM Public Key Discovery",
                    severity=Severity.PASS,
                    status=f"Ditemukan ({', '.join(found_selectors)})",
                    description=f"Kunci publik DKIM aktif terdeteksi pada selector: {', '.join(found_selectors)}.",
                    remediation="Lakukan rotasi kunci DKIM (minimal RSA 2048-bit) secara berkala setiap 6-12 bulan.",
                    reference="RFC 6376",
                )
            ]
        return [
            AuditFinding(
                category="DNS Security",
                item="DKIM Public Key Discovery",
                severity=Severity.INFO,
                status="Selector Kustom / Tidak Terdeteksi",
                description="Tidak ditemukan kunci DKIM pada daftar selector umum (google, selector1, default, k1, dll).",
                remediation="Jika domain menggunakan selector kustom (unik), abaikan pesan ini. Pastikan kunci RSA minimal 2048-bit.",
                reference="RFC 6376",
            )
        ]

    def _check_mta_sts_and_tlsrpt(
        self, resolver: dns.resolver.Resolver, domain: str
    ) -> list[AuditFinding]:
        findings: list[AuditFinding] = []
        mta_sts_found = False
        try:
            answers = resolver.resolve(f"_mta-sts.{domain}", "TXT")
            for rdata in answers:
                txt_val = "".join(s.decode("utf-8", errors="ignore") for s in rdata.strings)
                if "v=sts1" in txt_val.lower():
                    mta_sts_found = True
                    findings.append(
                        AuditFinding(
                            category="DNS Security",
                            item="MTA-STS (Email Transport Encryption)",
                            severity=Severity.PASS,
                            status="Aktif (v=STSv1)",
                            description=f"Kebijakan enkripsi pengiriman email MTA-STS aktif: {txt_val[:50]}",
                            remediation="Pastikan file kebijakan di https://mta-sts.<domain>/.well-known/mta-sts.txt menggunakan 'mode: enforce'.",
                            reference="RFC 8461",
                        )
                    )
                    break
        except Exception:
            pass

        if not mta_sts_found:
            findings.append(
                AuditFinding(
                    category="DNS Security",
                    item="MTA-STS (Email Transport Encryption)",
                    severity=Severity.LOW,
                    status="Belum Dikonfigurasi",
                    description="Tidak ditemukan TXT record '_mta-sts' untuk mencegah serangan downgrade TLS pada pengiriman SMTP.",
                    remediation="Konfigurasikan MTA-STS (RFC 8461) dan SMTP TLS Reporting (RFC 8460) bila domain menangani trafik email sensitif.",
                    reference="RFC 8461",
                )
            )

        return findings

    def _check_caa_records(
        self, resolver: dns.resolver.Resolver, domain: str
    ) -> list[AuditFinding]:
        try:
            answers = resolver.resolve(domain, "CAA")
            caa_entries = [r.to_text() for r in answers]
            return [
                AuditFinding(
                    category="DNS Security",
                    item="CAA Record (SSL Issuance Control)",
                    severity=Severity.PASS,
                    status=f"Terkonfigurasi ({len(caa_entries)} Aturan)",
                    description=f"Otoritas CA yang diizinkan menerbitkan sertifikat: {', '.join(caa_entries)[:60]}",
                    remediation="Pertahankan daftar CAA seminimal mungkin sesuai CA yang benar-benar Anda gunakan.",
                    reference="RFC 8659",
                )
            ]
        except Exception:
            return [
                AuditFinding(
                    category="DNS Security",
                    item="CAA Record (SSL Issuance Control)",
                    severity=Severity.LOW,
                    status="Tidak Ditemukan",
                    description="Tidak ada record DNS CAA yang membatasi otoritas penerbit sertifikat SSL/TLS.",
                    remediation="Tambahkan DNS CAA record (contoh: '0 issue \"letsencrypt.org\"' dan '0 iodef \"mailto:security@...\"').",
                    reference="RFC 8659",
                )
            ]

    def _check_dnssec(self, resolver: dns.resolver.Resolver, domain: str) -> list[AuditFinding]:
        has_dnskey = False
        try:
            resolver.resolve(domain, "DNSKEY")
            has_dnskey = True
        except Exception:
            pass

        if has_dnskey:
            return [
                AuditFinding(
                    category="DNS Security",
                    item="DNSSEC Cryptographic Signing",
                    severity=Severity.PASS,
                    status="Aktif (DNSKEY Terdeteksi)",
                    description=f"Zona DNS {domain} menandatangani record secara kriptografis menggunakan DNSSEC.",
                    remediation="Pastikan algoritma penandatanganan menggunakan ECDSAP256SHA256 (Algo 13) atau ED25519 (Algo 15).",
                    reference="RFC 4035 / RFC 8624",
                )
            ]
        return [
            AuditFinding(
                category="DNS Security",
                item="DNSSEC Cryptographic Signing",
                severity=Severity.LOW,
                status="Tidak Aktif (Unsigned)",
                description=f"Domain {domain} belum mengaktifkan DNSSEC (tidak ditemukan record DNSKEY).",
                remediation="Aktifkan DNSSEC pada registrar dan penyedia DNS Anda untuk mencegah serangan DNS Spoofing / Cache Poisoning.",
                reference="RFC 4035",
            )
        ]
