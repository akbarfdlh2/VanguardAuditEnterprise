from unittest.mock import MagicMock, patch

import pytest

from vanguard.auditors.dns_auditor import DNSAuditor
from vanguard.core.models import Severity


def test_extract_base_domain_indonesian_cctld() -> None:
    assert DNSAuditor._extract_base_domain("portal.perusahaan.co.id") == "perusahaan.co.id"
    assert DNSAuditor._extract_base_domain("api.staging.example.com") == "example.com"
    assert DNSAuditor._extract_base_domain("example.com") == "example.com"
    assert DNSAuditor._extract_base_domain("localhost") == "localhost"


def test_spf_lookup_counter_rfc7208() -> None:
    sample_spf = (
        "v=spf1 ip4:192.0.2.0/24 include:_spf.google.com include:sendgrid.net "
        "a mx exists:%{i}._spf.mta.example.com -all"
    )
    assert DNSAuditor._count_spf_lookups(sample_spf) == 5


def test_dmarc_tag_parser() -> None:
    raw = "v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:dmarc@example.com"
    tags = DNSAuditor._parse_dmarc_tags(raw)
    assert tags["v"] == "DMARC1"
    assert tags["p"] == "quarantine"
    assert tags["sp"] == "reject"
    assert tags["pct"] == "100"
    assert tags["rua"] == "mailto:dmarc@example.com"


@pytest.mark.asyncio
async def test_dns_auditor_name_and_localhost() -> None:
    auditor = DNSAuditor()
    assert "DNS" in auditor.name
    findings = await auditor.run("http://localhost:8000")
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "Localhost" in findings[0].status


@pytest.mark.asyncio
async def test_dns_auditor_mocked_run() -> None:
    auditor = DNSAuditor()

    def mock_resolve(qname: str, rdtype: str) -> list[MagicMock]:
        if rdtype == "MX":
            m = MagicMock()
            m.exchange = "mail.example.com."
            return [m]
        if rdtype == "TXT":
            if qname.startswith("_dmarc."):
                m = MagicMock()
                m.strings = [b"v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com"]
                return [m]
            if qname.startswith("_mta-sts."):
                m = MagicMock()
                m.strings = [b"v=STSv1; id=20261023"]
                return [m]
            if qname.startswith("_smtp._tls."):
                m = MagicMock()
                m.strings = [b"v=TLSRPTv1; rua=mailto:tlsrpt@example.com"]
                return [m]
            if "._domainkey." in qname:
                m = MagicMock()
                m.strings = [b"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQE..."]
                return [m]
            m = MagicMock()
            m.strings = [b"v=spf1 include:_spf.google.com -all"]
            return [m]
        if rdtype == "CAA":
            m = MagicMock()
            m.tag = "issue"
            m.value = "letsencrypt.org"
            return [m]
        if rdtype in ("DNSKEY", "DS"):
            m = MagicMock()
            return [m]
        raise Exception("Record not found")

    with patch("dns.resolver.Resolver.resolve", side_effect=mock_resolve):
        findings = await auditor.run("https://example.com")
        assert len(findings) >= 5

        spf_f = next(f for f in findings if "SPF Enforcement Policy" in f.item)
        assert spf_f.severity == Severity.PASS

        dmarc_f = next(f for f in findings if "DMARC Enforcement" in f.item)
        assert dmarc_f.severity == Severity.PASS

        dnssec_f = next(f for f in findings if "DNSSEC" in f.item)
        assert dnssec_f.severity == Severity.PASS


@pytest.mark.asyncio
async def test_dns_auditor_spf_variations() -> None:
    auditor = DNSAuditor()

    def mock_resolve(qname: str, rdtype: str) -> list[MagicMock]:
        if rdtype == "TXT" and not qname.startswith("_"):
            m1 = MagicMock()
            m1.strings = [b"v=spf1 +all"]
            m2 = MagicMock()
            m2.strings = [b"v=spf1 ~all"]
            return [m1, m2]
        raise Exception("Not found")

    with patch("dns.resolver.Resolver.resolve", side_effect=mock_resolve):
        findings = await auditor.run("https://example.com")
        conflict_f = next(f for f in findings if "Multiple Records" in f.item)
        assert conflict_f.severity == Severity.HIGH
