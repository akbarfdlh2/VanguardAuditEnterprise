import ssl
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from vanguard.auditors.ssl_auditor import SSLAuditor
from vanguard.core.models import Severity


@pytest.mark.asyncio
async def test_ssl_auditor_name() -> None:
    auditor = SSLAuditor()
    assert "SSL/TLS" in auditor.name


@pytest.mark.asyncio
async def test_ssl_auditor_http_scheme() -> None:
    auditor = SSLAuditor()
    findings = await auditor.run("http://example.com")
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "Enkripsi Transport" in findings[0].item


@pytest.mark.asyncio
async def test_ssl_auditor_success() -> None:
    auditor = SSLAuditor()
    future_date = datetime.now(timezone.utc).year + 1
    mock_cert = {
        "notAfter": f"Dec 31 23:59:59 {future_date} GMT",
    }
    mock_ssock = MagicMock()
    mock_ssock.__enter__.return_value = mock_ssock
    mock_ssock.getpeercert.return_value = mock_cert
    mock_ssock.version.return_value = "TLSv1.3"
    mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    mock_sock = MagicMock()
    mock_sock.__enter__.return_value = mock_sock

    with (
        patch("socket.create_connection", return_value=mock_sock),
        patch("ssl.create_default_context") as mock_ctx,
    ):
        mock_ctx.return_value.wrap_socket.return_value = mock_ssock
        findings = await auditor.run("https://example.com")
        assert len(findings) == 3
        tls_f = next(f for f in findings if f.item == "Versi Protokol TLS")
        assert tls_f.severity == Severity.PASS

        cipher_f = next(f for f in findings if "Cipher" in f.item)
        assert cipher_f.severity == Severity.PASS

        cert_f = next(f for f in findings if "Masa Aktif" in f.item)
        assert cert_f.severity == Severity.PASS


@pytest.mark.asyncio
async def test_ssl_auditor_cert_verification_error() -> None:
    auditor = SSLAuditor()
    err = ssl.SSLCertVerificationError()
    err.verify_message = "certificate has expired"

    with patch("socket.create_connection", side_effect=err):
        findings = await auditor.run("https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "Verifikasi Rantai Sertifikat CA" in findings[0].item


@pytest.mark.asyncio
async def test_ssl_auditor_general_exception() -> None:
    auditor = SSLAuditor()
    with patch("socket.create_connection", side_effect=OSError("Network unreachable")):
        findings = await auditor.run("https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "Jabat Tangan TLS" in findings[0].item
