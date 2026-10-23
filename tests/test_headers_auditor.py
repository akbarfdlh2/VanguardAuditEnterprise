from unittest.mock import AsyncMock, patch

import httpx
import pytest

from vanguard.auditors.headers_auditor import HeadersAuditor
from vanguard.core.models import Severity


@pytest.mark.asyncio
async def test_headers_auditor_name() -> None:
    auditor = HeadersAuditor()
    assert "HTTP Security Headers" in auditor.name


@pytest.mark.asyncio
async def test_headers_auditor_all_pass() -> None:
    auditor = HeadersAuditor()
    mock_resp = AsyncMock()
    mock_resp.headers = httpx.Headers(
        [
            ("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload"),
            ("Content-Security-Policy", "default-src 'self'"),
            ("X-Frame-Options", "DENY"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("Permissions-Policy", "geolocation=()"),
            ("Cross-Origin-Opener-Policy", "same-origin"),
            ("Cross-Origin-Resource-Policy", "same-origin"),
            ("Access-Control-Allow-Origin", "https://trusted.com"),
            ("Server", "nginx"),
            ("Set-Cookie", "session=123; Secure; HttpOnly; SameSite=Strict"),
        ]
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        findings = await auditor.run("https://example.com")
        assert len(findings) > 0
        hsts_finding = next(f for f in findings if f.item == "Strict-Transport-Security")
        assert hsts_finding.severity == Severity.PASS

        csp_finding = next(f for f in findings if f.item == "Content-Security-Policy")
        assert csp_finding.severity == Severity.PASS

        cookie_finding = next(f for f in findings if "session" in f.item)
        assert cookie_finding.severity == Severity.PASS


@pytest.mark.asyncio
async def test_headers_auditor_unsafe_csp_and_cors_wildcard() -> None:
    auditor = HeadersAuditor()
    mock_resp = AsyncMock()
    mock_resp.headers = httpx.Headers(
        [
            ("Content-Security-Policy", "default-src 'self' 'unsafe-inline'"),
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Credentials", "true"),
            ("Server", "Apache/2.4.41"),
            ("X-Powered-By", "PHP/8.1"),
            ("Set-Cookie", "tracker=abc"),
        ]
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        findings = await auditor.run("https://example.com")
        csp_finding = next(f for f in findings if "Content-Security-Policy" in f.item)
        assert csp_finding.severity == Severity.LOW

        cors_finding = next(f for f in findings if f.item == "Access-Control-Allow-Origin")
        assert cors_finding.severity == Severity.HIGH

        server_finding = next(f for f in findings if f.item == "Header Server")
        assert server_finding.severity == Severity.LOW

        cookie_finding = next(f for f in findings if "tracker" in f.item)
        assert cookie_finding.severity == Severity.MEDIUM
        assert "Secure, HttpOnly, SameSite" in cookie_finding.status


@pytest.mark.asyncio
async def test_headers_auditor_network_error() -> None:
    auditor = HeadersAuditor()
    req = httpx.Request("GET", "https://example.com")
    with patch(
        "httpx.AsyncClient.get", side_effect=httpx.ConnectError("Connection refused", request=req)
    ):
        findings = await auditor.run("https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].status == "Gagal Terhubung"
