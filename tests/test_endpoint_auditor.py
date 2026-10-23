from unittest.mock import AsyncMock, patch

import pytest

from vanguard.auditors.endpoint_auditor import SENSITIVE_TARGETS, EndpointAuditor
from vanguard.core.models import Severity


@pytest.mark.asyncio
async def test_endpoint_auditor_name() -> None:
    auditor = EndpointAuditor()
    assert "Unauthenticated Endpoints" in auditor.name


@pytest.mark.asyncio
async def test_endpoint_auditor_exposed_200() -> None:
    auditor = EndpointAuditor()
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.text = "DB_PASSWORD=supersecret\nAPP_KEY=12345"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        findings = await auditor.run("https://example.com")
        assert len(findings) == len(SENSITIVE_TARGETS)
        for f in findings:
            assert "Terekspos Tanpa Auth" in f.status
            assert f.severity in (Severity.HIGH, Severity.MEDIUM, Severity.LOW)


@pytest.mark.asyncio
async def test_endpoint_auditor_protected_401() -> None:
    auditor = EndpointAuditor()
    mock_resp = AsyncMock()
    mock_resp.status_code = 401
    mock_resp.text = "Unauthorized"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        findings = await auditor.run("https://example.com")
        assert len(findings) == len(SENSITIVE_TARGETS)
        for f in findings:
            assert "Terproteksi Auth" in f.status
            assert f.severity == Severity.PASS


@pytest.mark.asyncio
async def test_endpoint_auditor_404() -> None:
    auditor = EndpointAuditor()
    mock_resp = AsyncMock()
    mock_resp.status_code = 404
    mock_resp.text = "Not Found"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        findings = await auditor.run("https://example.com")
        assert len(findings) == len(SENSITIVE_TARGETS)
        for f in findings:
            assert "Tidak Ditemukan" in f.status
            assert f.severity == Severity.PASS


@pytest.mark.asyncio
async def test_endpoint_auditor_exception() -> None:
    auditor = EndpointAuditor()
    with patch("httpx.AsyncClient.get", side_effect=Exception("Connection reset")):
        findings = await auditor.run("https://example.com")
        assert len(findings) == len(SENSITIVE_TARGETS)
        for f in findings:
            assert f.status == "Tidak Dapat Diakses"
            assert f.severity == Severity.PASS
