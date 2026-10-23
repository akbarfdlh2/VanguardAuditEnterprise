from unittest.mock import AsyncMock, patch

import pytest

from vanguard.auditors.governance_auditor import GovernanceAuditor
from vanguard.core.models import Severity


@pytest.mark.asyncio
async def test_governance_auditor_name() -> None:
    auditor = GovernanceAuditor()
    assert "RFC 9116" in auditor.name


@pytest.mark.asyncio
async def test_governance_auditor_pass() -> None:
    auditor = GovernanceAuditor()
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Type": "text/plain; charset=utf-8"}
    mock_resp.text = "Contact: mailto:security@example.com\nExpires: 2026-12-31T23:59:59z"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        findings = await auditor.run("https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.PASS
        assert findings[0].status == "Tersedia"


@pytest.mark.asyncio
async def test_governance_auditor_no_expires() -> None:
    auditor = GovernanceAuditor()
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Type": "text/plain"}
    mock_resp.text = "Contact: mailto:security@example.com"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        findings = await auditor.run("https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert "Tanpa Field 'Expires:'" in findings[0].status


@pytest.mark.asyncio
async def test_governance_auditor_404() -> None:
    auditor = GovernanceAuditor()
    mock_resp = AsyncMock()
    mock_resp.status_code = 404
    mock_resp.headers = {"Content-Type": "text/html"}
    mock_resp.text = "Not Found"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        findings = await auditor.run("https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert findings[0].status == "Tidak Ditemukan"


@pytest.mark.asyncio
async def test_governance_auditor_exception() -> None:
    auditor = GovernanceAuditor()
    with patch("httpx.AsyncClient.get", side_effect=Exception("Connection error")):
        findings = await auditor.run("https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert findings[0].status == "Tidak Dapat Diakses"
