from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vanguard.auditors.network_auditor import NetworkAuditor
from vanguard.core.models import Severity


@pytest.mark.asyncio
async def test_network_auditor_name() -> None:
    auditor = NetworkAuditor()
    assert "SecurityScorecard" in auditor.name


@pytest.mark.asyncio
async def test_network_auditor_all_closed_and_https_enforced() -> None:
    auditor = NetworkAuditor()

    mock_resp = AsyncMock()
    mock_resp.status_code = 301
    mock_resp.headers = {"location": "https://example.com/"}

    with (
        patch.object(auditor, "_raw_connect", return_value=(False, "")),
        patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get,
    ):
        mock_get.return_value = mock_resp
        findings = await auditor.run("https://example.com")
        assert len(findings) > 0
        enforce_f = next(f for f in findings if f.item == "Site Enforces HTTPS")
        assert enforce_f.severity == Severity.PASS
        assert "Terenkripsi Paksa" in enforce_f.status


@pytest.mark.asyncio
async def test_network_auditor_open_ports_and_ssh_banner() -> None:
    auditor = NetworkAuditor()

    def mock_connect(host: str, port: int) -> tuple[bool, str]:
        if port == 22:
            return True, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
        if port == 443:
            return True, ""
        if port == 3306:
            return True, ""
        return False, ""

    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.headers = {}

    with (
        patch.object(auditor, "_raw_connect", side_effect=mock_connect),
        patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get,
    ):
        mock_get.return_value = mock_resp
        findings = await auditor.run("https://example.com")

        ssh_f = next(f for f in findings if "SSH Service (Port 22)" in f.item)
        assert ssh_f.severity == Severity.LOW

        banner_f = next(f for f in findings if "SSH Service Banner Disclosure" in f.item)
        assert banner_f.severity == Severity.LOW
        assert "OpenSSH" in banner_f.status

        mysql_f = next(f for f in findings if "MySQL" in f.item)
        assert mysql_f.severity == Severity.HIGH

        https_f = next(f for f in findings if "Site Enforces HTTPS" in f.item)
        assert https_f.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_network_auditor_connect_exception() -> None:
    auditor = NetworkAuditor()

    with (
        patch.object(auditor, "_raw_connect", return_value=(False, "")),
        patch("httpx.AsyncClient.get", side_effect=Exception("Connection refused")),
    ):
        findings = await auditor.run("https://example.com")
        enforce_f = next(f for f in findings if f.item == "Site Enforces HTTPS")
        assert enforce_f.severity == Severity.PASS
        assert "Tidak Merespon" in enforce_f.status


def test_network_auditor_raw_connect_live() -> None:
    auditor = NetworkAuditor()
    mock_sock = MagicMock()
    mock_sock.__enter__.return_value = mock_sock
    mock_sock.recv.return_value = b"SSH-2.0-TestSSH\r\n"

    with patch("socket.create_connection", return_value=mock_sock):
        is_open, banner = auditor._raw_connect("localhost", 22)
        assert is_open is True
        assert banner == "SSH-2.0-TestSSH"
