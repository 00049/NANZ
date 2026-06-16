from unittest.mock import MagicMock, patch

import pytest

from app.utils.url_validator import validate_scan_url


@pytest.mark.asyncio
@patch("app.services.scanner.ssl_check._deep_ssl_inspect")
@patch("app.services.scanner.ssl_check.ssl")
@patch("app.services.scanner.ssl_check.socket")
async def test_ssl_check_valid_cert(mock_socket, mock_ssl, mock_deep):
    from app.services.scanner.ssl_check import _basic_ssl_fallback, run

    mock_deep.side_effect = lambda domain: _basic_ssl_fallback(domain)

    mock_ctx = MagicMock()
    mock_ssl.create_default_context.return_value = mock_ctx
    mock_ssock = MagicMock()
    # Need to simulate ctx.wrap_socket returning a context manager
    mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock

    mock_ssock.getpeercert.return_value = {
        "notAfter": "Dec 31 23:59:59 2030 GMT",
        "issuer": ((("O", "Test Corp"),),),
        "subject": ((("CN", "example.com"),),),
    }
    mock_ssock.version.return_value = "TLSv1.3"

    result = await run("example.com")
    assert result.valid
    assert result.days_until_expiry > 0


@pytest.mark.asyncio
@patch("app.services.scanner.ssl_check._deep_ssl_inspect")
@patch("app.services.scanner.ssl_check.ssl")
@patch("app.services.scanner.ssl_check.socket")
async def test_ssl_check_expired_cert(mock_socket, mock_ssl, mock_deep):
    from app.services.scanner.ssl_check import _basic_ssl_fallback, run

    mock_deep.side_effect = lambda domain: _basic_ssl_fallback(domain)

    mock_ctx = MagicMock()
    mock_ssl.create_default_context.return_value = mock_ctx
    mock_ssock = MagicMock()
    mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock

    # 2020 is past
    mock_ssock.getpeercert.return_value = {
        "notAfter": "Dec 31 23:59:59 2020 GMT",
        "issuer": ((("O", "Test Corp"),),),
        "subject": ((("CN", "example.com"),),),
    }

    result = await run("example.com")
    assert result.valid  # Cert format parsed ok
    assert result.days_until_expiry < 0


@pytest.mark.asyncio
@patch("app.services.scanner.headers_check.httpx.AsyncClient")
async def test_headers_check_missing_csp(mock_client):
    from app.services.scanner.headers_check import run

    mock_instance = mock_client.return_value.__aenter__.return_value
    mock_response = MagicMock()
    mock_response.headers = {
        "strict-transport-security": "max-age=31536000"
        # csp is missing
    }
    mock_instance.get.return_value = mock_response

    result = await run("https://example.com")
    assert "content-security-policy" in result.missing
    assert "strict-transport-security" in result.present


def test_url_validator_rejects_localhost():
    is_valid, msg = validate_scan_url("http://localhost:8000")
    assert not is_valid
    assert "Cannot scan local addresses" in msg


def test_url_validator_rejects_private_ip_10_range():
    is_valid, msg = validate_scan_url("http://10.0.0.1")
    assert not is_valid
    assert "Cannot scan bare IP addresses" in msg


@patch("app.utils.url_validator.socket.gethostbyname")
def test_url_validator_accepts_valid_domain(mock_gethostbyname):
    # Mocking external DNS resolution to prevent real network calls
    mock_gethostbyname.return_value = "8.8.8.8"
    is_valid, ip = validate_scan_url("https://google.com")
    assert is_valid
    assert ip == "8.8.8.8"


@pytest.mark.asyncio
@patch("app.services.scanner.cookie_check.httpx.AsyncClient")
async def test_cookie_check_detects_missing_httponly(mock_client):
    from app.services.scanner.cookie_check import run

    mock_instance = mock_client.return_value.__aenter__.return_value
    mock_response = MagicMock()
    mock_response.headers.get_list.return_value = [
        "session_id=123; Secure; SameSite=Lax"
    ]  # Missing HttpOnly
    mock_instance.get.return_value = mock_response

    result = await run("https://example.com")
    assert result.total_cookies == 1
    assert any(
        c["name"] == "session_id" and "HttpOnly" in c["missing_flags"]
        for c in result.insecure_cookies
    )
    assert result.session_cookies_insecure
