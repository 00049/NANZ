import pytest

from app.security.url_validator import SSRFValidationError, SSRFValidator


def test_valid_urls():
    assert (
        SSRFValidator.validate_url("https://www.google.com") == "https://www.google.com"
    )
    assert (
        SSRFValidator.validate_url("http://example.com/path?query=1")
        == "http://example.com/path?query=1"
    )


def test_invalid_schemes():
    with pytest.raises(SSRFValidationError, match="Blocked scheme"):
        SSRFValidator.validate_url("file:///etc/passwd")
    with pytest.raises(SSRFValidationError, match="Blocked scheme"):
        SSRFValidator.validate_url("gopher://127.0.0.1:6379/_PING")
    with pytest.raises(SSRFValidationError, match="Blocked scheme"):
        SSRFValidator.validate_url("dict://127.0.0.1:11211/stat")


def test_blocked_ips():
    bad_ips = [
        "http://127.0.0.1",
        "https://10.0.0.5",
        "http://172.16.0.1",
        "http://192.168.1.1",
        "http://169.254.169.254",  # AWS metadata
        "http://0.0.0.0",
        "http://[::1]",  # IPv6 loopback
        "http://[fc00::1]",
    ]
    for url in bad_ips:
        with pytest.raises(
            SSRFValidationError, match="Blocked internal/reserved IP address"
        ):
            SSRFValidator.validate_url(url)


def test_dns_rebinding_protection():
    # This assumes localhost resolves to 127.0.0.1 on the testing machine
    with pytest.raises(
        SSRFValidationError, match="Blocked internal/reserved IP address"
    ):
        SSRFValidator.validate_url("http://localhost")

    # localtest.me is a public domain that intentionally resolves to 127.0.0.1 for testing
    with pytest.raises(
        SSRFValidationError, match="Blocked internal/reserved IP address"
    ):
        SSRFValidator.validate_url("http://localtest.me")
