import socket
from urllib.parse import urlparse

from app.security.url_validator import SSRFValidationError, SSRFValidator


def validate_scan_url(url: str) -> tuple[bool, str]:
    """
    Validates the URL for scan safety using the enterprise SSRFValidator.
    Returns (True, resolved_ip) or (False, error_message).
    """
    try:
        SSRFValidator.validate_url(url)
    except SSRFValidationError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Unexpected validation error: {e}"

    # Maintain existing behavior of returning the resolved IP for legacy callers
    parsed = urlparse(url)
    if parsed.hostname is None:
        return False, "Hostname cannot be None"

    try:
        resolved_ip = socket.gethostbyname(parsed.hostname)
        return True, resolved_ip
    except socket.gaierror:
        return False, "Domain does not exist or cannot be resolved"
