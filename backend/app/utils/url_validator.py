import socket
import ipaddress
from urllib.parse import urlparse

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
]

def validate_scan_url(url: str) -> tuple[bool, str]:
    """
    Validates the URL for scan safety (no local network scanning).
    Returns (True, resolved_ip) or (False, error_message).
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "URL must start with http:// or https://"

    if parsed.hostname is None:
        return False, "Hostname cannot be None"
    hostname = parsed.hostname
    if hostname in ("localhost", "127.0.0.1", "0.0.0.0", ""):
        return False, "Cannot scan local addresses"
        
    try:
        # Check if the hostname itself is an IP address
        # If it is, we reject bare IPs per rules
        ipaddress.ip_address(hostname)
        return False, "Cannot scan bare IP addresses, must use a domain"
    except ValueError:
        pass # It's a domain name, which is good

    try:
        resolved_ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(resolved_ip)
        for private_range in PRIVATE_RANGES:
            if ip_obj in private_range:
                return False, "Cannot scan private IP addresses"
    except socket.gaierror:
        return False, "Domain does not exist or cannot be resolved"

    return True, resolved_ip
