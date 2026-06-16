import ipaddress


def is_private_ip(ip_str: str) -> bool:
    """Helper function to check if an IP is private."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False
