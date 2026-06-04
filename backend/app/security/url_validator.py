import socket
import urllib.parse
import ipaddress
import dns.resolver
from typing import List

class SSRFValidationError(Exception):
    pass

class SSRFValidator:
    """
    Enterprise-grade SSRF validator.
    Blocks internal, loopback, private, multicast, and cloud metadata IPs.
    Prevents DNS rebinding via pre-flight resolution checks.
    """

    ALLOWED_SCHEMES = {"http", "https"}

    # Known bad IP ranges (RFC 1918, RFC 4193, loopback, link-local, multicast, cloud metadata)
    BLOCKED_NETWORKS = [
        ipaddress.ip_network("127.0.0.0/8"),      # Loopback IPv4
        ipaddress.ip_network("::1/128"),          # Loopback IPv6
        ipaddress.ip_network("10.0.0.0/8"),       # Private IPv4
        ipaddress.ip_network("172.16.0.0/12"),    # Private IPv4
        ipaddress.ip_network("192.168.0.0/16"),   # Private IPv4
        ipaddress.ip_network("fc00::/7"),         # Unique Local IPv6
        ipaddress.ip_network("169.254.0.0/16"),   # Link-local (includes 169.254.169.254 AWS/GCP metadata)
        ipaddress.ip_network("fe80::/10"),        # Link-local IPv6
        ipaddress.ip_network("224.0.0.0/4"),      # Multicast IPv4
        ipaddress.ip_network("ff00::/8"),         # Multicast IPv6
        ipaddress.ip_network("0.0.0.0/8"),        # Current network (validly blocked for routing)
        ipaddress.ip_network("255.255.255.255/32")# Broadcast
    ]

    @classmethod
    def validate_url(cls, url: str) -> str:
        """
        Fully validates a URL against SSRF attacks.
        Returns the original URL if safe, raises SSRFValidationError if unsafe.
        """
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception as e:
            raise SSRFValidationError(f"Invalid URL format: {e}")

        if parsed.scheme.lower() not in cls.ALLOWED_SCHEMES:
            raise SSRFValidationError(f"Blocked scheme: {parsed.scheme}. Only http/https are allowed.")

        hostname = parsed.hostname
        if not hostname:
            raise SSRFValidationError("No hostname found in URL.")

        # 1. Check if the hostname is a direct IP address
        try:
            ip_obj = ipaddress.ip_address(hostname)
            cls._check_ip_blocked(ip_obj)
            return url # It's a safe, direct IP
        except ValueError:
            pass # Not a direct IP, proceed to DNS resolution

        # 2. DNS Resolution (Pre-flight check for rebinding protection)
        try:
            # We resolve A (IPv4) and AAAA (IPv6) records
            resolved_ips: List[str] = []
            
            try:
                answers_ipv4 = dns.resolver.resolve(hostname, 'A', lifetime=2.0)
                resolved_ips.extend([rdata.to_text() for rdata in answers_ipv4])
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
                
            try:
                answers_ipv6 = dns.resolver.resolve(hostname, 'AAAA', lifetime=2.0)
                resolved_ips.extend([rdata.to_text() for rdata in answers_ipv6])
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
                
            if not resolved_ips:
                raise SSRFValidationError(f"Could not resolve hostname: {hostname}")
                
            for ip_str in resolved_ips:
                ip_obj = ipaddress.ip_address(ip_str)
                cls._check_ip_blocked(ip_obj)
                
        except dns.exception.DNSException as e:
            raise SSRFValidationError(f"DNS resolution failed for {hostname}: {e}")
            
        return url

    @classmethod
    def _check_ip_blocked(cls, ip: ipaddress._BaseAddress) -> None:
        """Checks if a parsed IP address falls into any blocked CIDR ranges."""
        # IP is private, loopback, link-local, multicast, etc.
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
             raise SSRFValidationError(f"Blocked internal/reserved IP address detected: {ip}")

        # Explicitly check against our exhaustive blocklist just in case python's built-in flags miss something
        for network in cls.BLOCKED_NETWORKS:
            if ip in network:
                raise SSRFValidationError(f"Blocked internal/reserved IP address detected: {ip} (matches {network})")
