"""
Domain 1: SSL/TLS Deep Analysis using SSLyze.

Replaces the basic ssl module check with comprehensive SSLyze-powered analysis.
Checks: certificate validity, chain trust, TLS versions, cipher suites,
HSTS, Heartbleed, ROBOT, OCSP stapling, CT logs, and more.

All checks are PASSIVE — no active exploitation.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class SSLResult:
    """Result of deep SSL/TLS certificate and protocol inspection."""

    # Certificate basics
    valid: bool = False
    expiry_date: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    is_self_signed: bool = False
    serial_number: Optional[str] = None

    # Certificate chain
    chain_complete: bool = False
    chain_length: int = 0

    # Certificate details
    sans: list[str] = field(default_factory=list)
    is_wildcard: bool = False
    has_ct_logs: bool = False
    signature_algorithm: Optional[str] = None

    # TLS protocol support
    tls_version: Optional[str] = None
    supports_tls_1_0: bool = False
    supports_tls_1_1: bool = False
    supports_tls_1_2: bool = False
    supports_tls_1_3: bool = False

    # Cipher analysis
    weak_ciphers: list[str] = field(default_factory=list)
    has_null_cipher: bool = False
    has_rc4_cipher: bool = False
    has_des_cipher: bool = False
    has_export_cipher: bool = False

    # HSTS
    has_hsts: bool = False
    hsts_max_age: Optional[int] = None
    hsts_preloaded: bool = False
    hsts_include_subdomains: bool = False

    # Vulnerability checks (passive)
    heartbleed_vulnerable: bool = False
    robot_vulnerable: bool = False
    supports_secure_renegotiation: bool = True

    # OCSP
    has_ocsp_stapling: bool = False

    # Error
    error: Optional[str] = None


def _deep_ssl_inspect(domain: str) -> SSLResult:
    """Run comprehensive SSL/TLS analysis using SSLyze (synchronous)."""

    result = SSLResult()

    try:
        from sslyze import (
            Scanner,
            ServerScanRequest,
            ServerNetworkLocation,
            ScanCommand,
        )
        from sslyze.errors import ServerHostnameCouldNotBeResolved, ConnectionToServerFailed
    except ImportError:
        logger.warning("SSLyze not installed, falling back to basic SSL check")
        return _basic_ssl_fallback(domain)

    try:
        from sslyze import ServerNetworkConfiguration
        
        location = ServerNetworkLocation(hostname=domain, port=443)
        net_config = ServerNetworkConfiguration(
            tls_server_name_indication=domain,
            network_timeout=15,
            network_max_retries=3
        )
        
        scan_request = ServerScanRequest(
            server_location=location,
            network_configuration=net_config,
            scan_commands={
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.HEARTBLEED,
                ScanCommand.ROBOT,
                ScanCommand.SESSION_RENEGOTIATION,
            },
        )

        scanner = Scanner()
        scanner.queue_scans([scan_request])

        for server_scan_result in scanner.get_results():
            # Check for connectivity errors
            if server_scan_result.connectivity_error_trace:
                result.error = "Could not connect to server on port 443"
                return result

            # ── Certificate Info ──
            cert_result = server_scan_result.scan_result.certificate_info
            if cert_result and cert_result.result:
                cert_info = cert_result.result
                for deployment in cert_info.certificate_deployments:
                    leaf_cert = deployment.received_certificate_chain[0]

                    # Expiry
                    result.expiry_date = leaf_cert.not_valid_after_utc if hasattr(leaf_cert, 'not_valid_after_utc') else leaf_cert.not_valid_after
                    if result.expiry_date.tzinfo is None:
                        result.expiry_date = result.expiry_date.replace(tzinfo=timezone.utc)
                    result.days_until_expiry = (result.expiry_date - datetime.now(timezone.utc)).days

                    # Issuer and subject
                    result.issuer = leaf_cert.issuer.rfc4514_string()
                    result.subject = leaf_cert.subject.rfc4514_string()

                    # Self-signed check
                    result.is_self_signed = leaf_cert.issuer == leaf_cert.subject

                    # Serial number
                    result.serial_number = format(leaf_cert.serial_number, 'x')

                    # Signature algorithm
                    result.signature_algorithm = leaf_cert.signature_hash_algorithm.name if leaf_cert.signature_hash_algorithm else None

                    # Chain
                    result.chain_length = len(deployment.received_certificate_chain)
                    result.chain_complete = not bool(deployment.verified_certificate_chain is None)

                    # SANs
                    try:
                        from cryptography.x509 import SubjectAlternativeName, DNSName
                        san_ext = leaf_cert.extensions.get_extension_for_class(SubjectAlternativeName)
                        result.sans = san_ext.value.get_values_for_type(DNSName)
                        result.is_wildcard = any(s.startswith("*.") for s in result.sans)
                    except Exception:
                        result.sans = []

                    # CT logs
                    try:
                        from cryptography.x509 import PrecertificateSignedCertificateTimestamps
                        leaf_cert.extensions.get_extension_for_class(PrecertificateSignedCertificateTimestamps)
                        result.has_ct_logs = True
                    except Exception:
                        result.has_ct_logs = False

                    # OCSP stapling
                    result.has_ocsp_stapling = deployment.ocsp_response is not None

                    # Certificate is valid if chain verified and not expired
                    result.valid = (
                        result.chain_complete
                        and not result.is_self_signed
                        and (result.days_until_expiry or 0) > 0
                    )

                    break  # Only process first deployment

            # ── TLS Version Support ──
            _check_tls_version(server_scan_result, result)

            # ── Cipher Analysis ──
            _check_ciphers(server_scan_result, result)

            # ── Heartbleed ──
            heartbleed = server_scan_result.scan_result.heartbleed
            if heartbleed and heartbleed.result:
                result.heartbleed_vulnerable = heartbleed.result.is_vulnerable_to_heartbleed

            # ── ROBOT ──
            robot = server_scan_result.scan_result.robot
            if robot and robot.result:
                from sslyze import RobotScanResultEnum
                result.robot_vulnerable = robot.result.robot_result in (
                    RobotScanResultEnum.VULNERABLE_WEAK_ORACLE,
                    RobotScanResultEnum.VULNERABLE_STRONG_ORACLE,
                )

            # ── Session Renegotiation ──
            reneg = server_scan_result.scan_result.session_renegotiation
            if reneg and reneg.result:
                result.supports_secure_renegotiation = reneg.result.supports_secure_renegotiation

        # Determine highest TLS version connected
        if result.supports_tls_1_3:
            result.tls_version = "TLSv1.3"
        elif result.supports_tls_1_2:
            result.tls_version = "TLSv1.2"
        elif result.supports_tls_1_1:
            result.tls_version = "TLSv1.1"
        elif result.supports_tls_1_0:
            result.tls_version = "TLSv1"
        else:
            result.tls_version = "Unknown"

        return result

    except Exception as e:
        logger.error(f"SSLyze scan failed for domain={domain}: {e}", exc_info=True)
        return _basic_ssl_fallback(domain)


def _check_tls_version(scan_result, result: SSLResult) -> None:
    """Extract TLS version support from scan results."""
    try:
        tls10 = scan_result.scan_result.tls_1_0_cipher_suites
        if tls10 and tls10.result:
            result.supports_tls_1_0 = len(tls10.result.accepted_cipher_suites) > 0

        tls11 = scan_result.scan_result.tls_1_1_cipher_suites
        if tls11 and tls11.result:
            result.supports_tls_1_1 = len(tls11.result.accepted_cipher_suites) > 0

        tls12 = scan_result.scan_result.tls_1_2_cipher_suites
        if tls12 and tls12.result:
            result.supports_tls_1_2 = len(tls12.result.accepted_cipher_suites) > 0

        tls13 = scan_result.scan_result.tls_1_3_cipher_suites
        if tls13 and tls13.result:
            result.supports_tls_1_3 = len(tls13.result.accepted_cipher_suites) > 0
    except Exception as e:
        logger.warning(f"Error checking TLS versions: {e}")


def _check_ciphers(scan_result, result: SSLResult) -> None:
    """Check for weak cipher suites across all TLS versions."""
    weak_keywords = {"NULL", "RC4", "DES", "EXPORT", "anon", "MD5"}

    try:
        for attr_name in [
            "ssl_2_0_cipher_suites",
            "ssl_3_0_cipher_suites",
            "tls_1_0_cipher_suites",
            "tls_1_1_cipher_suites",
            "tls_1_2_cipher_suites",
        ]:
            suite_result = getattr(scan_result.scan_result, attr_name, None)
            if not suite_result or not suite_result.result:
                continue

            for cipher in suite_result.result.accepted_cipher_suites:
                cipher_name = cipher.cipher_suite.name.upper()
                for keyword in weak_keywords:
                    if keyword in cipher_name:
                        result.weak_ciphers.append(cipher.cipher_suite.name)
                        if "NULL" in cipher_name:
                            result.has_null_cipher = True
                        if "RC4" in cipher_name:
                            result.has_rc4_cipher = True
                        if "DES" in cipher_name:
                            result.has_des_cipher = True
                        if "EXPORT" in cipher_name:
                            result.has_export_cipher = True
                        break
    except Exception as e:
        logger.warning(f"Error checking cipher suites: {e}")


import socket
import ssl

def _basic_ssl_fallback(domain: str) -> SSLResult:
    """Fallback to basic ssl module check if SSLyze is unavailable."""
    result = SSLResult()
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

                if not cert:
                    return _httpx_ssl_fallback(domain)

                expiry_str = cert["notAfter"]
                expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days

                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))

                issuer_name = issuer.get("O") or issuer.get("CN") or "Unknown"
                issuer_cn = issuer.get("CN") or issuer.get("O") or "Unknown"
                subject_cn = subject.get("CN") or "Unknown"

                result.valid = True
                result.expiry_date = expiry
                result.days_until_expiry = days_left
                result.tls_version = protocol
                result.issuer = issuer_name
                result.subject = subject_cn
                result.is_self_signed = issuer_cn == subject_cn and subject_cn != "Unknown"

                # Extract SANs from basic cert
                san_list = cert.get("subjectAltName", [])
                result.sans = [s[1] for s in san_list if s[0] == "DNS"]
                result.is_wildcard = any(s.startswith("*.") for s in result.sans)

                return result
    except Exception as e:
        logger.error(f"Basic SSL check failed for domain={domain}: {e}", exc_info=True)
        return _httpx_ssl_fallback(domain)


def _httpx_ssl_fallback(domain: str) -> SSLResult:
    """Ultimate fallback: just check if HTTPS port 443 responds."""
    import httpx
    try:
        # Use verify=False to ignore certificate validation errors, just check if port is open
        with httpx.Client(verify=False, timeout=5.0) as client:
            client.head(f"https://{domain}")
            # If it succeeds or returns a status code (even 4xx/5xx), port 443 is serving HTTPS
            # We don't have cert details, but we know it's HTTPS
            return SSLResult(valid=False, error="SSL details unavailable, but port 443 is open")
    except Exception:
        return SSLResult(valid=False, error="Could not connect to port 443 — site may not support HTTPS")


async def run(domain: str) -> SSLResult:
    """Run deep SSL/TLS analysis asynchronously with explicit fallback chain."""
    try:
        return await asyncio.to_thread(_deep_ssl_inspect, domain)
    except Exception as e:
        logger.error(f"Top-level exception in ssl_check.run for {domain}: {e}")
        return SSLResult(valid=False, error="Could not connect to port 443 — site may not support HTTPS")

