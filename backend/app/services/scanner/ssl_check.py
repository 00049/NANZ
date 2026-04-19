import asyncio
import logging
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class SSLResult:
    """Result of a passive certificate inspection."""

    valid: bool
    expiry_date: datetime | None
    days_until_expiry: int | None
    tls_version: str | None
    issuer: str | None
    is_self_signed: bool
    error: str | None = None


def _inspect_certificate(domain: str) -> SSLResult:
    """Inspect a certificate using Python ssl and socket modules."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

                expiry_str = cert["notAfter"]
                expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days

                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))

                issuer_name = issuer.get("O") or issuer.get("CN") or "Unknown"
                issuer_cn = issuer.get("CN") or issuer.get("O") or "Unknown"
                subject_cn = subject.get("CN") or "Unknown"

                return SSLResult(
                    valid=True,
                    expiry_date=expiry,
                    days_until_expiry=days_left,
                    tls_version=protocol,
                    issuer=issuer_name,
                    is_self_signed=issuer_cn == subject_cn and subject_cn != "Unknown",
                )
    except Exception as e:
        logger.error(f"SSL certificate inspection failed for domain={domain}: {e}", exc_info=True)
        return SSLResult(
            valid=False,
            expiry_date=None,
            days_until_expiry=None,
            tls_version=None,
            issuer=None,
            is_self_signed=False,
            error="SSL check unavailable",
        )


async def run(domain: str) -> SSLResult:
    """Connect to domain:443 and retrieve certificate details."""
    return await asyncio.to_thread(_inspect_certificate, domain)
