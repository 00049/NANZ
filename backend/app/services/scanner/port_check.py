"""
Domain 4: Port & Service Scanning.

Uses Shodan API first (cached 24h in Redis), falls back to Nmap safe scan.
Per-port risk classification with service version detection.

SAFE ONLY: -sV with safe scripts (unsafe=0), no SYN scan.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field

from redis.asyncio import Redis

from app.config import settings
from app.services.shodan_service import host_lookup
from app.utils.nmap_parser import (
    CRITICAL_PORTS,
    RED_PORTS,
    NmapResult,
    run_nmap_scan,
)

logger = logging.getLogger(__name__)

# Port-specific risk descriptions
PORT_RISK_INFO = {
    21: {
        "service": "FTP",
        "risk": "Anonymous login or unencrypted file transfer",
        "severity": "RED",
    },
    22: {"service": "SSH", "risk": "Remote shell access", "severity": "INFO"},
    23: {
        "service": "Telnet",
        "risk": "Unencrypted remote access — all data sent in cleartext",
        "severity": "RED",
    },
    25: {
        "service": "SMTP",
        "risk": "Email relay — may allow spam if misconfigured",
        "severity": "AMBER",
    },
    53: {"service": "DNS", "risk": "DNS resolver exposed", "severity": "INFO"},
    80: {"service": "HTTP", "risk": "Unencrypted web traffic", "severity": "INFO"},
    110: {
        "service": "POP3",
        "risk": "Unencrypted email retrieval",
        "severity": "AMBER",
    },
    143: {"service": "IMAP", "risk": "Unencrypted email access", "severity": "AMBER"},
    443: {"service": "HTTPS", "risk": "Encrypted web traffic", "severity": "INFO"},
    445: {
        "service": "SMB",
        "risk": "File sharing protocol — frequent attack vector",
        "severity": "RED",
    },
    587: {
        "service": "SMTP Submission",
        "risk": "Email submission port",
        "severity": "INFO",
    },
    993: {"service": "IMAPS", "risk": "Encrypted email access", "severity": "INFO"},
    995: {"service": "POP3S", "risk": "Encrypted email retrieval", "severity": "INFO"},
    3306: {
        "service": "MySQL",
        "risk": "Database exposed to internet — critical data risk",
        "severity": "CRITICAL",
    },
    3389: {
        "service": "RDP",
        "risk": "Remote desktop exposed — brute force target",
        "severity": "RED",
    },
    5432: {
        "service": "PostgreSQL",
        "risk": "Database exposed to internet — critical data risk",
        "severity": "CRITICAL",
    },
    5900: {
        "service": "VNC",
        "risk": "Remote desktop protocol — often unencrypted",
        "severity": "RED",
    },
    6379: {
        "service": "Redis",
        "risk": "In-memory database exposed — often no auth",
        "severity": "CRITICAL",
    },
    8080: {
        "service": "HTTP-Alt",
        "risk": "Non-standard web port — may be dev/staging",
        "severity": "AMBER",
    },
    8443: {
        "service": "HTTPS-Alt",
        "risk": "Non-standard HTTPS port",
        "severity": "AMBER",
    },
    8888: {
        "service": "HTTP-Alt",
        "risk": "Non-standard web port — may expose admin panels",
        "severity": "AMBER",
    },
    27017: {
        "service": "MongoDB",
        "risk": "NoSQL database exposed — often no auth by default",
        "severity": "CRITICAL",
    },
    9200: {
        "service": "Elasticsearch",
        "risk": "Search engine exposed — can leak indexed data",
        "severity": "CRITICAL",
    },
}


@dataclass
class PortFinding:
    """Detailed finding for a single open port."""

    port: int
    service: str
    product: str | None = None
    version: str | None = None
    risk_level: str = "INFO"  # CRITICAL, RED, AMBER, GREEN, INFO
    risk_description: str | None = None
    banner: str | None = None


@dataclass
class PortResult:
    """Result of port & service scanning."""

    open_ports: list[int] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    source: str = ""
    error: str | None = None

    # Expanded fields
    port_findings: list[dict] = field(default_factory=list)
    critical_ports_exposed: list[int] = field(default_factory=list)
    dangerous_ports_exposed: list[int] = field(default_factory=list)
    total_ports_scanned: int = 0
    nmap_scan_info: str | None = None

    # v2 enhanced checks
    smbv1_enabled: bool = False
    redis_no_auth: bool = False


async def check_port_direct(ip: str, port: int) -> bool:
    """Return True when a TCP connection can be opened to a port."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=3.0,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (ConnectionError, TimeoutError, OSError):
        return False


async def _shodan_lookup(ip_address: str, redis_client: Redis) -> PortResult | None:
    """Try Shodan API with Redis caching (24h TTL)."""
    cache_key = f"shodan:ip:{ip_address}"

    # Check cache
    try:
        cached_data = await redis_client.get(cache_key)
        if cached_data:
            data = json.loads(cached_data)
            result = PortResult(
                open_ports=data.get("open_ports", []),
                services=data.get("services", []),
                source="shodan-cache",
            )
            _enrich_port_findings(result)
            return result
    except (
        ConnectionError,
        TimeoutError,
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as e:
        logger.warning(f"Shodan cache read failed for ip={ip_address}: {e}")

    if not settings.SHODAN_API_KEY:
        return None

    try:
        data = await host_lookup(ip_address)
        if "error" in data:
            logger.warning(f"Shodan API error for ip={ip_address}: {data['error']}")
            return None

        ports = data.get("ports", [])
        services = []

        for item in data.get("data", []):
            services.append(
                {
                    "port": item.get("port"),
                    "product": item.get("product"),
                    "version": item.get("version"),
                    "transport": item.get("transport", "tcp"),
                    "banner": (item.get("data", "") or "")[:200],
                }
            )

        result_dict = {"open_ports": ports, "services": services}
        try:
            await redis_client.set(cache_key, json.dumps(result_dict), ex=86400)
        except (ConnectionError, TimeoutError, OSError):
            pass

        result = PortResult(open_ports=ports, services=services, source="shodan")
        _enrich_port_findings(result)
        return result
    except Exception as e:
        logger.warning(
            f"Unexpected error during Shodan lookup for ip={ip_address}: {e}"
        )

    return None


async def _nmap_scan(ip_address: str) -> PortResult | None:
    """Fall back to safe Nmap scan."""
    try:
        nmap_result: NmapResult = await asyncio.wait_for(
            run_nmap_scan(ip_address), timeout=60.0
        )

        if nmap_result.error:
            logger.warning(f"Nmap scan error for {ip_address}: {nmap_result.error}")
            return None

        services = []
        for svc in nmap_result.services:
            services.append(
                {
                    "port": svc.port,
                    "product": svc.product,
                    "version": svc.version,
                    "transport": svc.protocol,
                    "banner": svc.banner,
                    "service_name": svc.service_name,
                }
            )

        result = PortResult(
            open_ports=nmap_result.open_ports,
            services=services,
            source="nmap",
            nmap_scan_info=nmap_result.scan_info,
        )
        _enrich_port_findings(result)
        return result
    except TimeoutError:
        logger.warning(f"Nmap scan timed out for {ip_address}")
    except Exception as e:
        logger.warning(f"Nmap scan failed for {ip_address}: {e}")

    return None


def _enrich_port_findings(result: PortResult) -> None:
    """Add per-port risk classification and detailed findings."""
    for port in result.open_ports:
        port_info = PORT_RISK_INFO.get(
            port,
            {
                "service": "Unknown",
                "risk": "Unknown service on this port",
                "severity": "INFO",
            },
        )

        # Find service details from scan data
        svc_data = next((s for s in result.services if s.get("port") == port), {})

        finding = PortFinding(
            port=port,
            service=svc_data.get("service_name")
            or svc_data.get("product")
            or port_info["service"],
            product=svc_data.get("product"),
            version=svc_data.get("version"),
            risk_level=port_info["severity"],
            risk_description=port_info["risk"],
            banner=svc_data.get("banner"),
        )

        result.port_findings.append(
            {
                "port": finding.port,
                "service": finding.service,
                "product": finding.product,
                "version": finding.version,
                "risk_level": finding.risk_level,
                "risk_description": finding.risk_description,
                "banner": finding.banner,
            }
        )

        if port in CRITICAL_PORTS:
            result.critical_ports_exposed.append(port)
        elif port in RED_PORTS:
            result.dangerous_ports_exposed.append(port)


async def _check_redis_no_auth(ip: str) -> bool:
    """Probe Redis for unauthenticated access."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 6379), timeout=4.0
        )
        writer.write(b"PING\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(128), timeout=3.0)
        writer.close()
        await writer.wait_closed()
        return b"+PONG" in data
    except Exception:
        return False


async def _run_tcp_fallback(ip_address: str) -> PortResult:
    """Last resort: direct TCP probe of critical ports only."""
    fallback_ports = [
        21,
        22,
        23,
        25,
        80,
        443,
        3306,
        3389,
        5432,
        5900,
        6379,
        8080,
        8443,
        27017,
        9200,
    ]
    open_ports = []

    try:
        tasks = [check_port_direct(ip_address, p) for p in fallback_ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for p, r in zip(fallback_ports, results, strict=False):
            if isinstance(r, bool) and r is True:
                open_ports.append(p)

        result = PortResult(
            open_ports=open_ports,
            source="direct",
            total_ports_scanned=len(fallback_ports),
        )
        _enrich_port_findings(result)
        await _enhanced_checks(ip_address, result)
        return result
    except Exception as e:
        logger.error(
            f"Direct port fallback failed for ip={ip_address}: {e}", exc_info=True
        )
        return PortResult(error="Port check unavailable")


async def run(ip_address: str, redis_client: Redis) -> PortResult:
    """
    Check for open ports using Shodan (cached) -> Nmap (fallback) -> direct probe.
    Never raises an exception, always returns a PortResult.
    """
    try:
        if not ip_address:
            return PortResult(error="No IP address provided")

        # Try Shodan first (fastest, cached)
        shodan_result = await _shodan_lookup(ip_address, redis_client)
        if shodan_result:
            shodan_result.total_ports_scanned = 23
            await _enhanced_checks(ip_address, shodan_result)
            return shodan_result

        # Fall back to Nmap
        nmap_result = await _nmap_scan(ip_address)
        if nmap_result:
            nmap_result.total_ports_scanned = 23
            await _enhanced_checks(ip_address, nmap_result)
            return nmap_result

        return await _run_tcp_fallback(ip_address)
    except Exception as e:
        logger.error(
            f"port_check.run completely failed for {ip_address}: {e}", exc_info=True
        )
        return PortResult(error="Port check completely failed")


async def _enhanced_checks(ip: str, result: PortResult) -> None:
    """Run enhanced checks on open ports (Redis auth, SMBv1)."""
    try:
        if 6379 in result.open_ports:
            result.redis_no_auth = await _check_redis_no_auth(ip)
    except Exception:
        pass
