"""
Parser for Nmap XML output via python-nmap.

Wraps python-nmap PortScanner and extracts structured port/service data.
"""

import asyncio
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Ports we scan — safe, well-known services only
SCAN_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    143,
    443,
    445,
    587,
    993,
    995,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
    8888,
    27017,
    9200,
]

SCAN_PORTS_STR = ",".join(str(p) for p in SCAN_PORTS)

# Port risk classification
CRITICAL_PORTS = {3306, 5432, 27017, 6379, 9200}  # Exposed databases
RED_PORTS = {21, 23, 3389, 5900}  # FTP, Telnet, RDP, VNC
AMBER_PORTS = {8080, 8443, 8888}  # Non-standard web ports


@dataclass
class NmapService:
    """A single discovered service from nmap scan."""

    port: int
    state: str  # open, closed, filtered
    protocol: str  # tcp, udp
    service_name: str
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    banner: str | None = None
    risk_level: str = "INFO"  # CRITICAL, RED, AMBER, GREEN, INFO


@dataclass
class NmapResult:
    """Parsed nmap scan results."""

    open_ports: list[int] = field(default_factory=list)
    services: list[NmapService] = field(default_factory=list)
    scan_info: str | None = None
    error: str | None = None


def _classify_port_risk(port: int) -> str:
    """Classify the risk level of an open port."""
    if port in CRITICAL_PORTS:
        return "CRITICAL"
    if port in RED_PORTS:
        return "RED"
    if port in AMBER_PORTS:
        return "AMBER"
    return "INFO"


def _run_nmap_sync(target_ip: str) -> NmapResult:
    """Run nmap scan synchronously (called via asyncio.to_thread)."""
    try:
        import nmap
    except ImportError:
        logger.error("python-nmap not installed")
        return NmapResult(error="python-nmap not available")

    try:
        scanner = nmap.PortScanner()

        # SAFE scan only: -sV for version detection, safe scripts, no SYN scan
        scanner.scan(
            hosts=target_ip,
            ports=SCAN_PORTS_STR,
            arguments=(
                "-sV "
                "--version-intensity 3 "
                "--script=banner,http-title,ssl-cert "
                "--script-args=unsafe=0 "
                "-T3 "
                "--host-timeout 30s"
            ),
        )

        result = NmapResult()

        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in sorted(ports):
                    port_info = scanner[host][proto][port]
                    state = port_info.get("state", "unknown")

                    if state != "open":
                        continue

                    service_name = port_info.get("name", "unknown")
                    product = port_info.get("product", "")
                    version = port_info.get("version", "")
                    extra = port_info.get("extrainfo", "")

                    # Get banner from script output if available
                    scripts = port_info.get("script", {})
                    banner = scripts.get("banner", "")

                    svc = NmapService(
                        port=port,
                        state=state,
                        protocol=proto,
                        service_name=service_name,
                        product=product or None,
                        version=version or None,
                        extra_info=extra or None,
                        banner=banner or None,
                        risk_level=_classify_port_risk(port),
                    )
                    result.services.append(svc)
                    result.open_ports.append(port)

        result.scan_info = f"Scanned {len(SCAN_PORTS)} ports on {target_ip}"
        return result

    except nmap.PortScannerError as e:
        logger.error(f"Nmap scan error for {target_ip}: {e}", exc_info=True)
        return NmapResult(error=f"Nmap scan failed: {e}")
    except Exception as e:
        logger.error(f"Nmap unexpected error for {target_ip}: {e}", exc_info=True)
        return NmapResult(error=f"Nmap error: {e}")


async def run_nmap_scan(target_ip: str) -> NmapResult:
    """Run nmap scan asynchronously."""
    return await asyncio.to_thread(_run_nmap_sync, target_ip)
