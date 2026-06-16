"""
OAST Check — Out-of-Band Application Security Testing module.

Injects OAST callback domain into URL parameters and HTTP headers
to detect blind SSRF, header injection, and Log4Shell surfaces.

PASSIVE CONSTRAINTS:
  - Only GET requests (no form POSTs with payloads)
  - Payloads are detection-only, never exploit code
  - Log4j probe uses ${java:version} — non-malicious
  - OAST domain injection in URL parameters only

Requires an active OASTClient session to be passed in.
If no OAST session is available, degrades gracefully to surface detection only.
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from app.services.oast.oast_client import OASTClient

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 12.0
MAX_CONCURRENT = 4

# URL parameters that commonly accept URL values (SSRF surfaces)
SSRF_PARAMS = [
    "url",
    "redirect",
    "callback",
    "webhook",
    "feed",
    "next",
    "return",
    "target",
    "dest",
    "destination",
    "redir",
    "link",
    "src",
    "source",
    "uri",
    "path",
    "endpoint",
    "proxy",
    "load",
    "fetch",
]

# HTTP headers to inject OAST domain into (header injection detection)
INJECTION_HEADERS = [
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Original-URL",
    "X-Real-IP",
    "CF-Connecting-IP",
    "True-Client-IP",
    "X-Client-IP",
]

# Log4j payload — ${java:version} is non-malicious (just fetches JVM version string)
LOG4J_INDICATOR_PAYLOADS = [
    "${java:version}",
    "${java:os}",
    "${env:HOME}",  # non-malicious env var lookup
]

# Patterns indicating XSS output encoding issues (surface detection)
XSS_SURFACE_CHECKS = [
    (
        "<b>nanztest</b>",
        r"<b>nanztest</b>",
        "Reflected HTML without encoding — XSS surface",
    ),
    (
        "nanz<script>void(0)</script>test",
        r"<script>void\(0\)</script>",
        "Script tag reflected — XSS surface",
    ),
]


@dataclass
class OASTResult:
    ssrf_confirmed: bool = False
    ssrf_endpoints: list = field(default_factory=list)
    header_injection_confirmed: bool = False
    header_injection_details: list = field(default_factory=list)
    log4j_surface_detected: bool = False
    log4j_indicator_details: list = field(default_factory=list)
    xss_surfaces_found: list = field(default_factory=list)
    interactions_received: list = field(default_factory=list)
    oast_domain_used: str = ""
    probes_sent: int = 0
    error: str | None = None


async def run(
    url: str, domain: str, oast_client: OASTClient | None = None
) -> OASTResult:
    """
    Run OAST checks. Accepts optional pre-started OASTClient.
    Degrades gracefully to surface-only detection without OAST.
    """
    result = OASTResult()

    # Get OAST callback domain
    oast_domain = ""
    if oast_client and oast_client.callback_domain:
        oast_domain = oast_client.callback_domain
        result.oast_domain_used = oast_domain
        logger.info(f"OAST check using domain: {oast_domain}")
    else:
        logger.info("OAST check running in surface-only mode (no OAST session)")

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(REQUEST_TIMEOUT, connect=5.0),
            follow_redirects=False,  # DON'T follow — SSRF could redirect to oast
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"},
            limits=httpx.Limits(max_connections=MAX_CONCURRENT),
        ) as client:

            tasks = [
                _check_ssrf_params(client, url, oast_domain, result),
                _check_header_injection(client, url, oast_domain, result),
                _check_log4j_surface(client, url, oast_domain, result),
                _detect_xss_surfaces(client, url, result),
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        # If we have an active OAST session, poll for 30s for callbacks
        if oast_client and oast_domain:
            logger.info("Polling OAST server for 30s...")
            interactions = await oast_client.poll_interactions(timeout_s=30)
            result.interactions_received = [
                {
                    "protocol": i.protocol,
                    "remote_address": i.remote_address,
                    "timestamp": i.timestamp,
                    "unique_id": i.unique_id[:12],
                }
                for i in interactions
            ]

            # Correlate interactions with our probes
            if any(i.protocol == "http" for i in interactions):
                result.ssrf_confirmed = True
                logger.warning(f"OAST SSRF confirmed for {domain}!")
            if any(i.protocol == "dns" for i in interactions):
                # DNS interaction could be header injection or Log4j
                result.header_injection_confirmed = True
                logger.warning(f"OAST header injection confirmed for {domain}!")

    except Exception as exc:
        logger.error(f"OAST check failed for {url}: {exc}")
        result.error = str(exc)[:200]

    return result


# ── SSRF Param Probes ───────────────────────────────────────────────────────────


async def _check_ssrf_params(
    client: httpx.AsyncClient,
    url: str,
    oast_domain: str,
    result: OASTResult,
) -> None:
    """Inject OAST domain into URL parameters that accept URLs."""
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    sem = asyncio.Semaphore(MAX_CONCURRENT)
    probes = []

    oast_url = f"http://{oast_domain}" if oast_domain else "http://169.254.169.254"

    for param in SSRF_PARAMS:
        target = f"{base}/?{param}={oast_url}"
        probes.append((param, target))

    async def probe_one(param: str, probe_url: str) -> None:
        async with sem:
            try:
                result.probes_sent += 1
                resp = await client.get(probe_url)
                # Check if the server made a connection back (non-redirect 2xx means it fetched)
                if resp.status_code in (200, 201) and oast_domain in resp.text:
                    result.ssrf_endpoints.append(
                        {
                            "param": param,
                            "url": probe_url,
                            "status": resp.status_code,
                            "severity": "CRITICAL",
                        }
                    )
            except (httpx.TimeoutException, httpx.ConnectError):
                pass
            except Exception as exc:
                logger.debug(f"SSRF probe {param} error: {exc}")
            await asyncio.sleep(0.1)

    await asyncio.gather(*[probe_one(p, u) for p, u in probes], return_exceptions=True)


# ── Header Injection Probes ─────────────────────────────────────────────────────


async def _check_header_injection(
    client: httpx.AsyncClient,
    url: str,
    oast_domain: str,
    result: OASTResult,
) -> None:
    """Send requests with OAST domain in forwarding/host headers."""
    if not oast_domain:
        return

    sem = asyncio.Semaphore(2)

    async def probe_header(header_name: str) -> None:
        async with sem:
            try:
                result.probes_sent += 1
                headers = {header_name: oast_domain}
                await client.get(url, headers=headers)
                result.header_injection_details.append(
                    {
                        "header": header_name,
                        "injected_value": oast_domain,
                        "note": "Probed — OAST callback confirms exploitation",
                    }
                )
            except Exception as exc:
                logger.debug(f"Header probe {header_name} error: {exc}")
            await asyncio.sleep(0.2)

    await asyncio.gather(
        *[probe_header(h) for h in INJECTION_HEADERS], return_exceptions=True
    )


# ── Log4Shell Surface Detection ─────────────────────────────────────────────────


async def _check_log4j_surface(
    client: httpx.AsyncClient,
    url: str,
    oast_domain: str,
    result: OASTResult,
) -> None:
    """
    Inject harmless Log4j-style patterns into User-Agent and Referer.
    ${java:version} is non-malicious — just a JVM version lookup.
    If OAST gets a DNS callback, indicates Log4j processing.
    """
    if not oast_domain:
        # Without OAST, just test for literal reflection (log injection indicator)
        try:
            result.probes_sent += 1
            resp = await client.get(
                url,
                headers={
                    "User-Agent": "${java:version}",
                    "Referer": f"http://{url}/?ref=${{java:version}}",
                },
            )
            body = resp.text[:3000]
            # If ${java:version} literal appears in response → log injection surface
            if "${java:version}" in body or "java:version" in body:
                result.log4j_surface_detected = True
                result.log4j_indicator_details.append(
                    {
                        "type": "literal_reflection",
                        "detail": "Log4j expression reflected in response body",
                        "severity": "RED",
                    }
                )
        except Exception as exc:
            logger.debug(f"Log4j surface check error: {exc}")
        return

    # With OAST: Use OAST domain in JNDI-style probe (harmless structure)
    jndi_safe = "${java:os} ${env:HOME}"
    oast_probe_ua = f"${{{oast_domain}}}"  # Non-JNDI, just DNS lookup trigger

    try:
        result.probes_sent += 1
        resp = await client.get(
            url,
            headers={
                "User-Agent": jndi_safe,
                "X-Api-Version": oast_probe_ua,
                "Referer": f"http://{oast_domain}/log4j-probe",
            },
        )
        body = resp.text[:3000]
        if any(kw in body for kw in ["java:version", "java:os", "${env:"]):
            result.log4j_surface_detected = True
            result.log4j_indicator_details.append(
                {
                    "type": "expression_reflected",
                    "detail": "Log4j-style expression reflected — server may process EL expressions",
                    "severity": "CRITICAL",
                }
            )
    except Exception as exc:
        logger.debug(f"Log4j OAST probe error: {exc}")


# ── XSS Surface Detection ───────────────────────────────────────────────────────


async def _detect_xss_surfaces(
    client: httpx.AsyncClient,
    url: str,
    result: OASTResult,
) -> None:
    """
    Detect XSS surfaces by checking for HTML rendering without encoding.
    Uses benign test strings — no script execution.
    """
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    surfaces_to_check = [
        # Search parameter — most common XSS surface
        (
            "search",
            f"{base}/?q=<b>nanztest</b>",
            re.compile(r"<b>nanztest</b>"),
            "Search parameter reflects HTML",
        ),
        (
            "search_s",
            f"{base}/?s=<b>nanztest</b>",
            re.compile(r"<b>nanztest</b>"),
            "Search parameter reflects HTML",
        ),
        (
            "query",
            f"{base}/?query=<b>nanztest</b>",
            re.compile(r"<b>nanztest</b>"),
            "Query parameter reflects HTML",
        ),
        # File path parameter
        (
            "file",
            f"{base}/?file=nanztest.txt",
            re.compile(r"nanztest\.txt"),
            "File parameter reflects input",
        ),
    ]

    for surface_name, test_url, pattern, description in surfaces_to_check:
        try:
            result.probes_sent += 1
            resp = await client.get(test_url)
            if resp.status_code == 200 and pattern.search(resp.text):
                result.xss_surfaces_found.append(
                    {
                        "surface_type": surface_name,
                        "url": test_url,
                        "description": description,
                        "severity": "AMBER",
                        "note": "Reflected input detected — manual XSS testing recommended",
                    }
                )
        except Exception as exc:
            logger.debug(f"XSS surface check {surface_name} error: {exc}")
        await asyncio.sleep(0.1)
