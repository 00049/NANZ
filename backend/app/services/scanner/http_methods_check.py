"""
HTTP Methods Detection Module — checks for dangerous methods enabled on server.

Checks: OPTIONS Allow header for TRACE/CONNECT/DELETE/PUT/PATCH.
Verifies TRACE reflection (XST attack) with actual TRACE request.
"""

import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

DANGEROUS_METHODS = {"TRACE", "CONNECT"}
RISKY_METHODS = {"DELETE", "PUT"}
INFO_METHODS = {"PATCH"}
TEST_PATHS = ["", "/api/"]


@dataclass
class HTTPMethodsResult:
    allowed_methods: list[str] = field(default_factory=list)
    dangerous_methods: list[str] = field(default_factory=list)
    trace_enabled: bool = False
    trace_reflected: bool = False
    tested_endpoints: list[str] = field(default_factory=list)
    error: str | None = None


async def run(url: str) -> HTTPMethodsResult:
    """
    Detect dangerous HTTP methods by sending OPTIONS request and parsing Allow header.
    Verifies TRACE reflection with actual TRACE request.
    """
    result = HTTPMethodsResult()
    base_url = url.rstrip("/")

    try:
        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
        ) as client:

            all_methods = set()

            for path in TEST_PATHS:
                test_url = f"{base_url}{path}" if path else base_url
                result.tested_endpoints.append(test_url)

                try:
                    res = await client.options(test_url)
                    allow = res.headers.get("allow", "")
                    if allow:
                        methods = {m.strip().upper() for m in allow.split(",")}
                        all_methods.update(methods)
                except Exception as e:
                    logger.debug(f"OPTIONS request failed for {test_url}: {e}")

            result.allowed_methods = sorted(all_methods)

            # Identify dangerous methods
            for method in all_methods:
                if method in DANGEROUS_METHODS:
                    result.dangerous_methods.append(method)
                elif method in RISKY_METHODS:
                    result.dangerous_methods.append(method)

            # Check if TRACE is actually enabled
            if "TRACE" in all_methods:
                result.trace_enabled = True

                # Verify TRACE reflection (XST attack)
                try:
                    trace_res = await client.request(
                        "TRACE",
                        base_url,
                        headers={"X-ShieldCheck-Test": "xst-verify-probe"},
                    )
                    if "xst-verify-probe" in trace_res.text:
                        result.trace_reflected = True
                except Exception as e:
                    logger.debug(f"TRACE verification failed: {e}")

    except Exception as e:
        logger.error(f"HTTP methods check failed: {e}", exc_info=True)
        result.error = str(e)

    return result
