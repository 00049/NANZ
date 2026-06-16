"""
CORS Misconfiguration Detection Module — passive Origin header analysis.

Tests: wildcard CORS, reflected origin, null origin, credentials with wildcard.
All checks are passive GET requests with spoofed Origin headers.
"""

import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

TEST_PATHS = ["", "/api", "/api/v1", "/graphql", "/rest"]
EVIL_ORIGIN = "https://evil-attacker-site.com"


@dataclass
class CORSResult:
    wildcard_cors: bool = False
    reflected_origin: bool = False
    null_origin_allowed: bool = False
    credentials_with_wildcard: bool = False
    tested_endpoints: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    error: str | None = None


async def run(url: str) -> CORSResult:
    """
    Detect CORS misconfiguration by sending GET requests with spoofed Origin headers.
    Tests multiple endpoints for wildcard, reflected origin, null origin, and
    credentials-with-wildcard misconfigurations.
    """
    result = CORSResult()
    base_url = url.rstrip("/")

    try:
        async with httpx.AsyncClient(
            timeout=8.0,
            follow_redirects=True,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
        ) as client:

            for path in TEST_PATHS:
                test_url = f"{base_url}{path}" if path else base_url
                result.tested_endpoints.append(test_url)

                # Test 1: Evil origin
                try:
                    res = await client.get(test_url, headers={"Origin": EVIL_ORIGIN})
                    acao = res.headers.get("access-control-allow-origin", "")
                    acac = res.headers.get(
                        "access-control-allow-credentials", ""
                    ).lower()
                    content_type = res.headers.get("content-type", "").lower()
                    is_api = (
                        "json" in content_type or "xml" in content_type or path != ""
                    )

                    # Wildcard CORS
                    if acao == "*":
                        if acac == "true":
                            result.credentials_with_wildcard = True
                            result.findings.append(
                                {
                                    "type": "cors_credentials_wildcard",
                                    "endpoint": test_url,
                                    "severity": "CRITICAL",
                                    "detail": "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                                }
                            )
                        elif is_api:
                            result.wildcard_cors = True
                            result.findings.append(
                                {
                                    "type": "cors_wildcard_api",
                                    "endpoint": test_url,
                                    "severity": "RED",
                                    "detail": "Wildcard CORS on API endpoint",
                                }
                            )
                        else:
                            result.wildcard_cors = True
                            result.findings.append(
                                {
                                    "type": "cors_wildcard_html",
                                    "endpoint": test_url,
                                    "severity": "AMBER",
                                    "detail": "Wildcard CORS on HTML page",
                                }
                            )

                    # Reflected origin
                    elif acao == EVIL_ORIGIN:
                        result.reflected_origin = True
                        result.findings.append(
                            {
                                "type": "cors_reflected_origin",
                                "endpoint": test_url,
                                "severity": "RED",
                                "detail": f"Origin {EVIL_ORIGIN} reflected back in ACAO header",
                            }
                        )

                except Exception as e:
                    logger.debug(f"CORS evil origin test failed for {test_url}: {e}")

                # Test 2: Null origin
                try:
                    res = await client.get(test_url, headers={"Origin": "null"})
                    acao = res.headers.get("access-control-allow-origin", "")

                    if acao == "null":
                        result.null_origin_allowed = True
                        result.findings.append(
                            {
                                "type": "cors_null_origin",
                                "endpoint": test_url,
                                "severity": "RED",
                                "detail": "Null origin allowed — sandboxed iframes can read responses",
                            }
                        )

                except Exception as e:
                    logger.debug(f"CORS null origin test failed for {test_url}: {e}")

            # Deduplicate findings by type (keep worst severity)
            seen_types = set()
            unique_findings = []
            for f in result.findings:
                if f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    unique_findings.append(f)
            result.findings = unique_findings

    except Exception as e:
        logger.error(f"CORS check failed: {e}", exc_info=True)
        result.error = str(e)

    return result
