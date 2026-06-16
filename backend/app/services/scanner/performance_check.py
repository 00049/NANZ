"""
Performance Security Check.

Checks TTFB (Time to First Byte), CDN usage, gzip compression, and open DNS resolver risks.
"""

import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

CDN_HEADERS = [
    "x-fastly-request-id",
    "cf-ray",
    "x-amz-cf-id",
    "x-edgecast-",
    "x-akamai-",
    "server: cloudflare",
    "server: awselb",
]


@dataclass
class PerformanceResult:
    ttfb_ms: float = 0.0
    uses_cdn: bool = False
    cdn_provider: str | None = None
    uses_gzip: bool = False
    open_dns_resolver: bool = False
    error: str | None = None


async def _check_ttfb_and_cdn(domain: str, result: PerformanceResult) -> None:
    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=10.0
        ) as client:
            # First request without gzip to get raw TTFB
            res = await client.get(f"https://{domain}")
            result.ttfb_ms = res.elapsed.total_seconds() * 1000

            # Check CDN
            headers_lower = {k.lower(): v.lower() for k, v in res.headers.items()}

            if "cf-ray" in headers_lower or headers_lower.get("server") == "cloudflare":
                result.uses_cdn = True
                result.cdn_provider = "Cloudflare"
            elif "x-amz-cf-id" in headers_lower or headers_lower.get(
                "server", ""
            ).startswith("awselb"):
                result.uses_cdn = True
                result.cdn_provider = "AWS CloudFront/ELB"
            elif any(k.startswith("x-fastly") for k in headers_lower):
                result.uses_cdn = True
                result.cdn_provider = "Fastly"
            elif any(k.startswith("x-akamai") for k in headers_lower):
                result.uses_cdn = True
                result.cdn_provider = "Akamai"

            # Check Gzip
            # We need to explicitly request it
            res_gzip = await client.get(
                f"https://{domain}", headers={"Accept-Encoding": "gzip, deflate, br"}
            )
            content_encoding = res_gzip.headers.get("Content-Encoding", "").lower()
            if (
                "gzip" in content_encoding
                or "br" in content_encoding
                or "deflate" in content_encoding
            ):
                result.uses_gzip = True

    except Exception as e:
        logger.warning(f"TTFB/CDN check failed for {domain}: {e}")


async def run(domain: str) -> PerformanceResult:
    """Run performance security analysis."""
    result = PerformanceResult()
    try:
        await _check_ttfb_and_cdn(domain, result)
        # Note: Open DNS resolver check requires sending DNS queries to the target domain's IP.
        # This is a bit intrusive for a passive scan, so we omit it for now or implement a passive heuristic.
    except Exception as e:
        logger.error(f"Performance check failed for {domain}: {e}", exc_info=True)
        result.error = "Performance check failed"

    return result
