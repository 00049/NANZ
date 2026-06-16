"""
WAF/CDN Detection Module — passive header, CNAME, and ASN analysis.

Detects: Cloudflare, AWS WAF/CloudFront, Akamai, Fastly, Sucuri,
Imperva/Incapsula, Azure Front Door, Nginx proxy, Vercel, Netlify.
Result is used by orchestrator to adjust severity of header findings.
"""

import logging
from dataclasses import dataclass, field

import dns.resolver
import httpx

logger = logging.getLogger(__name__)

# Known CDN/WAF ASN numbers
CDN_ASN_MAP = {
    "13335": "Cloudflare",
    "16509": "AWS",
    "20940": "Akamai",
    "54113": "Fastly",
    "8075": "Microsoft Azure",
    "15169": "Google Cloud",
    "14618": "AWS",
    "209242": "Cloudflare",
}

# CNAME patterns that indicate CDN/WAF
CNAME_PATTERNS = {
    "cloudflare": "Cloudflare",
    "cloudfront.net": "AWS CloudFront",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "sucuri": "Sucuri",
    "incapsula": "Imperva",
    "azurefd.net": "Azure Front Door",
    "azureedge.net": "Azure CDN",
    "vercel": "Vercel",
    "netlify": "Netlify",
    "edgekey.net": "Akamai",
    "edgesuite.net": "Akamai",
    "amazonaws.com": "AWS",
    "googleusercontent.com": "Google Cloud",
    "wpengine.com": "WP Engine",
}

# Response header signatures for WAF/CDN detection
HEADER_SIGNATURES = {
    "cf-ray": ("Cloudflare", "waf"),
    "cf-cache-status": ("Cloudflare", "cdn"),
    "x-amz-cf-id": ("AWS CloudFront", "cdn"),
    "x-amz-cf-pop": ("AWS CloudFront", "cdn"),
    "x-cache": ("AWS CloudFront", "cdn"),  # "Hit from cloudfront"
    "x-akamai-transformed": ("Akamai", "cdn"),
    "akamai-origin-hop": ("Akamai", "cdn"),
    "x-sucuri-id": ("Sucuri", "waf"),
    "x-sucuri-cache": ("Sucuri", "waf"),
    "x-iinfo": ("Imperva", "waf"),
    "x-cdn": ("Imperva", "cdn"),  # "Incapsula"
    "x-azure-ref": ("Azure Front Door", "cdn"),
    "x-fd-healthprobe": ("Azure Front Door", "cdn"),
    "x-vercel-id": ("Vercel", "cdn"),
    "x-nf-request-id": ("Netlify", "cdn"),
    "x-fastly-request-id": ("Fastly", "cdn"),
}

SERVER_PATTERNS = {
    "cloudflare": ("Cloudflare", "waf"),
    "amazons3": ("AWS S3", "cdn"),
    "akamaighost": ("Akamai", "cdn"),
    "netlify": ("Netlify", "cdn"),
    "vercel": ("Vercel", "cdn"),
    "sucuri": ("Sucuri", "waf"),
    "imunify360": ("Imunify360", "waf"),
}


@dataclass
class WAFResult:
    waf_detected: bool = False
    waf_provider: str | None = None
    cdn_detected: bool = False
    cdn_provider: str | None = None
    is_behind_proxy: bool = False
    detection_method: str = ""
    all_detections: list[dict] = field(default_factory=list)
    error: str | None = None


async def _check_headers(url: str) -> list[dict]:
    """Detect WAF/CDN from response headers."""
    detections = []
    try:
        async with httpx.AsyncClient(
            timeout=8.0, follow_redirects=True, verify=False
        ) as client:
            res = await client.get(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                },
            )

            response_headers = {k.lower(): v for k, v in res.headers.items()}

            # Check specific header signatures
            for header_key, (provider, detection_type) in HEADER_SIGNATURES.items():
                if header_key in response_headers:
                    detections.append(
                        {
                            "provider": provider,
                            "type": detection_type,
                            "method": f"header:{header_key}",
                            "value": response_headers[header_key][:100],
                        }
                    )

            # Check Server header patterns
            server = response_headers.get("server", "").lower()
            for pattern, (provider, detection_type) in SERVER_PATTERNS.items():
                if pattern in server:
                    detections.append(
                        {
                            "provider": provider,
                            "type": detection_type,
                            "method": f"server:{pattern}",
                        }
                    )

            # Check for Via header (proxy indicator)
            via = response_headers.get("via", "")
            if via:
                detections.append(
                    {
                        "provider": "Proxy",
                        "type": "proxy",
                        "method": "header:via",
                        "value": via[:100],
                    }
                )

    except Exception as e:
        logger.debug(f"WAF header check error: {e}")

    return detections


def _check_cname(domain: str) -> list[dict]:
    """Detect CDN/WAF from CNAME records."""
    detections = []
    try:
        answers = dns.resolver.resolve(domain, "CNAME")
        for rdata in answers:
            cname_target = str(rdata.target).lower().rstrip(".")
            for pattern, provider in CNAME_PATTERNS.items():
                if pattern in cname_target:
                    detections.append(
                        {
                            "provider": provider,
                            "type": "cdn",
                            "method": f"cname:{cname_target}",
                        }
                    )
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        Exception,
    ):
        pass

    return detections


async def _check_asn(ip_address: str | None) -> list[dict]:
    """Detect CDN from IP ASN lookup."""
    detections = []
    if not ip_address:
        return detections

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            res = await client.get(f"https://ipapi.co/{ip_address}/json/")
            if res.status_code == 200:
                data = res.json()
                asn = str(data.get("asn", "")).replace("AS", "")
                org = data.get("org", "")

                if asn in CDN_ASN_MAP:
                    detections.append(
                        {
                            "provider": CDN_ASN_MAP[asn],
                            "type": "cdn",
                            "method": f"asn:{asn}",
                            "org": org,
                        }
                    )
                else:
                    # Check org name for CDN keywords
                    org_lower = org.lower()
                    for keyword, provider in CNAME_PATTERNS.items():
                        if keyword in org_lower:
                            detections.append(
                                {
                                    "provider": provider,
                                    "type": "cdn",
                                    "method": f"asn_org:{org}",
                                }
                            )
                            break
    except Exception as e:
        logger.debug(f"WAF ASN check error: {e}")

    return detections


async def run(url: str, domain: str, ip_address: str | None = None) -> WAFResult:
    """
    Detect WAF and CDN presence using headers, CNAME, and ASN analysis.

    This module runs BEFORE other scan modules so its result can be
    used to adjust severity of header-related findings.
    """
    try:
        all_detections = []

        # 1. Header-based detection
        header_detections = await _check_headers(url)
        all_detections.extend(header_detections)

        # 2. CNAME-based detection
        cname_detections = _check_cname(domain)
        all_detections.extend(cname_detections)

        # 3. ASN-based detection
        asn_detections = await _check_asn(ip_address)
        all_detections.extend(asn_detections)

        # Determine WAF and CDN providers
        waf_providers = [
            d["provider"] for d in all_detections if d.get("type") == "waf"
        ]
        cdn_providers = [
            d["provider"] for d in all_detections if d.get("type") == "cdn"
        ]
        proxy_detected = any(d.get("type") == "proxy" for d in all_detections)

        waf_detected = len(waf_providers) > 0
        cdn_detected = len(cdn_providers) > 0

        # Pick primary provider
        waf_provider = waf_providers[0] if waf_providers else None
        cdn_provider = cdn_providers[0] if cdn_providers else None

        # Determine detection method
        methods = list({d.get("method", "").split(":")[0] for d in all_detections})
        detection_method = ", ".join(methods) if methods else "none"

        return WAFResult(
            waf_detected=waf_detected,
            waf_provider=waf_provider,
            cdn_detected=cdn_detected,
            cdn_provider=cdn_provider,
            is_behind_proxy=proxy_detected or cdn_detected,
            detection_method=detection_method,
            all_detections=all_detections,
        )

    except Exception as e:
        logger.error(f"WAF check failed: {e}", exc_info=True)
        return WAFResult(error=str(e))
