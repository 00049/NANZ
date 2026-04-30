"""
Domain 2: HTTP Security Headers — expanded to 13+ headers.

Checks all critical HTTP security headers, redirect chain analysis,
server info leakage, and scores 0-100.

All checks are PASSIVE — only HTTP GET requests.
"""

import httpx
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# All headers to check with their expected configurations
SECURITY_HEADERS = {
    "strict-transport-security": {
        "required": True,
        "weight": 15,
        "description": "HSTS — forces HTTPS connections",
    },
    "content-security-policy": {
        "required": True,
        "weight": 15,
        "description": "CSP — prevents XSS and injection attacks",
    },
    "x-frame-options": {
        "required": True,
        "weight": 10,
        "description": "Prevents clickjacking via iframes",
    },
    "x-content-type-options": {
        "required": True,
        "weight": 10,
        "description": "Prevents MIME-type sniffing",
    },
    "referrer-policy": {
        "required": True,
        "weight": 8,
        "description": "Controls referrer information leakage",
    },
    "permissions-policy": {
        "required": True,
        "weight": 8,
        "description": "Controls browser feature access",
    },
    "cross-origin-opener-policy": {
        "required": False,
        "weight": 5,
        "description": "Isolates browsing context",
    },
    "cross-origin-resource-policy": {
        "required": False,
        "weight": 5,
        "description": "Controls cross-origin resource loading",
    },
    "x-xss-protection": {
        "required": False,
        "weight": 4,
        "description": "Legacy XSS filter (should be '0' in modern browsers)",
    },
    "cache-control": {
        "required": False,
        "weight": 5,
        "description": "Controls caching of sensitive data",
    },
}

# Headers that leak information (bad if present with version info)
LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]

# Version pattern to detect exposed version info
VERSION_PATTERN = re.compile(r"[\d]+\.[\d]+")

USER_AGENT = "ShieldCheck-Scanner/2.0 (+https://shieldcheck.in/bot)"


@dataclass
class HeaderDetail:
    """Analysis result for a single header."""

    name: str
    present: bool
    value: Optional[str] = None
    status: str = "missing"  # pass, fail, missing, warning
    detail: Optional[str] = None


@dataclass
class RedirectInfo:
    """Information about the HTTP redirect chain."""

    http_to_https: bool = False
    redirect_chain: list[str] = field(default_factory=list)
    chain_length: int = 0
    final_url: Optional[str] = None
    too_many_redirects: bool = False
    www_consistency: Optional[str] = None  # "www", "non-www", "inconsistent"


@dataclass
class HeadersResult:
    """Complete result of HTTP security headers analysis."""

    present: dict[str, str] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)
    score: int = 0
    grade: str = "F"
    server_header: Optional[str] = None
    x_powered_by: Optional[str] = None
    error: Optional[str] = None

    # Expanded fields
    header_details: list[dict] = field(default_factory=list)
    leaky_headers: list[dict] = field(default_factory=list)
    redirect_info: Optional[dict] = None
    server_exposes_version: bool = False
    xpowered_exposes_tech: bool = False
    has_deprecated_feature_policy: bool = False
    hsts_max_age: Optional[int] = None
    hsts_includes_subdomains: bool = False
    csp_report_only: bool = False
    referrer_unsafe: bool = False
    xss_protection_misconfigured: bool = False
    total_headers_checked: int = 0
    total_headers_passed: int = 0

    # New: robots.txt, security.txt, HTTP/2
    robots_sensitive_paths: list[str] = field(default_factory=list)
    robots_total_disallowed: int = 0
    has_security_txt: bool = False
    security_txt_content: Optional[str] = None
    http2_supported: bool = False
    http3_supported: bool = False


async def run(url: str) -> HeadersResult:
    """
    Fetch the URL and analyze all HTTP security headers.
    Also checks redirect chain and server info leakage.
    """
    result = HeadersResult()

    try:
        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=False,
            verify=False,
        ) as client:
            # ── Step 1: Check redirect chain ──
            redirect_info = await _check_redirects(client, url)
            result.redirect_info = {
                "http_to_https": redirect_info.http_to_https,
                "redirect_chain": redirect_info.redirect_chain,
                "chain_length": redirect_info.chain_length,
                "final_url": redirect_info.final_url,
                "too_many_redirects": redirect_info.too_many_redirects,
                "www_consistency": redirect_info.www_consistency,
            }

        # ── Step 2: Follow redirects and get final response headers ──
        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            verify=False,
        ) as client:
            response = await client.get(url, headers={"User-Agent": USER_AGENT})
            headers_lower = {k.lower(): v for k, v in response.headers.items()}

            # ── Step 3: Check each security header ──
            total_weight = 0
            earned_weight = 0

            for header_name, config in SECURITY_HEADERS.items():
                total_weight += config["weight"]
                detail = HeaderDetail(name=header_name, present=header_name in headers_lower)

                if detail.present:
                    detail.value = headers_lower[header_name]
                    result.present[header_name] = detail.value

                    # Validate specific headers
                    validation = _validate_header(header_name, detail.value)
                    detail.status = validation["status"]
                    detail.detail = validation.get("detail")

                    if detail.status == "pass":
                        earned_weight += config["weight"]
                    elif detail.status == "warning":
                        earned_weight += config["weight"] * 0.5
                else:
                    result.missing.append(header_name)
                    detail.status = "missing"
                    detail.detail = config["description"]

                result.header_details.append({
                    "name": detail.name,
                    "present": detail.present,
                    "value": detail.value,
                    "status": detail.status,
                    "detail": detail.detail,
                })

            result.total_headers_checked = len(SECURITY_HEADERS)
            result.total_headers_passed = sum(
                1 for d in result.header_details if d["status"] == "pass"
            )

            # ── Step 4: Check leaky/info headers ──
            for header_name in LEAKY_HEADERS:
                value = headers_lower.get(header_name)
                if value:
                    has_version = bool(VERSION_PATTERN.search(value))
                    result.leaky_headers.append({
                        "name": header_name,
                        "value": value,
                        "exposes_version": has_version,
                    })

                    if header_name == "server":
                        result.server_header = value
                        result.server_exposes_version = has_version
                    elif header_name == "x-powered-by":
                        result.x_powered_by = value
                        result.xpowered_exposes_tech = True

            # ── Step 5: Check deprecated Feature-Policy ──
            if "feature-policy" in headers_lower:
                result.has_deprecated_feature_policy = True

            # ── Step 6: HSTS details ──
            hsts = headers_lower.get("strict-transport-security", "")
            if hsts:
                max_age_match = re.search(r"max-age=(\d+)", hsts)
                if max_age_match:
                    result.hsts_max_age = int(max_age_match.group(1))
                result.hsts_includes_subdomains = "includesubdomains" in hsts.lower()

            # ── Step 7: CSP report-only check ──
            if "content-security-policy-report-only" in headers_lower and "content-security-policy" not in headers_lower:
                result.csp_report_only = True

            # ── Step 8: Referrer-Policy safety ──
            referrer = headers_lower.get("referrer-policy", "")
            if referrer.lower() == "unsafe-url":
                result.referrer_unsafe = True

            # ── Step 9: X-XSS-Protection check ──
            xss = headers_lower.get("x-xss-protection", "")
            if xss and xss.strip() != "0":
                result.xss_protection_misconfigured = True

            # ── Step 10: robots.txt analysis ──
            try:
                base_url = url.rstrip("/")
                robots_res = await client.get(f"{base_url}/robots.txt", headers={"User-Agent": USER_AGENT})
                if robots_res.status_code == 200 and "disallow" in robots_res.text.lower():
                    sensitive_keywords = {"admin", "backup", "config", "db", ".env", "api", "internal", "private", "secret", "wp-admin", "phpmyadmin"}
                    disallowed = []
                    for line in robots_res.text.splitlines():
                        line_stripped = line.strip().lower()
                        if line_stripped.startswith("disallow:"):
                            path = line_stripped.replace("disallow:", "").strip()
                            if path:
                                disallowed.append(path)
                    result.robots_total_disallowed = len(disallowed)
                    result.robots_sensitive_paths = [
                        p for p in disallowed
                        if any(kw in p.lower() for kw in sensitive_keywords)
                    ]
            except Exception as e:
                logger.debug(f"robots.txt check failed: {e}")

            # ── Step 11: security.txt check (RFC 9116) ──
            try:
                base_url = url.rstrip("/")
                sec_res = await client.get(f"{base_url}/.well-known/security.txt", headers={"User-Agent": USER_AGENT})
                if sec_res.status_code == 200 and ("contact:" in sec_res.text.lower() or "policy:" in sec_res.text.lower()):
                    result.has_security_txt = True
                    result.security_txt_content = sec_res.text[:500]
                else:
                    # Try root path fallback
                    sec_res2 = await client.get(f"{base_url}/security.txt", headers={"User-Agent": USER_AGENT})
                    if sec_res2.status_code == 200 and "contact:" in sec_res2.text.lower():
                        result.has_security_txt = True
                        result.security_txt_content = sec_res2.text[:500]
            except Exception as e:
                logger.debug(f"security.txt check failed: {e}")

            # ── Step 12: HTTP/2 and HTTP/3 support ──
            alt_svc = headers_lower.get("alt-svc", "")
            if "h3" in alt_svc:
                result.http3_supported = True
            if "h2" in alt_svc or response.http_version == "HTTP/2":
                result.http2_supported = True

            # ── Calculate final score ──
            # Base score from header weights
            base_score = int((earned_weight / total_weight) * 80) if total_weight > 0 else 0

            # Bonus for redirect and no leaky headers
            bonus = 0
            if redirect_info.http_to_https:
                bonus += 10
            if not result.server_exposes_version:
                bonus += 5
            if not result.xpowered_exposes_tech:
                bonus += 5

            result.score = min(100, base_score + bonus)
            
            # Letter grade
            if result.score >= 95:
                result.grade = "A+"
            elif result.score >= 90:
                result.grade = "A"
            elif result.score >= 80:
                result.grade = "B"
            elif result.score >= 70:
                result.grade = "C"
            elif result.score >= 60:
                result.grade = "D"
            else:
                result.grade = "F"

    except Exception as e:
        logger.error(f"Headers check failed for url={url}: {e}", exc_info=True)
        result.error = str(e)

    return result


async def _check_redirects(client: httpx.AsyncClient, url: str) -> RedirectInfo:
    """Follow redirect chain manually to analyze HTTP→HTTPS and consistency."""
    info = RedirectInfo()
    current_url = url
    seen_urls: list[str] = []

    # Also check HTTP version for redirect
    http_url = url.replace("https://", "http://")
    if url.startswith("https://"):
        try:
            http_res = await client.get(http_url, headers={"User-Agent": USER_AGENT})
            if http_res.status_code in (301, 302, 307, 308):
                location = http_res.headers.get("location", "")
                if location.startswith("https://"):
                    info.http_to_https = True
        except Exception:
            pass

    # Follow redirect chain on the original URL
    for _ in range(10):
        if current_url in seen_urls:
            break
        seen_urls.append(current_url)

        try:
            res = await client.get(current_url, headers={"User-Agent": USER_AGENT})
            if res.status_code in (301, 302, 307, 308):
                location = res.headers.get("location", "")
                if location:
                    if location.startswith("/"):
                        from urllib.parse import urlparse
                        parsed = urlparse(current_url)
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"
                    current_url = location
                    continue
            break
        except Exception:
            break

    info.redirect_chain = seen_urls
    info.chain_length = len(seen_urls) - 1
    info.final_url = seen_urls[-1] if seen_urls else url
    info.too_many_redirects = info.chain_length > 3

    # WWW consistency check
    has_www = any("://www." in u for u in seen_urls)
    has_non_www = any("://" in u and "://www." not in u for u in seen_urls)
    if has_www and not has_non_www:
        info.www_consistency = "www"
    elif has_non_www and not has_www:
        info.www_consistency = "non-www"
    elif has_www and has_non_www:
        info.www_consistency = "inconsistent"

    return info


def _validate_header(header_name: str, value: str) -> dict:
    """Validate a specific header value and return pass/fail/warning status."""
    val_lower = value.lower().strip()

    if header_name == "strict-transport-security":
        max_age_match = re.search(r"max-age=(\d+)", val_lower)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age >= 31536000:
                return {"status": "pass", "detail": f"max-age={max_age} (>= 1 year)"}
            else:
                return {"status": "warning", "detail": f"max-age={max_age} (< 1 year recommended)"}
        return {"status": "fail", "detail": "Missing max-age directive"}

    elif header_name == "x-frame-options":
        if val_lower in ("deny", "sameorigin"):
            return {"status": "pass", "detail": f"Set to {value}"}
        return {"status": "warning", "detail": f"Unexpected value: {value}"}

    elif header_name == "x-content-type-options":
        if val_lower == "nosniff":
            return {"status": "pass", "detail": "Correctly set to nosniff"}
        return {"status": "fail", "detail": f"Should be 'nosniff', got '{value}'"}

    elif header_name == "referrer-policy":
        unsafe = {"unsafe-url"}
        if val_lower in unsafe:
            return {"status": "fail", "detail": "Unsafe referrer policy — leaks full URL"}
        return {"status": "pass", "detail": f"Set to {value}"}

    elif header_name == "x-xss-protection":
        if val_lower == "0":
            return {"status": "pass", "detail": "Correctly disabled (modern recommendation)"}
        return {"status": "warning", "detail": "Should be '0' — legacy filter can cause issues"}

    elif header_name == "content-security-policy":
        if "unsafe-inline" in val_lower and "unsafe-eval" in val_lower:
            return {"status": "warning", "detail": "CSP present but allows unsafe-inline and unsafe-eval"}
        if "default-src" in val_lower or "script-src" in val_lower:
            return {"status": "pass", "detail": "CSP present with source restrictions"}
        return {"status": "warning", "detail": "CSP present but may be too permissive"}

    # For all other headers, presence = pass
    return {"status": "pass", "detail": f"Present: {value[:80]}"}
