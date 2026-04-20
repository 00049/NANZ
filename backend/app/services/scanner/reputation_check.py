"""
Domain 6: Reputation & Threat Intelligence.

Integrates free APIs: VirusTotal, Google Safe Browsing, URLScan.io, LeakIX.
All checks use HTTP GET/POST to third-party APIs — no interaction with target site.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class VirusTotalResult:
    """Result from VirusTotal domain lookup."""

    checked: bool = False
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
    total_vendors: int = 0
    reputation_score: Optional[int] = None
    categories: list[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class SafeBrowsingResult:
    """Result from Google Safe Browsing check."""

    checked: bool = False
    is_safe: bool = True
    threats_found: list[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class URLScanResult:
    """Result from URLScan.io analysis."""

    checked: bool = False
    is_malicious: bool = False
    overall_score: int = 0
    categories: list[str] = field(default_factory=list)
    page_title: Optional[str] = None
    server: Optional[str] = None
    ip_address: Optional[str] = None
    country: Optional[str] = None
    urls_count: int = 0
    error: Optional[str] = None


@dataclass
class LeakIXResult:
    """Result from LeakIX domain lookup."""

    checked: bool = False
    leaks_found: int = 0
    services_found: int = 0
    events: list[dict] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class ReputationResult:
    """Complete reputation and threat intelligence result."""

    # Per-source results
    virustotal: Optional[dict] = None
    safe_browsing: Optional[dict] = None
    urlscan: Optional[dict] = None
    leakix: Optional[dict] = None

    # Aggregated
    is_flagged_malicious: bool = False
    total_sources_checked: int = 0
    sources_flagging_issues: int = 0

    # Error
    error: Optional[str] = None


async def _check_virustotal(domain: str) -> VirusTotalResult:
    """Query VirusTotal API for domain reputation."""
    result = VirusTotalResult()

    if not settings.VIRUSTOTAL_API_KEY:
        result.error = "No VirusTotal API key configured"
        return result

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            res = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            )

            if res.status_code == 200:
                data = res.json()
                attrs = data.get("data", {}).get("attributes", {})

                last_analysis = attrs.get("last_analysis_stats", {})
                result.checked = True
                result.malicious_count = last_analysis.get("malicious", 0)
                result.suspicious_count = last_analysis.get("suspicious", 0)
                result.harmless_count = last_analysis.get("harmless", 0)
                result.undetected_count = last_analysis.get("undetected", 0)
                result.total_vendors = sum(last_analysis.values())
                result.reputation_score = attrs.get("reputation")

                categories = attrs.get("categories", {})
                result.categories = list(set(categories.values()))[:5]
            elif res.status_code == 404:
                result.checked = True  # Domain not in VT database = likely clean
            else:
                result.error = f"VT API error: {res.status_code}"

    except Exception as e:
        logger.warning(f"VirusTotal check failed for {domain}: {e}")
        result.error = str(e)

    return result


async def _check_safe_browsing(domain: str) -> SafeBrowsingResult:
    """Query Google Safe Browsing API."""
    result = SafeBrowsingResult()

    if not settings.GOOGLE_SAFE_BROWSING_KEY:
        result.error = "No Google Safe Browsing API key configured"
        return result

    try:
        payload = {
            "client": {
                "clientId": "shieldcheck",
                "clientVersion": "2.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": f"http://{domain}/"},
                    {"url": f"https://{domain}/"},
                ],
            },
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            res = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={"key": settings.GOOGLE_SAFE_BROWSING_KEY},
                json=payload,
            )

            if res.status_code == 200:
                data = res.json()
                result.checked = True
                matches = data.get("matches", [])
                if matches:
                    result.is_safe = False
                    result.threats_found = list(set(
                        m.get("threatType", "UNKNOWN") for m in matches
                    ))
            else:
                result.error = f"GSB API error: {res.status_code}"

    except Exception as e:
        logger.warning(f"Safe Browsing check failed for {domain}: {e}")
        result.error = str(e)

    return result


async def _check_urlscan(domain: str) -> URLScanResult:
    """Query URLScan.io API — search for existing scans."""
    result = URLScanResult()

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            headers = {}
            if settings.URLSCAN_API_KEY:
                headers["API-Key"] = settings.URLSCAN_API_KEY

            # Search for recent scans instead of submitting new one
            search_res = await client.get(
                f"https://urlscan.io/api/v1/search/",
                params={"q": f"domain:{domain}", "size": 1},
                headers=headers,
            )

            if search_res.status_code == 200:
                search_data = search_res.json()
                results_list = search_data.get("results", [])

                if results_list:
                    latest = results_list[0]
                    result.checked = True

                    page = latest.get("page", {})
                    result.page_title = page.get("title")
                    result.server = page.get("server")
                    result.ip_address = page.get("ip")
                    result.country = page.get("country")

                    verdicts = latest.get("verdicts", {})
                    overall = verdicts.get("overall", {})
                    result.is_malicious = overall.get("malicious", False)
                    result.overall_score = overall.get("score", 0)

                    categories_list = overall.get("categories", [])
                    result.categories = categories_list[:5]

                    stats = latest.get("stats", {})
                    result.urls_count = stats.get("uniqUrls", 0)
                else:
                    result.checked = True  # No previous scans found — not necessarily bad
            else:
                result.error = f"URLScan API error: {search_res.status_code}"

    except Exception as e:
        logger.warning(f"URLScan check failed for {domain}: {e}")
        result.error = str(e)

    return result


async def _check_leakix(domain: str) -> LeakIXResult:
    """Query LeakIX API for exposed services and data leaks."""
    result = LeakIXResult()

    try:
        headers = {"Accept": "application/json"}
        if settings.LEAKIX_API_KEY:
            headers["api-key"] = settings.LEAKIX_API_KEY

        async with httpx.AsyncClient(timeout=10.0) as client:
            res = await client.get(
                f"https://leakix.net/domain/{domain}",
                headers=headers,
            )

            if res.status_code == 200:
                data = res.json()
                result.checked = True

                if isinstance(data, list):
                    result.leaks_found = len(data)
                    for event in data[:10]:
                        result.events.append({
                            "event_type": event.get("event_type", ""),
                            "protocol": event.get("protocol", ""),
                            "port": event.get("port", 0),
                            "summary": event.get("summary", "")[:200],
                            "time": event.get("time", ""),
                        })
                        if event.get("event_type") == "service":
                            result.services_found += 1
                elif isinstance(data, dict):
                    # Single result or error
                    result.checked = True
            elif res.status_code == 404:
                result.checked = True  # No data found = clean
            else:
                result.error = f"LeakIX API error: {res.status_code}"

    except Exception as e:
        logger.warning(f"LeakIX check failed for {domain}: {e}")
        result.error = str(e)

    return result


async def run(domain: str) -> ReputationResult:
    """Run all reputation and threat intelligence checks concurrently."""
    result = ReputationResult()

    try:
        vt_task = _check_virustotal(domain)
        gsb_task = _check_safe_browsing(domain)
        urlscan_task = _check_urlscan(domain)
        leakix_task = _check_leakix(domain)

        vt, gsb, urlscan, leakix = await asyncio.gather(
            vt_task, gsb_task, urlscan_task, leakix_task,
            return_exceptions=True,
        )

        sources_checked = 0
        sources_flagging = 0

        # VirusTotal
        if isinstance(vt, VirusTotalResult):
            result.virustotal = {
                "checked": vt.checked,
                "malicious_count": vt.malicious_count,
                "suspicious_count": vt.suspicious_count,
                "harmless_count": vt.harmless_count,
                "total_vendors": vt.total_vendors,
                "reputation_score": vt.reputation_score,
                "categories": vt.categories,
                "error": vt.error,
            }
            if vt.checked:
                sources_checked += 1
                if vt.malicious_count > 0:
                    sources_flagging += 1
                    result.is_flagged_malicious = True

        # Google Safe Browsing
        if isinstance(gsb, SafeBrowsingResult):
            result.safe_browsing = {
                "checked": gsb.checked,
                "is_safe": gsb.is_safe,
                "threats_found": gsb.threats_found,
                "error": gsb.error,
            }
            if gsb.checked:
                sources_checked += 1
                if not gsb.is_safe:
                    sources_flagging += 1
                    result.is_flagged_malicious = True

        # URLScan
        if isinstance(urlscan, URLScanResult):
            result.urlscan = {
                "checked": urlscan.checked,
                "is_malicious": urlscan.is_malicious,
                "overall_score": urlscan.overall_score,
                "categories": urlscan.categories,
                "page_title": urlscan.page_title,
                "server": urlscan.server,
                "ip_address": urlscan.ip_address,
                "country": urlscan.country,
                "error": urlscan.error,
            }
            if urlscan.checked:
                sources_checked += 1
                if urlscan.is_malicious:
                    sources_flagging += 1
                    result.is_flagged_malicious = True

        # LeakIX
        if isinstance(leakix, LeakIXResult):
            result.leakix = {
                "checked": leakix.checked,
                "leaks_found": leakix.leaks_found,
                "services_found": leakix.services_found,
                "events": leakix.events[:5],
                "error": leakix.error,
            }
            if leakix.checked:
                sources_checked += 1
                if leakix.leaks_found > 0:
                    sources_flagging += 1

        result.total_sources_checked = sources_checked
        result.sources_flagging_issues = sources_flagging

    except Exception as e:
        logger.error(f"Reputation check failed for domain={domain}: {e}", exc_info=True)
        result.error = str(e)

    return result
