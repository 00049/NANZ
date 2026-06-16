"""
Domain 8: Subdomain & Infrastructure Analysis.

Includes: Subfinder passive subdomain discovery, subdomain takeover checks,
email security deep check (BIMI, MTA-STS), typosquatting via dnstwist,
ASN & IP reputation checks.

All checks are PASSIVE — no active exploitation.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field

import dns.asyncresolver
import httpx

from app.config import settings
from app.utils.subprocess_runner import is_tool_available, run_safe_subprocess

logger = logging.getLogger(__name__)


@dataclass
class SubdomainInfo:
    """Information about a discovered subdomain."""

    subdomain: str
    is_live: bool = False
    ip_address: str | None = None
    cname: str | None = None
    takeover_risk: bool = False
    takeover_service: str | None = None


@dataclass
class EmailSecurityDetail:
    """Deep email security analysis beyond basic SPF/DMARC/DKIM."""

    has_bimi: bool = False
    bimi_record: str | None = None
    has_mta_sts: bool = False
    mta_sts_mode: str | None = None  # enforce, testing, none


@dataclass
class IPReputation:
    """IP address reputation data."""

    ip_address: str | None = None
    asn: str | None = None
    org: str | None = None
    country: str | None = None
    city: str | None = None
    abuse_score: int | None = None
    total_reports: int = 0
    is_known_bad: bool = False
    error: str | None = None


@dataclass
class InfraResult:
    """Complete infrastructure analysis result."""

    # Subdomain discovery
    subdomains_found: int = 0
    subdomains: list[dict] = field(default_factory=list)
    takeover_risks: int = 0

    # Email security deep check
    email_security: dict | None = None

    # Typosquatting
    typosquat_count: int = 0
    typosquat_domains: list[str] = field(default_factory=list)
    typosquat_risk: str = "LOW"  # LOW, MEDIUM, HIGH

    # IP Reputation
    ip_reputation: dict | None = None

    # Error
    error: str | None = None


# Known services with dangling CNAME signatures for subdomain takeover
TAKEOVER_SIGNATURES = {
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "pantheonsite.io": "Pantheon",
    "domains.tumblr.com": "Tumblr",
    "wpengine.com": "WP Engine",
    "ghost.io": "Ghost",
    "myshopify.com": "Shopify",
    "desk.com": "Desk.com",
    "zendesk.com": "Zendesk",
    "surge.sh": "Surge.sh",
    "bitbucket.io": "Bitbucket",
    "s3.amazonaws.com": "AWS S3",
    "cloudfront.net": "AWS CloudFront",
    "azurewebsites.net": "Azure",
    "blob.core.windows.net": "Azure Blob",
    "trafficmanager.net": "Azure Traffic Manager",
    "unbouncepages.com": "Unbounce",
    "freshdesk.com": "Freshdesk",
    "readme.io": "ReadMe",
    "statuspage.io": "Statuspage",
}


async def _discover_subdomains_subfinder(domain: str) -> list[str]:
    """Use Subfinder for passive subdomain discovery."""
    if not is_tool_available("subfinder"):
        return []

    try:
        proc_result = await run_safe_subprocess(
            ["subfinder", "-d", domain, "-silent", "-timeout", "30"],
            timeout=45.0,
            tool_name="subfinder",
        )

        if proc_result.error or not proc_result.stdout:
            return []

        subdomains = [
            line.strip()
            for line in proc_result.stdout.strip().splitlines()
            if line.strip() and line.strip() != domain
        ]

        return list(set(subdomains))[:50]  # Limit to 50 subdomains

    except Exception as e:
        logger.warning(f"Subfinder failed for {domain}: {e}")
        return []


async def _check_subdomain_details(subdomain: str) -> SubdomainInfo:
    """Check if a subdomain is live and has takeover risk."""
    info = SubdomainInfo(subdomain=subdomain)

    # Check CNAME for takeover risk
    try:
        cname_answers = await dns.asyncresolver.resolve(subdomain, "CNAME")
        for rdata in cname_answers:
            cname = str(rdata.target).rstrip(".")
            info.cname = cname

            # Check against takeover signatures
            for signature, service in TAKEOVER_SIGNATURES.items():
                if signature in cname.lower():
                    # Verify if the CNAME target is actually unreachable (dangling)
                    try:
                        await dns.asyncresolver.resolve(cname, "A")
                    except dns.resolver.NXDOMAIN:
                        info.takeover_risk = True
                        info.takeover_service = service
                    except Exception:
                        pass
                    break
    except Exception:
        pass

    # Check if live via A record
    try:
        a_answers = await dns.asyncresolver.resolve(subdomain, "A")
        if a_answers:
            info.is_live = True
            info.ip_address = str(a_answers[0])
    except Exception:
        pass

    return info


async def _check_email_security(domain: str) -> EmailSecurityDetail:
    """Deep email security checks: BIMI and MTA-STS."""
    result = EmailSecurityDetail()

    # BIMI check
    try:
        bimi_txts = []
        answers = await dns.asyncresolver.resolve(f"default._bimi.{domain}", "TXT")
        for rdata in answers:
            txt = "".join([part.decode("utf-8") for part in rdata.strings])
            bimi_txts.append(txt)

        bimi = next((t for t in bimi_txts if "v=bimi1" in t.lower()), None)
        if bimi:
            result.has_bimi = True
            result.bimi_record = bimi
    except Exception:
        pass

    # MTA-STS check
    try:
        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
            mta_res = await client.get(
                f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
            )
            if mta_res.status_code == 200:
                result.has_mta_sts = True
                content = mta_res.text
                for line in content.splitlines():
                    if line.strip().startswith("mode:"):
                        result.mta_sts_mode = line.split(":", 1)[1].strip()
                        break
    except Exception:
        pass

    return result


async def _check_ip_reputation(ip_address: str) -> IPReputation:
    """Check IP reputation via free APIs."""
    result = IPReputation(ip_address=ip_address)

    if not ip_address:
        result.error = "No IP address provided"
        return result

    # ipapi.co for geo/ASN info
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            geo_res = await client.get(f"https://ipapi.co/{ip_address}/json/")
            if geo_res.status_code == 200:
                data = geo_res.json()
                result.asn = data.get("asn")
                result.org = data.get("org")
                result.country = data.get("country_name")
                result.city = data.get("city")
    except Exception as e:
        logger.warning(f"ipapi.co check failed for {ip_address}: {e}")

    # AbuseIPDB for abuse reports
    if settings.ABUSEIPDB_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                abuse_res = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip_address, "maxAgeInDays": "90"},
                    headers={
                        "Key": settings.ABUSEIPDB_API_KEY,
                        "Accept": "application/json",
                    },
                )
                if abuse_res.status_code == 200:
                    data = abuse_res.json().get("data", {})
                    result.abuse_score = data.get("abuseConfidenceScore", 0)
                    result.total_reports = data.get("totalReports", 0)
                    result.is_known_bad = (result.abuse_score or 0) > 50
        except Exception as e:
            logger.warning(f"AbuseIPDB check failed for {ip_address}: {e}")

    return result


async def _check_typosquatting(domain: str) -> tuple[int, list[str]]:
    """Use dnstwist to find registered lookalike domains."""
    try:
        command = [
            "python",
            "-m",
            "dnstwist",
            "--registered",
            "--format",
            "json",
            domain,
        ]

        if is_tool_available("dnstwist"):
            command = [
                "dnstwist",
                "--registered",
                "--format",
                "json",
                "--threads",
                "4",
                domain,
            ]

        proc_result = await run_safe_subprocess(
            command, timeout=30.0, tool_name="dnstwist"
        )

        if proc_result.stdout and not proc_result.error:
            try:
                data = json.loads(proc_result.stdout)
                registered = [
                    d.get("domain", "")
                    for d in data
                    if d.get("domain") and d.get("domain") != domain
                ]
                return len(registered), registered[:20]
            except json.JSONDecodeError:
                pass
    except Exception as e:
        logger.warning(f"dnstwist failed for {domain}: {e}")

    return 0, []


async def run(domain: str, ip_address: str | None = None) -> InfraResult:
    """Run all infrastructure analysis checks concurrently."""
    result = InfraResult()

    try:
        # Run subfinder and other checks concurrently
        subfinder_task = _discover_subdomains_subfinder(domain)
        email_task = _check_email_security(domain)
        typosquat_task = _check_typosquatting(domain)
        ip_task = _check_ip_reputation(ip_address or "")

        subdomains, email_sec, (typo_count, typo_domains), ip_rep = (
            await asyncio.gather(
                subfinder_task,
                email_task,
                typosquat_task,
                ip_task,
                return_exceptions=True,
            )
        )

        # Process subdomains
        if isinstance(subdomains, list) and subdomains:
            # Check details for first 20 subdomains (avoid rate limiting)
            check_tasks = [_check_subdomain_details(s) for s in subdomains[:20]]
            subdomain_details = await asyncio.gather(
                *check_tasks, return_exceptions=True
            )

            for detail in subdomain_details:
                if isinstance(detail, SubdomainInfo):
                    result.subdomains.append(
                        {
                            "subdomain": detail.subdomain,
                            "is_live": detail.is_live,
                            "ip_address": detail.ip_address,
                            "cname": detail.cname,
                            "takeover_risk": detail.takeover_risk,
                            "takeover_service": detail.takeover_service,
                        }
                    )
                    if detail.takeover_risk:
                        result.takeover_risks += 1

            result.subdomains_found = len(subdomains)

        # Email security
        if isinstance(email_sec, EmailSecurityDetail):
            result.email_security = {
                "has_bimi": email_sec.has_bimi,
                "bimi_record": email_sec.bimi_record,
                "has_mta_sts": email_sec.has_mta_sts,
                "mta_sts_mode": email_sec.mta_sts_mode,
            }

        # Typosquatting
        if isinstance(typo_count, int):
            result.typosquat_count = typo_count
            result.typosquat_domains = (
                typo_domains if isinstance(typo_domains, list) else []
            )
            if typo_count > 10:
                result.typosquat_risk = "HIGH"
            elif typo_count > 5:
                result.typosquat_risk = "MEDIUM"
            else:
                result.typosquat_risk = "LOW"

        # IP reputation
        if isinstance(ip_rep, IPReputation):
            result.ip_reputation = {
                "ip_address": ip_rep.ip_address,
                "asn": ip_rep.asn,
                "org": ip_rep.org,
                "country": ip_rep.country,
                "city": ip_rep.city,
                "abuse_score": ip_rep.abuse_score,
                "total_reports": ip_rep.total_reports,
                "is_known_bad": ip_rep.is_known_bad,
                "error": ip_rep.error,
            }

    except Exception as e:
        logger.error(
            f"Infrastructure check failed for domain={domain}: {e}", exc_info=True
        )
        result.error = str(e)

    return result
