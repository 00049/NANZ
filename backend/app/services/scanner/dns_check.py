"""
Domain 3: DNS Security Deep Analysis.

Expanded checks: SPF validation, DMARC policy strength, DKIM multi-selector,
DNSSEC, CAA records, NS records, MX records, subdomain enumeration (passive),
zone transfer attempt, typosquatting detection via dnstwist.

All checks are PASSIVE — DNS queries only.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Optional

import dns.asyncresolver
import dns.resolver
import dns.rdatatype
import dns.zone
import dns.query
import dns.name

from app.utils.subprocess_runner import run_safe_subprocess, is_tool_available

logger = logging.getLogger(__name__)

# Common subdomains to check (passive enumeration)
COMMON_SUBDOMAINS = [
    "admin", "api", "mail", "ftp", "dev", "staging",
    "test", "beta", "portal", "vpn", "remote", "backup",
    "old", "blog", "shop", "store", "app", "dashboard",
    "cdn", "static", "media", "img", "docs", "wiki",
]

# DKIM selectors to check
DKIM_SELECTORS = ["default", "google", "mail", "selector1", "selector2", "dkim", "s1", "s2"]


@dataclass
class DNSResult:
    """Result of comprehensive DNS security analysis."""

    # SPF
    has_spf: bool = False
    spf_record: Optional[str] = None
    spf_all_mechanism: Optional[str] = None  # ~all, -all, +all, ?all
    spf_lookup_count: Optional[int] = None
    spf_too_many_lookups: bool = False

    # DMARC
    has_dmarc: bool = False
    dmarc_record: Optional[str] = None
    dmarc_policy: Optional[str] = None  # none, quarantine, reject
    dmarc_not_enforced: bool = False

    # DKIM
    has_dkim: bool = False
    dkim_selectors_found: list[str] = field(default_factory=list)

    # DNSSEC
    has_dnssec: bool = False

    # CAA
    has_caa: bool = False
    caa_records: list[str] = field(default_factory=list)

    # NS records
    ns_records: list[str] = field(default_factory=list)
    has_minimum_ns: bool = False

    # MX records
    mx_records: list[dict] = field(default_factory=list)
    has_mx: bool = False

    # Subdomain enumeration (passive)
    discovered_subdomains: list[str] = field(default_factory=list)

    # Zone transfer
    zone_transfer_possible: bool = False

    # Typosquatting
    typosquat_count: int = 0
    typosquat_domains: list[str] = field(default_factory=list)

    # Error
    error: Optional[str] = None


async def _query_txt(domain: str) -> list[str]:
    """Query TXT records for a domain and return decoded record values."""
    records = []
    try:
        answers = await dns.asyncresolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = "".join([part.decode("utf-8") for part in rdata.strings])
            records.append(txt)
    except (dns.resolver.DNSException, TimeoutError, OSError):
        pass
    return records


async def _check_spf(domain: str, result: DNSResult) -> None:
    """Check SPF record presence, validity, and all-mechanism."""
    try:
        txts = await _query_txt(domain)
        spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
        result.has_spf = bool(spf)
        result.spf_record = spf

        if spf:
            # Check the all-mechanism
            for mechanism in ["+all", "-all", "~all", "?all"]:
                if mechanism in spf.lower():
                    result.spf_all_mechanism = mechanism
                    break

            # Count DNS lookups (include, a, mx, ptr, exists, redirect)
            lookup_keywords = ["include:", "a:", "a/", "mx:", "mx/", "ptr:", "exists:", "redirect="]
            count = sum(1 for kw in lookup_keywords if kw in spf.lower())
            # "a" and "mx" without colon also count
            parts = spf.lower().split()
            for part in parts:
                if part in ("a", "mx", "ptr"):
                    count += 1
            result.spf_lookup_count = count
            result.spf_too_many_lookups = count > 10
    except Exception as e:
        logger.warning(f"SPF check error for {domain}: {e}")


async def _check_dmarc(domain: str, result: DNSResult) -> None:
    """Check DMARC record and policy strength."""
    try:
        txts = await _query_txt(f"_dmarc.{domain}")
        dmarc = next((t for t in txts if t.lower().startswith("v=dmarc1")), None)
        result.has_dmarc = bool(dmarc)
        result.dmarc_record = dmarc

        if dmarc:
            # Extract policy
            parts = dmarc.split(";")
            for part in parts:
                part = part.strip().lower()
                if part.startswith("p="):
                    result.dmarc_policy = part.split("=", 1)[1].strip()
                    break

            result.dmarc_not_enforced = result.dmarc_policy in ("none", None)
    except Exception as e:
        logger.warning(f"DMARC check error for {domain}: {e}")


async def _check_dkim(domain: str, result: DNSResult) -> None:
    """Check DKIM across multiple common selectors."""
    for selector in DKIM_SELECTORS:
        try:
            txts = await _query_txt(f"{selector}._domainkey.{domain}")
            if txts:
                result.dkim_selectors_found.append(selector)
        except Exception:
            pass
    result.has_dkim = len(result.dkim_selectors_found) > 0


async def _check_dnssec(domain: str, result: DNSResult) -> None:
    """Check if DNSSEC is enabled for the domain."""
    try:
        answers = await dns.asyncresolver.resolve(domain, "DNSKEY")
        result.has_dnssec = len(answers) > 0
    except dns.resolver.NoAnswer:
        result.has_dnssec = False
    except dns.resolver.NXDOMAIN:
        result.has_dnssec = False
    except Exception:
        result.has_dnssec = False


async def _check_caa(domain: str, result: DNSResult) -> None:
    """Check for Certificate Authority Authorization records."""
    try:
        answers = await dns.asyncresolver.resolve(domain, "CAA")
        for rdata in answers:
            result.caa_records.append(str(rdata))
        result.has_caa = len(result.caa_records) > 0
    except (dns.resolver.DNSException, TimeoutError, OSError):
        result.has_caa = False


async def _check_ns(domain: str, result: DNSResult) -> None:
    """Check nameserver records."""
    try:
        answers = await dns.asyncresolver.resolve(domain, "NS")
        result.ns_records = [str(rdata).rstrip(".") for rdata in answers]
        result.has_minimum_ns = len(result.ns_records) >= 2
    except (dns.resolver.DNSException, TimeoutError, OSError):
        pass


async def _check_mx(domain: str, result: DNSResult) -> None:
    """Check MX records and priority configuration."""
    try:
        answers = await dns.asyncresolver.resolve(domain, "MX")
        for rdata in answers:
            result.mx_records.append({
                "priority": rdata.preference,
                "host": str(rdata.exchange).rstrip("."),
            })
        result.mx_records.sort(key=lambda x: x["priority"])
        result.has_mx = len(result.mx_records) > 0
    except (dns.resolver.DNSException, TimeoutError, OSError):
        pass


async def _check_subdomains(domain: str, result: DNSResult) -> None:
    """Passively check common subdomains via DNS resolution."""
    async def _check_one(sub: str) -> Optional[str]:
        fqdn = f"{sub}.{domain}"
        try:
            await dns.asyncresolver.resolve(fqdn, "A")
            return fqdn
        except Exception:
            return None

    tasks = [_check_one(sub) for sub in COMMON_SUBDOMAINS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    result.discovered_subdomains = [
        r for r in results if isinstance(r, str) and r is not None
    ]


async def _check_zone_transfer(domain: str, result: DNSResult) -> None:
    """Attempt AXFR zone transfer (if successful = CRITICAL finding)."""
    try:
        ns_answers = await dns.asyncresolver.resolve(domain, "NS")
        for ns_rdata in ns_answers:
            ns_host = str(ns_rdata).rstrip(".")
            try:
                # Attempt zone transfer with timeout
                zone = await asyncio.wait_for(
                    asyncio.to_thread(
                        dns.zone.from_xfr,
                        dns.query.xfr(ns_host, domain, timeout=5.0),
                    ),
                    timeout=10.0,
                )
                if zone:
                    result.zone_transfer_possible = True
                    logger.warning(f"Zone transfer SUCCESSFUL for {domain} via {ns_host}")
                    return
            except Exception:
                continue
    except Exception:
        pass


async def _check_typosquatting(domain: str, result: DNSResult) -> None:
    """Use dnstwist to find registered lookalike domains."""
    if not is_tool_available("dnstwist"):
        # Try Python module
        try:
            proc_result = await run_safe_subprocess(
                ["python", "-m", "dnstwist", "--registered", "--format", "json", domain],
                timeout=30.0,
                tool_name="dnstwist",
            )
            if proc_result.stdout and not proc_result.error:
                try:
                    data = json.loads(proc_result.stdout)
                    registered = [
                        d.get("domain", "")
                        for d in data
                        if d.get("domain") and d.get("domain") != domain
                    ]
                    result.typosquat_count = len(registered)
                    result.typosquat_domains = registered[:20]  # Limit output
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            logger.warning(f"dnstwist failed for {domain}: {e}")
        return

    try:
        proc_result = await run_safe_subprocess(
            ["dnstwist", "--registered", "--format", "json", "--threads", "4", domain],
            timeout=30.0,
            tool_name="dnstwist",
        )
        if proc_result.stdout and not proc_result.error:
            try:
                data = json.loads(proc_result.stdout)
                registered = [
                    d.get("domain", "")
                    for d in data
                    if d.get("domain") and d.get("domain") != domain
                ]
                result.typosquat_count = len(registered)
                result.typosquat_domains = registered[:20]
            except json.JSONDecodeError:
                pass
    except Exception as e:
        logger.warning(f"dnstwist subprocess failed for {domain}: {e}")


async def run(domain: str) -> DNSResult:
    """Run all DNS security checks concurrently."""
    result = DNSResult()

    try:
        await asyncio.gather(
            _check_spf(domain, result),
            _check_dmarc(domain, result),
            _check_dkim(domain, result),
            _check_dnssec(domain, result),
            _check_caa(domain, result),
            _check_ns(domain, result),
            _check_mx(domain, result),
            _check_subdomains(domain, result),
            _check_zone_transfer(domain, result),
            _check_typosquatting(domain, result),
            return_exceptions=True,
        )
    except Exception as e:
        logger.error(f"DNS check failed for domain={domain}: {e}", exc_info=True)
        result.error = "DNS check partially failed"

    return result
