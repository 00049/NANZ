"""
Expanded Scan Orchestrator — runs all 8 security domains concurrently.

Domains:
1. SSL/TLS Deep Analysis (SSLyze)
2. HTTP Security Headers (expanded 13+ headers)
3. DNS Security (SPF/DMARC/DKIM/DNSSEC/CAA/zone transfer/typosquatting)
4. Port & Service Scanning (Shodan → Nmap → direct)
5. Web Application Security (Mozilla Observatory + Nuclei + WhatWeb + sensitive files)
6. Reputation & Threat Intel (VirusTotal + Google Safe Browsing + URLScan + LeakIX)
7. CMS & Software Vulnerabilities (WPScan + multi-CMS detection)
8. Subdomain & Infrastructure (Subfinder + dnstwist + IP reputation)

Plus existing: Breach check, Cookie check

All checks remain PASSIVE — no active exploitation, no payload injection.
"""

import asyncio
import hashlib
import logging
import json
from datetime import datetime, timezone
from dataclasses import asdict

from app.services.scanner import (
    ssl_check, headers_check, dns_check, port_check,
    breach_check, cms_check, cookie_check,
)
from app.services.scanner import webapp_check, reputation_check, infra_check
from app.services.classifier import classify_findings
from app.services.ai_translator import translate_to_plain_english, generate_executive_summary
from app.db.session import async_session_maker
from app.models import Report, Scan
from app.config import settings
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)

# Total number of check domains
TOTAL_CHECK_DOMAINS = 10  # 8 new domains + breach + cookies


def _json_safe(value: object) -> object:
    """Convert dataclass output into JSON-compatible values."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, set):
        return list(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _calculate_security_score(raw_findings: dict, classified: list) -> int:
    """Calculate 0-100 overall security score based on findings."""
    # Start at 100, deduct for findings
    score = 100

    for finding in classified:
        severity = finding.get("severity", "INFO")
        if severity == "CRITICAL":
            score -= 15
        elif severity == "RED":
            score -= 8
        elif severity == "AMBER":
            score -= 3
        elif severity == "GREEN":
            score -= 1

    # Bonus from header score if available
    headers_data = raw_findings.get("headers", {}).get("data", {})
    if isinstance(headers_data, dict):
        header_score = headers_data.get("score", 0)
        if header_score >= 80:
            score += 5

    return max(0, min(100, score))


def _calculate_dpdp_compliance(raw_findings: dict, classified: list) -> tuple[int, list[str]]:
    """Calculate DPDP (Digital Personal Data Protection) compliance score."""
    score = 100
    issues: list[str] = []

    # Check SSL
    ssl_data = raw_findings.get("ssl", {}).get("data", {})
    if isinstance(ssl_data, dict):
        if not ssl_data.get("valid"):
            score -= 20
            issues.append("Website lacks valid encryption certificate — personal data may be transmitted insecurely")
        if ssl_data.get("supports_tls_1_0") or ssl_data.get("supports_tls_1_1"):
            score -= 10
            issues.append("Outdated encryption protocols in use — does not meet data protection standards")

    # Check headers
    headers_data = raw_findings.get("headers", {}).get("data", {})
    if isinstance(headers_data, dict):
        redirect_info = headers_data.get("redirect_info", {})
        if isinstance(redirect_info, dict) and not redirect_info.get("http_to_https"):
            score -= 15
            issues.append("No forced encryption — visitors can access site without data protection")

    # Check for exposed data
    webapp_data = raw_findings.get("webapp", {}).get("data", {})
    if isinstance(webapp_data, dict):
        exposed = webapp_data.get("exposed_files", [])
        if exposed:
            score -= 20
            issues.append("Sensitive configuration files are publicly accessible — potential personal data exposure")

    # Check ports
    ports_data = raw_findings.get("ports", {}).get("data", {})
    if isinstance(ports_data, dict):
        critical_ports = ports_data.get("critical_ports_exposed", [])
        if critical_ports:
            score -= 25
            issues.append("Database ports exposed to internet — personal data at risk of unauthorized access")

    # Check reputation
    rep_data = raw_findings.get("reputation", {}).get("data", {})
    if isinstance(rep_data, dict):
        if rep_data.get("is_flagged_malicious"):
            score -= 20
            issues.append("Domain flagged as malicious — may be compromised or serving harmful content")

    return max(0, min(100, score)), issues


async def run_full_scan(scan_id: str, url: str, redis_client: Redis) -> None:
    """
    Orchestrate the running of all 10 check modules concurrently.
    """
    logger.info(f"Starting expanded orchestration for scan_id={scan_id}, url={url}")
    start_time = datetime.now(timezone.utc)

    try:
        async with async_session_maker() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalars().first()

            if not scan:
                logger.error(f"Scan {scan_id} not found in DB.")
                return

            await db.refresh(scan)
            scan.status = "running"
            await db.commit()

            domain = scan.domain
            ip_address = scan.ip_address
    except SQLAlchemyError as e:
        logger.error(f"Database error preparing scan_id={scan_id}: {e}", exc_info=True)
        return

    progress_key = f"scan:progress:{scan_id}"
    url_hash = hashlib.sha256(url.lower().strip().encode("utf-8")).hexdigest()
    cache_key = f"scan:url:{url_hash}"

    check_names = [
        "ssl_check", "headers_check", "dns_check", "port_check",
        "breach_check", "cms_check", "cookie_check",
        "webapp_check", "reputation_check", "infra_check",
    ]

    progress = {name: "pending" for name in check_names}

    try:
        await redis_client.set(progress_key, json.dumps(progress), ex=3600)
    except (ConnectionError, TimeoutError, OSError, ValueError) as e:
        logger.error(f"Redis error setting scan_id={scan_id} progress: {e}", exc_info=True)

    try:
        async def wrap_check(name: str, coroutine: asyncio.Future) -> dict:
            """Run a scanner coroutine with timeout, progress, and safe fallback data."""
            check_start = datetime.now(timezone.utc)
            try:
                progress[name] = "running"
                try:
                    await redis_client.set(progress_key, json.dumps(progress), ex=3600)
                except (ConnectionError, TimeoutError, OSError, ValueError):
                    pass

                # Longer timeout for expanded checks
                timeout = 30.0 if name in ("webapp_check", "infra_check", "cms_check") else 15.0
                res = await asyncio.wait_for(coroutine, timeout=timeout)
                progress[name] = "complete"

                check_duration = int((datetime.now(timezone.utc) - check_start).total_seconds() * 1000)
                logger.info(f"Scan {scan_id} module {name} completed in {check_duration}ms")

                return {"status": "success", "data": _json_safe(asdict(res)), "error": None}
            except Exception as e:
                check_duration = int((datetime.now(timezone.utc) - check_start).total_seconds() * 1000)
                logger.error(f"Scan {scan_id} module {name} failed in {check_duration}ms: {e}", exc_info=True)
                progress[name] = "failed"

                # Safe fallback data for each check type
                fallback_map = {
                    "ssl_check": asdict(ssl_check.SSLResult(error="SSL check unavailable")),
                    "headers_check": asdict(headers_check.HeadersResult(error="Header check unavailable")),
                    "dns_check": asdict(dns_check.DNSResult(error="DNS check unavailable")),
                    "port_check": asdict(port_check.PortResult(error="Port check unavailable")),
                    "breach_check": asdict(breach_check.BreachResult(error="Breach check unavailable")),
                    "cms_check": asdict(cms_check.CMSResult(error="CMS check unavailable")),
                    "cookie_check": asdict(cookie_check.CookieResult(error="Cookie check unavailable")),
                    "webapp_check": asdict(webapp_check.WebAppResult(error="WebApp check unavailable")),
                    "reputation_check": asdict(reputation_check.ReputationResult(error="Reputation check unavailable")),
                    "infra_check": asdict(infra_check.InfraResult(error="Infra check unavailable")),
                }
                raw_data = fallback_map.get(name)
                return {"status": "error", "data": raw_data, "error": "Check failed"}
            finally:
                try:
                    await redis_client.set(progress_key, json.dumps(progress), ex=3600)
                except (ConnectionError, TimeoutError, OSError, ValueError):
                    pass

        # ── Run all 10 checks concurrently ──
        results = await asyncio.gather(
            wrap_check("ssl_check", ssl_check.run(domain)),
            wrap_check("headers_check", headers_check.run(url)),
            wrap_check("dns_check", dns_check.run(domain)),
            wrap_check("port_check", port_check.run(ip_address or "", redis_client)),
            wrap_check("breach_check", breach_check.run(domain)),
            wrap_check("cms_check", cms_check.run(url)),
            wrap_check("cookie_check", cookie_check.run(url)),
            wrap_check("webapp_check", webapp_check.run(url, domain)),
            wrap_check("reputation_check", reputation_check.run(domain)),
            wrap_check("infra_check", infra_check.run(domain, ip_address)),
            return_exceptions=True,
        )

        # ── Map results to domain keys ──
        domain_keys = [
            "ssl", "headers", "dns", "ports", "breach",
            "cms", "cookies", "webapp", "reputation", "infra",
        ]

        raw_findings = {}
        for idx, key in enumerate(domain_keys):
            if isinstance(results[idx], Exception):
                raw_findings[key] = {"status": "error", "error": "Fatal Error"}
            else:
                raw_findings[key] = results[idx]

        all_failed = all(
            res.get("status") == "error"
            for res in raw_findings.values()
            if isinstance(res, dict)
        )

        # ── Classify findings ──
        classifier_data = {k: v.get("data", {}) for k, v in raw_findings.items()}
        classified = classify_findings(classifier_data)

        # ── AI translate ──
        ai_items = await translate_to_plain_english(classified, domain)
        ai_items_dict = [item.model_dump() for item in ai_items]

        # ── Generate executive summary ──
        exec_summary = await generate_executive_summary(classified, domain)

        # ── Calculate overall severity ──
        overall_severity = "GREEN"
        if any(item.severity == "CRITICAL" for item in ai_items):
            overall_severity = "CRITICAL"
        elif any(item.severity == "RED" for item in ai_items):
            overall_severity = "RED"
        elif any(item.severity == "AMBER" for item in ai_items):
            overall_severity = "AMBER"

        # ── Calculate security score ──
        overall_score = _calculate_security_score(raw_findings, classified)

        # ── Calculate DPDP compliance ──
        dpdp_score, dpdp_issues = _calculate_dpdp_compliance(raw_findings, classified)

        # ── Count findings by severity ──
        critical_count = sum(1 for f in classified if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in classified if f.get("severity") == "RED")
        medium_count = sum(1 for f in classified if f.get("severity") == "AMBER")
        low_count = sum(1 for f in classified if f.get("severity") == "GREEN")
        info_count = sum(1 for f in classified if f.get("severity") == "INFO")

        # ── Build domain-specific reports ──
        domain_reports = {}
        for key in domain_keys:
            finding_data = raw_findings.get(key, {})
            if isinstance(finding_data, dict):
                domain_reports[key] = finding_data.get("data", {})

        end_time = datetime.now(timezone.utc)
        duration_ms = int((end_time - start_time).total_seconds() * 1000)

        # ── Persist to database ──
        async with async_session_maker() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalars().first()
            if scan:
                scan.raw_findings = raw_findings
                scan.scan_duration_ms = duration_ms

                if all_failed:
                    scan.status = "failed"
                    scan.error_message = "All scanning checks failed."
                else:
                    scan.status = "complete"

                scan.completed_at = end_time

                if not all_failed:
                    report = Report(
                        scan_id=scan.id,
                        overall_severity=overall_severity,
                        overall_score=overall_score,
                        risk_items=ai_items_dict,
                        ai_summary=exec_summary,
                        executive_summary=exec_summary,
                        checks_run={"checks": list(raw_findings.keys()), "total": TOTAL_CHECK_DOMAINS},
                        domain_reports=_json_safe(domain_reports),
                        ssl_score=0,
                        header_score=classifier_data.get("headers", {}).get("score", 0) if isinstance(classifier_data.get("headers"), dict) else 0,
                        total_findings=len(classified),
                        critical_count=critical_count,
                        high_count=high_count,
                        medium_count=medium_count,
                        low_count=low_count,
                        info_count=info_count,
                        dpdp_compliance_score=dpdp_score,
                        dpdp_issues=dpdp_issues,
                    )
                    db.add(report)

                await db.commit()

                # Cache successful scan
                if not all_failed:
                    try:
                        await redis_client.set(cache_key, str(scan.id), ex=settings.SCAN_CACHE_HOURS * 3600)
                    except (ConnectionError, TimeoutError, OSError, ValueError) as e:
                        logger.error(f"Redis cache error for scan_id={scan_id}: {e}", exc_info=True)

                logger.info(
                    f"Scan {scan_id} completed in {duration_ms}ms with status={scan.status}, "
                    f"findings={len(classified)}, severity={overall_severity}, score={overall_score}"
                )

    except Exception as e:
        logger.error(f"Scan {scan_id} failed catastrophically: {e}", exc_info=True)
        async with async_session_maker() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalars().first()
            if scan:
                scan.status = "failed"
                scan.error_message = "Scan processing failed"
                await db.commit()
    finally:
        try:
            await redis_client.expire(progress_key, 3600)
        except (ConnectionError, TimeoutError, OSError, ValueError) as e:
            logger.error(f"Failed to set scan_id={scan_id} progress TTL: {e}", exc_info=True)
