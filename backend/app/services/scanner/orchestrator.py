"""
Enterprise Scan Orchestrator v3 — runs all 25 check modules with WAF context sharing.

Phase 1 (pre-scan)  : waf_check (result shared with classifier)
Phase 2 (parallel)  : ssl, headers, dns, ports, breach, cms, cookies,
                       webapp, reputation, infra, javascript, cors,
                       http_methods, cloud_exposure, email, performance,
                       tech_inventory, crawl_intelligence
Phase 3 (enterprise): iast_behavioral, oast_check, api_security, graphql,
                       business_logic, container_security, dependency,
                       llm_security (all in parallel, OAST session shared)
Phase 4 (post)      : ASPM score aggregation

Weighted scoring with exploitability multipliers.
Industry benchmark comparison.
"""

import logging
import asyncio
import json
import hashlib
from datetime import datetime, timezone
from dataclasses import asdict
from typing import Dict, Any, List

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import SQLAlchemyError

from app.db.session import async_session_maker
from app.models.scan import Scan
from app.models.report import Report
from app.security.url_validator import SSRFValidator, SSRFValidationError

from app.services.scanner import (
    ssl_check, headers_check, dns_check, port_check,
    breach_check, cms_check, cookie_check,
    webapp_check, reputation_check, infra_check,
    waf_check, javascript_check, cors_check,
    http_methods_check, cloud_exposure_check,
    email_security_check, performance_check,
    tech_inventory, crawl_intelligence
)
# Enterprise modules
from app.services.scanner import iast_behavioral
from app.services.scanner import oast_check
from app.services.scanner import api_security_check
from app.services.scanner import graphql_check
from app.services.scanner import business_logic_check
from app.services.scanner import container_security_check
from app.services.scanner import dependency_check
from app.services.scanner import llm_security_check
from app.services.scanner import identity_auth_check
from app.services.scanner import iac_exposure_check
from app.services.oast.oast_client import OASTClient, OASTUnavailableError
from app.services.aspm_engine import compute_aspm_report
from app.services.cve_intelligence import map_cves
from app.services.classifier import classify_findings
from app.services.ai_translator import translate_to_plain_english, generate_executive_summary
from app.services.benchmark import get_benchmark
from app.services.compliance_mapper import map_to_frameworks
from app.db.session import async_session_maker
from app.models import Report, Scan
from app.config import settings
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

import logging
logger = logging.getLogger(__name__)

TOTAL_CHECK_DOMAINS = 28

# ── New dynamic scoring: R = (CVSS × EM × VF) − MF ──
#
# EM  = Exploitability Multiplier
# VF  = Visibility Factor (1.0 production, 0.6 subdomain, 0.3 internal)
# MF  = Mitigation Factor (deducted for WAF, HSTS, CDN)

# Exploitability multipliers (EM) per finding key
EXPLOITABILITY_MULTIPLIERS: dict[str, float] = {
    # Credential/secret exposure — maximum exploitability
    "webapp_exposed_.env": 2.0,
    "webapp_exposed_.git_config": 2.0,
    "aws_key_in_source": 2.0,
    "cms_api_keys_exposed": 1.8,
    # Direct access to data
    "ports_database_exposed": 2.0,
    "public_cloud_bucket": 2.0,
    "dns_zone_transfer": 2.0,
    # Auth / session compromise
    "cors_credentials_wildcard": 2.0,
    "trace_with_reflection": 1.8,
    "webapp_sql_injection": 2.0,
    "jwt_none_alg_bypass": 2.5,
    "jwt_sensitive_data_exposure": 2.0,
    "iac_tfstate_exposed": 2.5,
    "iac_dockerfile_exposed": 2.0,
    "iac_k8s_manifest_exposed": 2.0,
    # Proof-confirmed findings get 1.5x bonus (set dynamically)
    # _PROOF_CONFIRMED_ -> 1.5x (applied in scoring loop)
    # Network exposure
    "headers_no_https_redirect": 1.5,
    "rep_google_unsafe": 1.5,
    "dangerous_ports_exposed": 1.5,
    # Standard findings
    "dns_no_dmarc": 0.8,
    "dns_dmarc_not_enforced": 0.8,
    "dns_no_spf": 0.8,
    "cms_admin_exposed": 0.7,
    "headers_many_missing": 0.6,
    "headers_some_missing": 0.6,
    "headers_one_missing": 0.5,
    "cors_wildcard_html": 0.5,
    "debug_code_in_production": 0.5,
    # Theoretical / low-reachability CVEs get 0.75x (applied dynamically)
}

# Default CVSS-equivalent base scores for our severity levels
SEVERITY_TO_CVSS: dict[str, float] = {
    "CRITICAL": 9.5,
    "RED":      7.5,
    "AMBER":    5.0,
    "GREEN":    1.0,
    "INFO":     0.5,
}

# Mitigation factors (MF) — subtracted from each finding's R score
MITIGATION_FACTORS = {
    "waf_strong": 1.5,    # Strong WAF (Cloudflare, Akamai, etc.)
    "hsts_enforced": 0.5, # HSTS header present
    "cdn_present": 1.0,   # CDN with security policy detected
}

# Severity weight caps
SEVERITY_WEIGHTS = {
    "CRITICAL": {"points": 25, "max_count": 3},
    "RED": {"points": 10, "max_count": 4},
    "AMBER": {"points": 5, "max_count": 6},
    "GREEN": {"bonus": 2, "max_count": 10},
}

# WAF-mitigated header finding keys
WAF_MITIGATED_KEYS = {
    "headers_some_missing", "headers_one_missing", "headers_many_missing",
    "headers_server_version_exposed", "headers_tech_stack_exposed",
}

STRONG_WAF_PROVIDERS = {"Cloudflare", "AWS CloudFront", "Akamai", "Imperva", "Sucuri", "Azure Front Door"}


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


def _calculate_weighted_score(classified: list, raw_findings: dict, waf_result=None, exceptions: dict = None) -> tuple[int, dict]:
    """
    New Dynamic Risk Scoring Formula: R = (CVSS × EM × VF) − MF

    CVSS = Severity-mapped base score (0-10)
    EM   = Exploitability Multiplier (0.5–2.0)
    VF   = Visibility Factor (1.0 production, 0.6 subdomain, 0.3 internal)
    MF   = Mitigation Factor (WAF, HSTS, CDN deductions)

    All per-finding R scores are summed and normalized to a 0–100 posture score.
    Returns (score_0_to_100, breakdown_dict).
    """
    breakdown = {"deductions": {}, "bonuses": {}, "base": 100, "formula": "R = (CVSS × EM × VF) − MF"}

    # ── Determine Mitigation Factor ──
    mf_total = 0.0
    headers_data = raw_findings.get("headers", {}).get("data", {})
    dns_data = raw_findings.get("dns", {}).get("data", {})

    is_strong_waf = False
    if waf_result and waf_result.get("waf_detected"):
        provider = waf_result.get("waf_provider", "")
        if provider in STRONG_WAF_PROVIDERS:
            mf_total += MITIGATION_FACTORS["waf_strong"]
            breakdown["bonuses"]["waf_strong"] = MITIGATION_FACTORS["waf_strong"]
            is_strong_waf = True
        else:
            mf_total += 0.5
            breakdown["bonuses"]["cdn_detected"] = 0.5

    if isinstance(headers_data, dict):
        redirect_info = headers_data.get("redirect_info", {})
        if isinstance(redirect_info, dict) and redirect_info.get("http_to_https"):
            mf_total += MITIGATION_FACTORS["hsts_enforced"]
            breakdown["bonuses"]["https_enforced"] = MITIGATION_FACTORS["hsts_enforced"]

    # ── Visibility Factor: treat as production (1.0) by default ──
    vf = 1.0

    # ── Sum finding risk scores ──
    total_risk = 0.0
    max_possible_risk = 0.0

    for finding in classified:
        severity = finding.get("severity", "INFO")
        key = finding.get("key", "")

        cvss = SEVERITY_TO_CVSS.get(severity, 0.5)
        em = EXPLOITABILITY_MULTIPLIERS.get(key, 1.0)

        # Proof-confirmed findings get 1.5x EM boost
        if finding.get("proof_confirmed"):
            em = min(em * 1.5, 2.5)

        # WAF mitigates header findings for strong providers
        if is_strong_waf and key in WAF_MITIGATED_KEYS:
            em *= 0.5

        # Theoretical CVEs (not reachable) get 0.75x
        if finding.get("reachability") == "theoretical":
            em *= 0.75

        # ── Handle Accepted Risks (Exceptions) ──
        if exceptions and key in exceptions:
            exc = exceptions[key]
            r = 0.0
            finding["risk_score"] = 0.0
            finding["exception_status"] = exc.status
            finding["exception_justification"] = exc.justification
            finding["exception_owner"] = exc.owner
            finding["exception_expires_at"] = exc.expires_at.isoformat() if exc.expires_at else None
        else:
            r = max(0.0, (cvss * em * vf) - mf_total)
            finding["risk_score"] = round(r, 2)  # annotate finding in-place
            if r > 0:
                breakdown["deductions"][key] = round(r, 2)

        total_risk += r
        max_possible_risk += SEVERITY_TO_CVSS.get("CRITICAL", 9.5) * 2.0 * vf

    # ── Bonus for good security practices ──
    bonus_total = 0.0
    if isinstance(dns_data, dict):
        dmarc = dns_data.get("dmarc", {})
        if isinstance(dmarc, dict) and dmarc.get("policy") in ("reject", "quarantine"):
            bonus_total += 5
            breakdown["bonuses"]["dmarc_enforced"] = 5
        if dns_data.get("dnssec_enabled"):
            bonus_total += 3
            breakdown["bonuses"]["dnssec"] = 3
        if dns_data.get("caa_records"):
            bonus_total += 2
            breakdown["bonuses"]["caa_present"] = 2

    ports_data = raw_findings.get("ports", {}).get("data", {})
    if isinstance(ports_data, dict):
        if not ports_data.get("critical_ports_exposed") and not ports_data.get("dangerous_ports"):
            bonus_total += 5
            breakdown["bonuses"]["no_dangerous_ports"] = 5

    breakdown["total_bonus"] = min(int(bonus_total), 25)

    # ── Normalize to 0–100 ──
    if max_possible_risk > 0:
        denominator = max(max_possible_risk * 0.5, 100.0)
        risk_ratio = min(total_risk / denominator, 1.0)
    else:
        risk_ratio = 0.0

    raw_score = 100.0 - (risk_ratio * 100.0) + bonus_total
    final_score = max(5, min(98, int(round(raw_score))))
    return final_score, breakdown


def _calculate_dpdp_compliance(raw_findings: dict, classified: list) -> tuple[int, list[str]]:
    """Calculate DPDP compliance score."""
    score = 100
    issues: list[str] = []

    ssl_data = raw_findings.get("ssl", {}).get("data", {})
    if isinstance(ssl_data, dict):
        if not ssl_data.get("valid"):
            score -= 20
            issues.append("Website lacks valid encryption certificate — personal data may be transmitted insecurely")
        if ssl_data.get("supports_tls_1_0") or ssl_data.get("supports_tls_1_1"):
            score -= 10
            issues.append("Outdated encryption protocols in use — does not meet data protection standards")

    headers_data = raw_findings.get("headers", {}).get("data", {})
    if isinstance(headers_data, dict):
        redirect_info = headers_data.get("redirect_info", {})
        if isinstance(redirect_info, dict) and not redirect_info.get("http_to_https"):
            score -= 15
            issues.append("No forced encryption — visitors can access site without data protection")

    webapp_data = raw_findings.get("webapp", {}).get("data", {})
    if isinstance(webapp_data, dict):
        exposed = webapp_data.get("exposed_files", [])
        if exposed:
            score -= 20
            issues.append("Sensitive configuration files are publicly accessible — potential personal data exposure")

    ports_data = raw_findings.get("ports", {}).get("data", {})
    if isinstance(ports_data, dict):
        critical_ports = ports_data.get("critical_ports_exposed", [])
        if critical_ports:
            score -= 25
            issues.append("Database ports exposed to internet — personal data at risk of unauthorized access")

    # Cloud buckets
    cloud_data = raw_findings.get("cloud", {}).get("data", {})
    if isinstance(cloud_data, dict):
        if cloud_data.get("public_buckets"):
            score -= 20
            issues.append("Cloud storage buckets are publicly accessible — potential data exposure")

    # CORS
    cors_data = raw_findings.get("cors", {}).get("data", {})
    if isinstance(cors_data, dict):
        if cors_data.get("credentials_with_wildcard"):
            score -= 15
            issues.append("Cross-origin security misconfiguration allows unauthorized data access")

    return max(0, min(100, score)), issues


async def run_full_scan(scan_id: str, url: str, redis_client: Redis) -> None:
    """Orchestrate all 15 check modules with WAF context sharing."""
    logger.info(f"Starting v2 orchestration for scan_id={scan_id}, url={url}")
    start_time = datetime.now(timezone.utc)

    try:
        async with async_session_maker() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalars().first()
            if not scan:
                logger.error(f"Scan {scan_id} not found in DB.")
                return
            await db.refresh(scan)
            # ── Idempotency guard ──
            # With Celery, we expect it to be queued or retrying.
            # If a worker crashed mid-scan, it might be 'running' when a late ack redelivers it.
            if scan.status not in ("queued", "retrying", "running"):
                logger.info(f"Scan {scan_id} already in status={scan.status!r}, skipping duplicate run.")
                return
            scan.status = "running"
            await db.commit()
            domain = scan.domain
            domain_id = scan.domain_id
            ip_address = scan.ip_address
            
            # Fetch active exceptions
            exceptions_map = {}
            if domain_id:
                now_dt = datetime.now(timezone.utc)
                from app.models.risk_exception import RiskException
                exc_result = await db.execute(
                    select(RiskException).where(
                        RiskException.domain_id == domain_id,
                        (RiskException.expires_at == None) | (RiskException.expires_at > now_dt)
                    )
                )
                for exc in exc_result.scalars().all():
                    exceptions_map[exc.finding_key] = exc

    except SQLAlchemyError as e:
        logger.error(f"Database error preparing scan_id={scan_id}: {e}", exc_info=True)
        return

    # ── SSRF Pre-flight Re-validation ──
    # Even if API layer validated it, we re-validate right before executing 
    # to protect against TOCTOU (Time-of-Check to Time-of-Use) DNS rebinding attacks.
    try:
        SSRFValidator.validate_url(url)
    except SSRFValidationError as e:
        logger.critical(f"SSRF validation failed immediately prior to execution for scan_id={scan_id}: {e}")
        try:
            async with async_session_maker() as db:
                result = await db.execute(select(Scan).where(Scan.id == scan_id))
                scan = result.scalars().first()
                if scan:
                    scan.status = "failed"
                    scan.error_message = f"Security Violation: {e}"
                    await db.commit()
        except Exception:
            pass
        return

    progress_key = f"scan:progress:{scan_id}"
    url_hash = hashlib.sha256(url.lower().strip().encode("utf-8")).hexdigest()
    cache_key = f"scan:url:{url_hash}"

    check_names = [
        "waf_check", "ssl_check", "headers_check", "dns_check", "port_check",
        "breach_check", "cms_check", "cookie_check", "webapp_check",
        "reputation_check", "infra_check", "javascript_check", "cors_check",
        "http_methods_check", "cloud_exposure_check",
        "email_security_check", "performance_check", "tech_inventory", "crawl_intelligence",
        # Enterprise modules
        "iast_behavioral", "oast_check", "api_security", "graphql",
        "business_logic", "container_security", "dependency", "llm_security",
        "identity_auth", "iac_exposure",
    ]
    progress = {name: "pending" for name in check_names}

    _redis_ok = True
    try:
        await redis_client.set(progress_key, json.dumps(progress), ex=3600)
    except (ConnectionError, TimeoutError, OSError, ValueError, Exception):
        _redis_ok = False

    async def _save_progress_to_db():
        """Fallback: persist progress dict to scan.raw_findings when Redis is unavailable."""
        try:
            async with async_session_maker() as _db:
                from sqlalchemy import select as _select
                _res = await _db.execute(_select(Scan).where(Scan.id == scan_id))
                _scan = _res.scalars().first()
                if _scan:
                    _findings = dict(_scan.raw_findings or {})
                    _findings["_progress"] = progress
                    _scan.raw_findings = _findings
                    await _db.commit()
        except Exception as _e:
            logger.debug(f"DB progress fallback failed: {_e}")

    try:
        async def wrap_check(name: str, coroutine, fallback_factory) -> dict:
            """Run a scanner coroutine with timeout, progress, and safe fallback."""
            check_start = datetime.now(timezone.utc)
            try:
                progress[name] = "running"
                try:
                    await redis_client.set(progress_key, json.dumps(progress), ex=3600)
                except (ConnectionError, TimeoutError, OSError, ValueError):
                    pass

                timeout_map = {
                    "webapp_check": 45.0, 
                    "infra_check": 45.0, 
                    "cms_check": 45.0,
                    "javascript_check": 30.0, 
                    "cloud_exposure_check": 60.0,
                    "cors_check": 20.0,
                    "dns_check": 60.0,
                    "port_check": 90.0,
                    "email_security_check": 60.0,
                    "tech_inventory": 45.0,
                    "crawl_intelligence": 60.0,
                    "ssl_check": 60.0,
                    "performance_check": 30.0,
                }
                timeout = timeout_map.get(name, 30.0)
                res = await asyncio.wait_for(coroutine, timeout=timeout)
                progress[name] = "complete"
                ms = int((datetime.now(timezone.utc) - check_start).total_seconds() * 1000)
                logger.info(f"Scan {scan_id} module {name} completed in {ms}ms")
                return {"status": "success", "data": _json_safe(asdict(res)), "error": None}
            except Exception as e:
                ms = int((datetime.now(timezone.utc) - check_start).total_seconds() * 1000)
                logger.error(f"Scan {scan_id} module {name} failed in {ms}ms: {e}", exc_info=True)
                progress[name] = "failed"
                return {"status": "error", "data": _json_safe(asdict(fallback_factory())), "error": str(e)[:200]}
            finally:
                try:
                    await redis_client.set(progress_key, json.dumps(progress), ex=3600)
                except (ConnectionError, TimeoutError, OSError, ValueError, Exception):
                    # Redis unavailable — persist progress to DB as fallback
                    await _save_progress_to_db()


        waf_raw = await wrap_check(
            "waf_check",
            waf_check.run(url, domain, ip_address),
            lambda: waf_check.WAFResult(error="WAF check unavailable"),
        )
        waf_data = waf_raw.get("data", {})


        results = await asyncio.gather(
            wrap_check("ssl_check", ssl_check.run(domain), lambda: ssl_check.SSLResult(error="unavailable")),
            wrap_check("headers_check", headers_check.run(url), lambda: headers_check.HeadersResult(error="unavailable")),
            wrap_check("dns_check", dns_check.run(domain), lambda: dns_check.DNSResult(error="unavailable")),
            wrap_check("port_check", port_check.run(ip_address or "", redis_client), lambda: port_check.PortResult(error="unavailable")),
            wrap_check("breach_check", breach_check.run(domain), lambda: breach_check.BreachResult(error="unavailable")),
            wrap_check("cms_check", cms_check.run(url), lambda: cms_check.CMSResult(error="unavailable")),
            wrap_check("cookie_check", cookie_check.run(url), lambda: cookie_check.CookieResult(error="unavailable")),
            wrap_check("webapp_check", webapp_check.run(url, domain), lambda: webapp_check.WebAppResult(error="unavailable")),
            wrap_check("reputation_check", reputation_check.run(domain), lambda: reputation_check.ReputationResult(error="unavailable")),
            wrap_check("infra_check", infra_check.run(domain, ip_address), lambda: infra_check.InfraResult(error="unavailable")),
            wrap_check("javascript_check", javascript_check.run(url, domain), lambda: javascript_check.JavaScriptResult(error="unavailable")),
            wrap_check("cors_check", cors_check.run(url), lambda: cors_check.CORSResult(error="unavailable")),
            wrap_check("http_methods_check", http_methods_check.run(url), lambda: http_methods_check.HTTPMethodsResult(error="unavailable")),
            wrap_check("cloud_exposure_check", cloud_exposure_check.run(domain), lambda: cloud_exposure_check.CloudResult(error="unavailable")),
            wrap_check("email_security_check", email_security_check.run(domain), lambda: email_security_check.EmailSecurityResult(0, "F", "", "", False, False, False, False, {}, error="unavailable")),
            wrap_check("performance_check", performance_check.run(domain), lambda: performance_check.PerformanceResult(error="unavailable")),
            wrap_check("tech_inventory", tech_inventory.run(domain), lambda: tech_inventory.TechInventoryResult(error="unavailable")),
            wrap_check("crawl_intelligence", crawl_intelligence.run(domain), lambda: crawl_intelligence.CrawlResult(error="unavailable")),
            return_exceptions=True,
        )

        # ── Map results ──
        domain_keys = [
            "ssl", "headers", "dns", "ports", "breach", "cms", "cookies",
            "webapp", "reputation", "infra", "javascript", "cors",
            "http_methods", "cloud", "email", "performance", "tech", "crawl"
        ]

        raw_findings = {"waf": waf_raw}
        for idx, key in enumerate(domain_keys):
            if isinstance(results[idx], Exception):
                raw_findings[key] = {"status": "error", "error": "Fatal Error"}
            else:
                raw_findings[key] = results[idx]
                
        # ── Phase 3: CVE Intelligence ──
        if "tech" in raw_findings and raw_findings["tech"].get("status") == "success":
            tech_data = raw_findings["tech"].get("data", {})
            technologies = tech_data.get("technologies", [])
            if technologies:
                try:
                    cve_results = await map_cves(technologies)
                    raw_findings["cve"] = {"status": "success", "data": _json_safe({k: asdict(v) for k, v in cve_results.items()})}
                except Exception as e:
                    logger.warning(f"CVE intelligence failed for {domain}: {e}")
                    raw_findings["cve"] = {"status": "error", "error": str(e)}

        # ── Phase 3b: Enterprise Security Modules ──
        # Start OAST session for shared use across OAST + IAST probes
        oast_client: Optional[OASTClient] = None
        try:
            oast_client = OASTClient()
            await oast_client.start_session()
        except OASTUnavailableError as exc:
            logger.warning(f"OAST session unavailable (degraded mode): {exc}")
            oast_client = None

        async def wrap_enterprise(name: str, coro, fallback: dict) -> dict:
            """Run an enterprise module coroutine with timeout and fallback."""
            # Per-module timeouts — must all complete well within Celery's 5-min limit
            enterprise_timeout_map = {
                "iast_behavioral":    25.0,
                "oast_check":         25.0,
                "api_security":       30.0,
                "graphql":            20.0,
                "business_logic":     30.0,
                "container_security": 20.0,
                "dependency":         20.0,
                "llm_security":       20.0,
                "identity_auth":      20.0,
                "iac_exposure":       20.0,
            }
            timeout = enterprise_timeout_map.get(name, 25.0)
            try:
                progress[name] = "running"
                try:
                    await redis_client.set(progress_key, json.dumps(progress), ex=3600)
                except Exception:
                    pass
                result_obj = await asyncio.wait_for(coro, timeout=timeout)
                progress[name] = "complete"
                try:
                    await redis_client.set(progress_key, json.dumps(progress), ex=3600)
                except Exception:
                    pass
                # Convert dataclass to dict if necessary
                if hasattr(result_obj, "__dict__"):
                    return _json_safe(result_obj.__dict__)
                return _json_safe(result_obj)
            except Exception as exc:
                logger.error(f"Enterprise module {name} failed: {exc}", exc_info=True)
                progress[name] = "failed"
                return {**fallback, "error": str(exc)[:200]}

        ent_iast, ent_oast, ent_api, ent_graphql, ent_bl, ent_container, ent_dep, ent_llm, ent_identity, ent_iac = \
            await asyncio.gather(
                wrap_enterprise("iast_behavioral",
                    iast_behavioral.run(url, domain),
                    {"error_verbosity_score": 0, "probes_sent": 0}),
                wrap_enterprise("oast_check",
                    oast_check.run(url, domain, oast_client),
                    {"ssrf_confirmed": False, "probes_sent": 0}),
                wrap_enterprise("api_security",
                    api_security_check.run(url, domain),
                    {"endpoints_discovered": []}),
                wrap_enterprise("graphql",
                    graphql_check.run(url, domain),
                    {"graphql_detected": False}),
                wrap_enterprise("business_logic",
                    business_logic_check.run(url, domain),
                    {"probes_sent": 0}),
                wrap_enterprise("container_security",
                    container_security_check.run(url, domain),
                    {"findings": []}),
                wrap_enterprise("dependency",
                    dependency_check.run(url, domain),
                    {"detected_libraries": []}),
                wrap_enterprise("llm_security",
                    llm_security_check.run(url, domain),
                    {"llm_surface_detected": False}),
                wrap_enterprise("identity_auth",
                    identity_auth_check.run(url, domain),
                    {"findings": []}),
                wrap_enterprise("iac_exposure",
                    iac_exposure_check.run(url, domain),
                    {"findings": []}),
                return_exceptions=False,
            )

        # Close OAST session if active
        if oast_client:
            try:
                await oast_client.stop_session()
            except Exception:
                pass

        enterprise_results = {
            "iast": ent_iast,
            "oast": ent_oast,
            "api_security": ent_api,
            "graphql": ent_graphql,
            "business_logic": ent_bl,
            "container": ent_container,
            "dependency": ent_dep,
            "llm_security": ent_llm,
            "identity_auth": ent_identity,
            "iac_exposure": ent_iac,
        }

        # Save report if ANY module succeeded (not all_failed)
        any_succeeded = any(
            isinstance(res, dict) and res.get("status") == "success"
            for key, res in raw_findings.items()
            if key != "waf"
        )
        all_failed = not any_succeeded

        # ── Classify findings with WAF context ──
        classifier_data = {k: v.get("data", {}) for k, v in raw_findings.items()}
        classified = classify_findings(classifier_data, waf_context=waf_data)

        # ── Compliance mapping (runs on classified list which always has 'key') ──
        try:
            compliance_result = map_to_frameworks(classified)
            compliance_report_dict = _json_safe(compliance_result.to_dict())
        except Exception as e:
            logger.warning(f"Compliance mapping failed for {domain}: {e}")
            compliance_report_dict = None

        # ── Weighted score ──
        overall_score, score_breakdown = _calculate_weighted_score(classified, raw_findings, waf_data, exceptions_map)

        # ── Phase 4: ASPM Score (enterprise-adjusted) ──
        try:
            aspm_report = compute_aspm_report(
                classified_findings=classified,
                raw_findings=raw_findings,
                enterprise_results=enterprise_results,
                base_score=overall_score,
            )
            aspm_data = _json_safe(aspm_report.__dict__)
        except Exception as exc:
            logger.warning(f"ASPM computation failed: {exc}")
            aspm_data = None

        # ── AI translate (non-fatal) ──
        try:
            ai_items = await asyncio.wait_for(
                translate_to_plain_english(classified, domain), timeout=60.0
            )
        except Exception as ai_err:
            logger.warning(f"AI translation failed for {domain}: {ai_err}")
            ai_items = []
        ai_items_dict = []
        for i, item in enumerate(ai_items):
            d = item.model_dump()
            if i < len(classified):
                d["risk_score"] = classified[i].get("risk_score")
                d["compliance_violations"] = classified[i].get("compliance_violations", [])
            ai_items_dict.append(d)

        # ── Executive summary (non-fatal) ──
        try:
            exec_summary = await asyncio.wait_for(
                generate_executive_summary(classified, domain), timeout=60.0
            )
        except Exception as ai_err:
            logger.warning(f"Executive summary generation failed for {domain}: {ai_err}")
            exec_summary = f"Security scan completed for {domain}. Review findings for details."

        # ── Overall severity ──
        overall_severity = "GREEN"
        if any(item.severity == "CRITICAL" for item in ai_items):
            overall_severity = "CRITICAL"
        elif any(item.severity == "RED" for item in ai_items):
            overall_severity = "RED"
        elif any(item.severity == "AMBER" for item in ai_items):
            overall_severity = "AMBER"

        # ── DPDP compliance ──
        dpdp_score, dpdp_issues = _calculate_dpdp_compliance(raw_findings, classified)

        # ── Industry benchmark ──
        benchmark = get_benchmark(domain, overall_score)

        # ── Counts ──
        critical_count = sum(1 for f in classified if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in classified if f.get("severity") == "RED")
        medium_count = sum(1 for f in classified if f.get("severity") == "AMBER")
        low_count = sum(1 for f in classified if f.get("severity") == "GREEN")
        info_count = sum(1 for f in classified if f.get("severity") == "INFO")

        # ── Domain reports ──
        domain_reports = {}
        for key in list(domain_keys) + ["waf"]:
            finding_data = raw_findings.get(key, {})
            if isinstance(finding_data, dict):
                domain_reports[key] = finding_data.get("data", {})

        domain_reports["score_breakdown"] = score_breakdown
        domain_reports["industry_benchmark"] = benchmark

        # Use ASPM score as the definitive overall score
        if aspm_data:
            overall_score = aspm_data.get("aspm_score", overall_score)
            domain_reports["aspm"] = aspm_data

        # Store enterprise results in domain_reports
        domain_reports["enterprise"] = enterprise_results

        end_time = datetime.now(timezone.utc)
        duration_ms = int((end_time - start_time).total_seconds() * 1000)

        # ── Persist ──
        try:
            async with async_session_maker() as db:
                result = await db.execute(select(Scan).where(Scan.id == scan_id))
                scan = result.scalars().first()
                if scan:
                    scan.raw_findings = raw_findings
                    scan.scan_duration_ms = duration_ms
                    scan.status = "failed" if all_failed else "complete"
                    if all_failed:
                        scan.error_message = "All scanning checks failed."
                    scan.completed_at = end_time

                    if True:
                        report = Report(
                            scan_id=scan.id,
                            overall_severity="CRITICAL" if all_failed else overall_severity,
                            overall_score=0 if all_failed else overall_score,
                            risk_items=[] if all_failed else ai_items_dict,
                            ai_summary="Scan failed. Detailed AI analysis is currently unavailable." if all_failed else exec_summary,
                            executive_summary="Scan failed." if all_failed else exec_summary,
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
                            waf_detected=waf_data.get("waf_detected", False),
                            waf_provider=waf_data.get("waf_provider"),
                            javascript_findings=domain_reports.get("javascript"),
                            cors_findings=domain_reports.get("cors"),
                            cloud_findings=domain_reports.get("cloud"),
                            email_findings=domain_reports.get("email"),
                            performance_findings=domain_reports.get("performance"),
                            tech_findings=domain_reports.get("tech"),
                            crawl_findings=domain_reports.get("crawl"),
                            compliance_report=compliance_report_dict,
                            brand_threats=_json_safe(domain_reports.get("reputation", {})),
                            bola_findings=_json_safe(enterprise_results.get("api_security", {})),
                            api_findings=_json_safe(enterprise_results.get("api_security", {})),
                            llm_findings=_json_safe(enterprise_results.get("llm_security", {})),
                            oast_interactions=_json_safe(enterprise_results.get("oast", {})),
                            cve_findings=domain_reports.get("cve"),
                            
                            # v2 Enterprise Fields
                            owasp_coverage=_json_safe(aspm_data.get("owasp_coverage")) if aspm_data else None,
                            owasp_llm_coverage=_json_safe(aspm_data.get("owasp_llm_structured")) if aspm_data else None,
                            compliance_report_v2=_json_safe(aspm_data.get("compliance_v2")) if aspm_data else None,
                            dpdp_penalty_crore=aspm_data.get("dpdp_penalty_crore") if aspm_data else None,
                            ale_reduction_total=aspm_data.get("total_ale_reduction_inr") if aspm_data else None,
                            kev_findings_count=aspm_data.get("kev_findings_count") if aspm_data else 0,
                            severity_adjusted_count=aspm_data.get("severity_adjusted_count") if aspm_data else 0,
                        )
                        db.add(report)

                    await db.commit()

                    if not all_failed:
                        try:
                            await redis_client.set(cache_key, str(scan.id), ex=settings.SCAN_CACHE_HOURS * 3600)
                        except (ConnectionError, TimeoutError, OSError, ValueError):
                            pass

                        # Send report ready email asynchronously if user is attached
                        if scan.user_id:
                            try:
                                from app.models.user import User
                                user_res = await db.execute(select(User).where(User.id == scan.user_id))
                                user = user_res.scalars().first()
                                if user and user.email:
                                    from app.services.email_service import send_report_ready_email
                                    grade = aspm_data.get("compliance_v2", {}).get("grade", overall_severity) if aspm_data else overall_severity
                                    asyncio.create_task(asyncio.to_thread(
                                        send_report_ready_email,
                                        user.email,
                                        scan.domain,
                                        overall_score,
                                        grade,
                                        str(scan.id)
                                    ))
                            except Exception as e:
                                logger.error(f"Failed to trigger report ready email for scan {scan_id}: {e}")

                    logger.info(
                        f"Scan {scan_id} completed in {duration_ms}ms: "
                        f"status={scan.status}, findings={len(classified)}, "
                        f"severity={overall_severity}, score={overall_score}"
                    )
        except Exception as persist_err:
            logger.error(f"Scan {scan_id} DB persist failed: {persist_err}", exc_info=True)
            # Try to at least mark the scan as complete even if report save failed
            try:
                async with async_session_maker() as db2:
                    result2 = await db2.execute(select(Scan).where(Scan.id == scan_id))
                    scan2 = result2.scalars().first()
                    if scan2 and scan2.status not in ("complete", "failed"):
                        scan2.status = "complete" if not all_failed else "failed"
                        scan2.completed_at = end_time
                        await db2.commit()
            except Exception as fallback_err:
                logger.error(f"Scan {scan_id} fallback status update failed: {fallback_err}")

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
        except (ConnectionError, TimeoutError, OSError, ValueError):
            pass
