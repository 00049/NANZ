"""
ASPM Engine — Application Security Posture Management scoring hub.

Aggregates all 25+ scan module outputs into a unified risk score,
OWASP coverage map, remediation roadmap, and ASPM posture tier.

This is the central intelligence layer of the enterprise scan engine.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Any

logger = logging.getLogger(__name__)

# ── ASPM Posture Tiers ────────────────────────────────────────────────────────

POSTURE_TIERS = {
    (90, 100): {
        "tier": "SECURE",
        "label": "Enterprise Secure",
        "color": "#00d97e",
        "description": "Security posture meets enterprise standards. Maintain with quarterly audits.",
    },
    (75, 89): {
        "tier": "HARDENED",
        "label": "Hardened",
        "color": "#00b4d8",
        "description": "Strong security posture with minor gaps. Address medium-risk findings.",
    },
    (55, 74): {
        "tier": "MODERATE",
        "label": "Moderate Risk",
        "color": "#f9c74f",
        "description": "Security gaps present that require attention. High-risk items need remediation.",
    },
    (35, 54): {
        "tier": "AT_RISK",
        "label": "At Risk",
        "color": "#f77f00",
        "description": "Significant vulnerabilities detected. Immediate remediation required.",
    },
    (0, 34): {
        "tier": "CRITICAL",
        "label": "Critical Exposure",
        "color": "#d62828",
        "description": "Critical security failures. Business continuity and data integrity at risk.",
    },
}

# ── OWASP Top 10 2021 Coverage Mapping ────────────────────────────────────────

OWASP_TOP10_COVERAGE = {
    "A01_Broken_Access_Control": {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "modules": ["api_security_check", "business_logic_check", "cors_check"],
        "finding_keys": ["bola_vulnerable_endpoints", "auth_bypass_endpoints",
                         "cors_credentials_wildcard", "cms_admin_no_auth"],
    },
    "A02_Cryptographic_Failures": {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "modules": ["ssl_check", "http_methods_check", "cookie_check"],
        "finding_keys": ["ssl_invalid", "ssl_tls10_supported", "ssl_tls11_supported",
                         "session_cookie_insecure", "headers_no_https_redirect"],
    },
    "A03_Injection": {
        "id": "A03:2021",
        "name": "Injection",
        "modules": ["webapp_check", "iast_behavioral", "oast_check"],
        "finding_keys": ["webapp_sql_injection", "db_errors_found", "xss_surfaces_found"],
    },
    "A04_Insecure_Design": {
        "id": "A04:2021",
        "name": "Insecure Design",
        "modules": ["business_logic_check", "api_security_check"],
        "finding_keys": ["price_manipulation_surface", "account_enumeration_confirmed",
                         "transaction_replay_surface"],
    },
    "A05_Security_Misconfiguration": {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "modules": ["headers_check", "graphql_check", "cors_check", "http_methods_check"],
        "finding_keys": ["headers_many_missing", "graphql_introspection_enabled",
                         "debug_endpoints_exposed", "swagger_ui_exposed"],
    },
    "A06_Vulnerable_Components": {
        "id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "modules": ["dependency_check", "javascript_check", "cms_check"],
        "finding_keys": ["vulnerable_libraries", "jquery_outdated", "cms_wp_vulnerable_plugins"],
    },
    "A07_Authentication_Failures": {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "modules": ["api_security_check", "business_logic_check"],
        "finding_keys": ["auth_bypass_endpoints", "missing_rate_limiting",
                         "account_enumeration_confirmed"],
    },
    "A08_Data_Integrity": {
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "modules": ["dependency_check", "javascript_check"],
        "finding_keys": ["dependency_confusion_risk", "source_map_exposed"],
    },
    "A09_Logging_Failures": {
        "id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "modules": ["iast_behavioral", "headers_check"],
        "finding_keys": ["stack_traces_found", "debug_endpoints_exposed",
                         "error_verbosity_score"],
    },
    "A10_SSRF": {
        "id": "A10:2021",
        "name": "Server-Side Request Forgery",
        "modules": ["oast_check"],
        "finding_keys": ["ssrf_confirmed", "ssrf_endpoints"],
    },
}

# ── Remediation Priority Framework ────────────────────────────────────────────

REMEDIATION_PRIORITY_WEIGHTS = {
    "CRITICAL": 100,
    "RED": 60,
    "AMBER": 25,
    "GREEN": 5,
    "INFO": 1,
}

# ── Module Weight Distribution (total = 100 points) ──────────────────────────

MODULE_WEIGHTS = {
    # Core security
    "ssl": 8.0,
    "headers": 7.0,
    "dns": 6.0,
    "ports": 8.0,
    "cors": 5.0,
    "http_methods": 3.0,
    # Enterprise modules
    "api_security": 8.0,
    "graphql": 4.0,
    "business_logic": 6.0,
    "iast": 6.0,
    "oast": 5.0,
    "dependency": 5.0,
    "llm_security": 3.0,
    "container": 5.0,
    # Platform
    "webapp": 7.0,
    "cms": 4.0,
    "reputation": 5.0,
    "cloud": 5.0,
    "javascript": 4.0,
    # Total: ~100
}


@dataclass
class OWASPCoverage:
    """OWASP Top 10 coverage result for a single category."""
    id: str
    name: str
    covered: bool
    findings_count: int
    severity: str    # worst severity in this category
    modules_tested: list = field(default_factory=list)


@dataclass
class RemediationItem:
    """Ordered remediation action with effort + impact."""
    priority: int
    severity: str
    title: str
    finding_key: str
    module: str
    estimated_fix_time: str
    impact_score: float
    quick_win: bool = False


@dataclass
class ASPMReport:
    """Unified ASPM posture report."""
    # Posture score (0-100)
    aspm_score: int
    posture_tier: str
    posture_label: str
    posture_color: str
    posture_description: str

    # Risk breakdown
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    total_findings: int

    # OWASP coverage
    owasp_coverage: list = field(default_factory=list)   # list of OWASPCoverage dicts
    owasp_covered_count: int = 0
    owasp_total: int = 10

    # Module coverage
    modules_tested: list = field(default_factory=list)
    modules_with_findings: list = field(default_factory=list)
    enterprise_modules_active: bool = False

    # Remediation roadmap
    remediation_roadmap: list = field(default_factory=list)   # ordered RemediationItem dicts
    quick_wins: list = field(default_factory=list)
    immediate_actions: list = field(default_factory=list)

    # Compliance impact
    dpdp_impact: float = 0.0
    gdpr_impact: float = 0.0
    pci_impact: float = 0.0

    # Trends (if historical data available)
    score_trend: str = "stable"   # "improving", "declining", "stable"

    generated_at: str = ""


def compute_aspm_report(
    classified_findings: list[dict],
    raw_findings: dict[str, Any],
    enterprise_results: dict[str, Any],
    base_score: int,
) -> ASPMReport:
    """
    Compute the ASPM report from all module outputs.

    Args:
        classified_findings: List of classified finding dicts from classifier.py
        raw_findings: Raw per-module results dict from orchestrator
        enterprise_results: Dict with enterprise module results (iast, oast, api, etc.)
        base_score: The base weighted score computed by orchestrator
    """

    # ── Merge enterprise findings into overall severity counts ──
    all_findings = list(classified_findings)
    _merge_enterprise_findings(all_findings, enterprise_results)

    critical = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in all_findings if f.get("severity") == "RED")
    medium = sum(1 for f in all_findings if f.get("severity") == "AMBER")
    low = sum(1 for f in all_findings if f.get("severity") in ("GREEN", "INFO"))

    # ── Compute enterprise-adjusted ASPM score ──
    aspm_score = _compute_aspm_score(base_score, enterprise_results, critical, high)

    # ── Determine posture tier ──
    tier_data = _get_posture_tier(aspm_score)

    # ── OWASP Top 10 coverage map ──
    owasp_coverage = _compute_owasp_coverage(all_findings, enterprise_results)
    covered_count = sum(1 for c in owasp_coverage if c["covered"])

    # ── Build remediation roadmap ──
    roadmap = _build_remediation_roadmap(all_findings, enterprise_results)
    quick_wins = [r for r in roadmap if r.get("quick_win")][:5]
    immediate = [r for r in roadmap if r.get("severity") == "CRITICAL"][:5]

    # ── Compliance impact ──
    dpdp_impact = _estimate_compliance_impact(all_findings, "dpdp")
    gdpr_impact = _estimate_compliance_impact(all_findings, "gdpr")
    pci_impact = _estimate_compliance_impact(all_findings, "pci")

    # ── Modules tested ──
    modules_tested = list(raw_findings.keys()) + list(enterprise_results.keys())
    enterprise_keys = set(enterprise_results.keys())
    modules_with_findings = [
        k for k, v in enterprise_results.items()
        if v and not v.get("error")
    ] + [
        k for k in raw_findings
        if raw_findings[k].get("status") == "success"
    ]

    return ASPMReport(
        aspm_score=aspm_score,
        posture_tier=tier_data["tier"],
        posture_label=tier_data["label"],
        posture_color=tier_data["color"],
        posture_description=tier_data["description"],
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        total_findings=len(all_findings),
        owasp_coverage=[c.__dict__ if hasattr(c, "__dict__") else c for c in owasp_coverage],
        owasp_covered_count=covered_count,
        owasp_total=10,
        modules_tested=list(set(modules_tested)),
        modules_with_findings=list(set(modules_with_findings)),
        enterprise_modules_active=bool(enterprise_keys),
        remediation_roadmap=[r.__dict__ if hasattr(r, "__dict__") else r for r in roadmap[:20]],
        quick_wins=[r.__dict__ if hasattr(r, "__dict__") else r for r in quick_wins],
        immediate_actions=[r.__dict__ if hasattr(r, "__dict__") else r for r in immediate],
        dpdp_impact=round(dpdp_impact, 1),
        gdpr_impact=round(gdpr_impact, 1),
        pci_impact=round(pci_impact, 1),
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


def _compute_aspm_score(
    base_score: int,
    enterprise_results: dict,
    critical: int,
    high: int,
) -> int:
    """
    Adjust base score with enterprise module findings.
    Enterprise findings can lower the score further if they reveal
    issues not captured by base modules.
    """
    penalty = 0

    # OAST confirmations — severe
    oast = enterprise_results.get("oast") or {}
    if oast.get("ssrf_confirmed"):
        penalty += 20
    if oast.get("header_injection_confirmed"):
        penalty += 12
    if oast.get("log4j_surface_detected"):
        penalty += 15

    # IAST behavioral
    iast = enterprise_results.get("iast") or {}
    if iast.get("stack_traces_found"):
        penalty += len(iast["stack_traces_found"]) * 5
    if iast.get("db_errors_found"):
        penalty += len(iast["db_errors_found"]) * 8
    verbosity = iast.get("error_verbosity_score", 0)
    penalty += verbosity // 10

    # API security
    api = enterprise_results.get("api_security") or {}
    if api.get("bola_vulnerable_endpoints"):
        penalty += len(api["bola_vulnerable_endpoints"]) * 10
    if api.get("auth_bypass_endpoints"):
        penalty += len(api["auth_bypass_endpoints"]) * 15

    # GraphQL
    gql = enterprise_results.get("graphql") or {}
    if gql.get("introspection_enabled"):
        penalty += 5
    if gql.get("depth_limit_missing") and gql.get("rate_limit_missing"):
        penalty += 8

    # Container
    container = enterprise_results.get("container") or {}
    if container.get("docker_registry_exposed"):
        penalty += 15
    if container.get("k8s_api_exposed"):
        penalty += 25
    if container.get("k8s_dashboard_exposed"):
        penalty += 20

    # LLM
    llm = enterprise_results.get("llm_security") or {}
    if llm.get("api_keys_in_response"):
        penalty += 30  # Critical — exposed API keys
    if llm.get("system_prompt_leaked"):
        penalty += 10

    # Business logic
    bl = enterprise_results.get("business_logic") or {}
    if bl.get("account_enumeration_confirmed"):
        penalty += 8
    if bl.get("predictable_ids_found"):
        penalty += 5

    adjusted = max(5, min(100, base_score - penalty))
    return adjusted


def _get_posture_tier(score: int) -> dict:
    for (lo, hi), tier_data in POSTURE_TIERS.items():
        if lo <= score <= hi:
            return tier_data
    return POSTURE_TIERS[(0, 34)]


def _merge_enterprise_findings(all_findings: list, enterprise_results: dict) -> None:
    """Normalize enterprise module results into the classified findings list."""
    # OAST
    oast = enterprise_results.get("oast") or {}
    if oast.get("ssrf_confirmed"):
        all_findings.append({"severity": "CRITICAL", "key": "oast_ssrf_confirmed",
                              "check": "oast", "detail": "SSRF confirmed via OAST callback"})
    if oast.get("log4j_surface_detected"):
        all_findings.append({"severity": "CRITICAL", "key": "oast_log4j_surface",
                              "check": "oast", "detail": "Log4Shell surface detected"})
    for xss in (oast.get("xss_surfaces_found") or []):
        all_findings.append({"severity": "AMBER", "key": "oast_xss_surface",
                              "check": "oast", "detail": xss.get("description", "XSS surface")})

    # IAST
    iast = enterprise_results.get("iast") or {}
    for st in (iast.get("stack_traces_found") or []):
        all_findings.append({"severity": "CRITICAL", "key": "iast_stack_trace",
                              "check": "iast", "detail": f"Stack trace in response: {st.get('framework', '')}"})
    for db in (iast.get("db_errors_found") or []):
        all_findings.append({"severity": "CRITICAL", "key": "iast_db_error",
                              "check": "iast", "detail": f"DB error: {db.get('db_type', '')}"})

    # API security
    api = enterprise_results.get("api_security") or {}
    for ep in (api.get("bola_vulnerable_endpoints") or []):
        all_findings.append({"severity": "CRITICAL", "key": "api_bola",
                              "check": "api_security", "detail": f"BOLA at {ep}"})

    # Container
    container = enterprise_results.get("container") or {}
    if container.get("k8s_api_exposed"):
        all_findings.append({"severity": "CRITICAL", "key": "container_k8s_api",
                              "check": "container", "detail": "K8s API server exposed"})
    if container.get("docker_registry_exposed"):
        all_findings.append({"severity": "RED", "key": "container_docker_registry",
                              "check": "container", "detail": "Docker registry exposed"})

    # LLM
    llm = enterprise_results.get("llm_security") or {}
    for key_item in (llm.get("api_keys_in_response") or []):
        all_findings.append({"severity": "CRITICAL", "key": "llm_api_key_exposed",
                              "check": "llm_security", "detail": f"{key_item.get('type', 'API key')} exposed"})


def _compute_owasp_coverage(
    all_findings: list,
    enterprise_results: dict,
) -> list[OWASPCoverage]:
    """Compute OWASP Top 10 coverage from all findings."""
    results = []
    finding_keys = {f.get("key", "") for f in all_findings}
    finding_checks = {f.get("check", "") for f in all_findings}

    for category_id, category_data in OWASP_TOP10_COVERAGE.items():
        # Check if any module for this category was tested
        modules_tested = [
            m for m in category_data["modules"]
            if m in finding_checks or any(
                m in k.get("modules_tested", [])
                for k in [enterprise_results.get(m) or {}]
            )
        ]

        # Count findings in this category
        cat_findings = [
            f for f in all_findings
            if f.get("key") in category_data["finding_keys"]
            or f.get("check") in category_data["modules"]
        ]

        worst_severity = "INFO"
        severity_order = ["CRITICAL", "RED", "AMBER", "GREEN", "INFO"]
        for sev in severity_order:
            if any(f.get("severity") == sev for f in cat_findings):
                worst_severity = sev
                break

        results.append(OWASPCoverage(
            id=category_data["id"],
            name=category_data["name"],
            covered=len(modules_tested) > 0,
            findings_count=len(cat_findings),
            severity=worst_severity if cat_findings else "INFO",
            modules_tested=modules_tested,
        ).__dict__)

    return results


def _build_remediation_roadmap(
    all_findings: list,
    enterprise_results: dict,
) -> list[RemediationItem]:
    """Build a prioritized remediation roadmap."""
    roadmap = []

    # Fix time estimates by severity
    fix_times = {
        "CRITICAL": "24-48 hours",
        "RED": "1-2 weeks",
        "AMBER": "1-4 weeks",
        "GREEN": "Next sprint",
        "INFO": "Optional",
    }

    # Quick win thresholds — findings that are fast to fix
    quick_win_keys = {
        "headers_many_missing", "headers_some_missing", "dns_no_dmarc",
        "dns_no_spf", "headers_no_https_redirect", "debug_code_in_production",
        "dns_dmarc_not_enforced", "headers_hsts_short_max_age",
    }

    for i, finding in enumerate(all_findings):
        severity = finding.get("severity", "INFO")
        key = finding.get("key", f"finding_{i}")
        weight = REMEDIATION_PRIORITY_WEIGHTS.get(severity, 1)

        roadmap.append(RemediationItem(
            priority=i + 1,
            severity=severity,
            title=finding.get("detail", finding.get("key", "Security Issue"))[:100],
            finding_key=key,
            module=finding.get("check", "unknown"),
            estimated_fix_time=fix_times.get(severity, "variable"),
            impact_score=weight,
            quick_win=key in quick_win_keys,
        ).__dict__)

    # Sort by impact score (desc), then quick wins first within same score
    roadmap.sort(key=lambda x: (-x["impact_score"], not x["quick_win"]))

    # Re-number after sort
    for i, item in enumerate(roadmap):
        item["priority"] = i + 1

    return roadmap


def _estimate_compliance_impact(
    findings: list,
    framework: str,
) -> float:
    """
    Estimate compliance impact score (0-100, higher = more violations).
    """
    impact = 0.0
    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "RED")

    if framework == "dpdp":
        # DPDP Act (India) — data protection focused
        impact = min(100, critical * 20 + high * 10)
        # Bonus deduction for encryption failures
        ssl_findings = [f for f in findings if "ssl" in f.get("key", "")]
        impact += len(ssl_findings) * 5

    elif framework == "gdpr":
        impact = min(100, critical * 15 + high * 8)

    elif framework == "pci":
        # PCI DSS — payment card industry
        pci_critical_keys = {
            "ports_database_exposed", "ssl_invalid", "ssl_tls10_supported",
            "ssl_heartbleed", "public_cloud_bucket", "cors_credentials_wildcard",
        }
        pci_relevant = [f for f in findings if f.get("key") in pci_critical_keys]
        impact = min(100, len(pci_relevant) * 20 + critical * 10)

    return min(100, impact)
