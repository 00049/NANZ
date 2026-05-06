"""
Risk Quantification Engine — Enterprise Financial Risk Metrics.

Replaces the abstract "ROI Score: 11.25" with board-presentable financial
risk metrics that CISOs actually use:

  1. Risk Reduction Factor (RRF)
     Quantifies how much exploit probability drops after fixing a finding.
     Formula: RRF = (exploit_prob_before - 0.02) × asset_criticality_weight
     Display: "Risk Reduction: 2.14 (High)"

  2. Annual Loss Expectancy (ALE) Reduction
     How much annual financial loss is avoided by fixing the issue.
     Formula: ALE_reduction = SLE × (ARO - 0.02)
     Display: "Fixing this could prevent Rs. 38,25,000 in annual losses"

  3. Contextual Severity (EPSS-enriched)
     Overrides flat RED/AMBER labels for CVE findings based on real-world
     exploit probability from the EPSS database and CISA KEV membership.

  4. SLA Tiers (Time to Remediate)
     Maps severity to enforceable SLA deadlines used by security operations.
     P0 = 24h (CRITICAL), P1 = 7d (RED), P2 = 30d (AMBER), P3 = 90d (GREEN)

Usage:
    from app.services.risk_quantification import (
        compute_rrf, compute_ale_reduction, compute_sla,
        enrich_finding_with_risk_metrics, detect_data_context
    )
"""

import logging
from dataclasses import dataclass, field
from typing import Optional, Any

logger = logging.getLogger(__name__)

# ── Exploit Probability Heuristics (no CVE) ───────────────────────────────────

HEURISTIC_EXPLOIT_PROBABILITY: dict[str, float] = {
    "CRITICAL": 0.75,
    "RED":      0.45,
    "AMBER":    0.20,
    "GREEN":    0.05,
    "INFO":     0.01,
}

RESIDUAL_RISK_AFTER_FIX = 0.02  # 2% residual risk assumed after remediation

# ── Asset Criticality Weights ─────────────────────────────────────────────────

# Determined by URL patterns, endpoint types, and detected technologies
ASSET_CRITICALITY: dict[str, float] = {
    "payment_page":         3.0,
    "login_auth_endpoint":  2.5,
    "admin_panel":          2.5,
    "api_pii_endpoint":     2.0,
    "public_web_page":      1.5,
    "static_assets":        0.5,
    "unknown":              1.0,
}

# ── Single Loss Expectancy (SLE) by Data Type Detected — in INR ───────────────

SLE_BY_DATA_TYPE: dict[str, int] = {
    "pii":           4_500_000,   # Rs. 45,00,000 — DPDP max fine scaled
    "payment_pci":   8_500_000,   # Rs. 85,00,000 — PCI scope breach
    "healthcare":    3_500_000,   # Rs. 35,00,000 — health data
    "auth_creds":    2_500_000,   # Rs. 25,00,000 — credential exposure
    "business_data": 1_200_000,   # Rs. 12,00,000 — general business
    "no_sensitive":    300_000,   # Rs.  3,00,000 — minimal exposure
}

# ── Annual Rate of Occurrence (ARO) by Severity ───────────────────────────────

ARO_BY_SEVERITY: dict[str, float] = {
    "CRITICAL": 0.85,
    "RED":      0.45,
    "AMBER":    0.15,
    "GREEN":    0.03,
    "INFO":     0.01,
}

# ── SLA Tiers ────────────────────────────────────────────────────────────────

SLA_BY_SEVERITY: dict[str, tuple[str, str]] = {
    "CRITICAL": ("24 hours",  "P0"),
    "RED":      ("7 days",    "P1"),
    "AMBER":    ("30 days",   "P2"),
    "GREEN":    ("90 days",   "P3"),
    "INFO":     ("Best effort", "P4"),
}


# ── Data Context Detector ─────────────────────────────────────────────────────

def detect_data_context(scan_data: dict[str, Any]) -> str:
    """
    Infer the type of sensitive data present from existing scan results.

    Priority order: payment_pci > pii > auth_creds > healthcare > business_data > no_sensitive
    """
    # PCI / Payment indicators
    tech = scan_data.get("tech", {}).get("data", {}) or {}
    js = scan_data.get("javascript", {}).get("data", {}) or {}
    crawl = scan_data.get("crawl", {}).get("data", {}) or {}

    technologies = tech.get("technologies", [])
    tech_names = " ".join(t.get("name", "").lower() for t in technologies)
    js_libs = " ".join(str(js.get("payment_processors_detected", [])))
    crawled_paths = " ".join(str(crawl.get("paths_discovered", [])))
    js_secrets = str(js.get("secrets_found", []))

    pci_signals = ["stripe", "razorpay", "paypal", "braintree", "checkout", "payment"]
    if (
        any(sig in tech_names for sig in pci_signals)
        or any(sig in js_libs for sig in pci_signals)
        or any(sig in crawled_paths for sig in ["/checkout", "/payment", "/pay", "/cart"])
        or any(sig in js_secrets.lower() for sig in ["stripe", "razorpay", "square"])
    ):
        return "payment_pci"

    # PII indicators
    breach = scan_data.get("breach", {}).get("data", {}) or {}
    api = scan_data.get("api_security", {}) or {}
    cookies = scan_data.get("cookies", {}).get("data", {}) or {}

    pii_signals = [
        breach.get("breached"),
        "/api/users" in crawled_paths,
        "/api/customers" in crawled_paths,
        "/api/profile" in crawled_paths,
        cookies.get("session_cookies_insecure"),
        api.get("pii_endpoint_detected"),
    ]
    if any(pii_signals):
        return "pii"

    # Auth credentials
    auth_signals = [
        "/login" in crawled_paths,
        "/auth" in crawled_paths,
        "/api/auth" in crawled_paths,
        bool(cookies.get("session_cookies_count")),
    ]
    if any(auth_signals):
        return "auth_creds"

    # Healthcare
    healthcare_signals = ["health", "medical", "clinic", "patient", "hipaa"]
    if any(sig in tech_names for sig in healthcare_signals):
        return "healthcare"

    # Has some business data
    if crawled_paths:
        return "business_data"

    return "no_sensitive"


def detect_asset_criticality(
    finding: dict[str, Any],
    scan_data: dict[str, Any],
) -> str:
    """
    Determine the asset criticality type for a specific finding.

    Returns one of the keys in ASSET_CRITICALITY dict.
    """
    key = finding.get("key", "")
    check = finding.get("check", "")
    detail = str(finding.get("detail", "")).lower()
    crawl = scan_data.get("crawl", {}).get("data", {}) or {}
    paths = " ".join(str(crawl.get("paths_discovered", [])))

    # Payment / checkout pages
    if any(sig in detail for sig in ["payment", "checkout", "stripe", "razorpay"]):
        return "payment_page"
    if any(sig in paths for sig in ["/checkout", "/payment", "/pay"]):
        if check in ("api_security", "webapp", "cors"):
            return "payment_page"

    # Admin panels
    if any(sig in key for sig in ["admin", "cms_admin"]) or "/admin" in detail:
        return "admin_panel"

    # Auth/login endpoints
    if any(sig in key for sig in ["auth", "login", "session", "jwt", "oauth"]):
        return "login_auth_endpoint"
    if any(sig in detail for sig in ["/login", "/auth", "/api/auth", "/oauth"]):
        return "login_auth_endpoint"

    # API with PII
    if check == "api_security" and any(
        sig in detail for sig in ["user", "customer", "profile", "pii"]
    ):
        return "api_pii_endpoint"

    # Static assets
    if check in ("javascript", "waf", "cdn") or any(
        ext in detail for ext in [".js", ".css", ".png", ".jpg", ".map"]
    ):
        return "static_assets"

    # Public-facing web content
    if check in ("headers", "ssl", "webapp", "cors", "http_methods"):
        return "public_web_page"

    return "unknown"


# ── Core Metric Calculators ───────────────────────────────────────────────────

def compute_rrf(
    severity: str,
    epss_score: Optional[float],
    asset_criticality_key: str,
) -> dict:
    """
    Compute Risk Reduction Factor (RRF).

    RRF = (exploit_probability_before - 0.02) × asset_criticality_weight

    Returns:
        {
            "rrf_score": float,       # 0.00–3.00
            "rrf_label": str,         # "High" | "Medium" | "Low"
            "rrf_display": str,       # "Risk Reduction: 2.14 (High)"
            "exploit_prob_before": float,
            "asset_weight": float,
        }
    """
    # Use EPSS score if available (more accurate for CVE findings)
    if epss_score is not None:
        exploit_prob_before = min(float(epss_score), 1.0)
    else:
        exploit_prob_before = HEURISTIC_EXPLOIT_PROBABILITY.get(severity, 0.20)

    asset_weight = ASSET_CRITICALITY.get(asset_criticality_key, 1.0)
    rrf = (exploit_prob_before - RESIDUAL_RISK_AFTER_FIX) * asset_weight
    rrf = max(0.0, round(rrf, 2))

    if rrf >= 2.0:
        label = "High"
    elif rrf >= 1.0:
        label = "Medium"
    else:
        label = "Low"

    return {
        "rrf_score": rrf,
        "rrf_label": label,
        "rrf_display": f"Risk Reduction: {rrf:.2f} ({label})",
        "exploit_prob_before": round(exploit_prob_before, 4),
        "asset_weight": asset_weight,
    }


def compute_ale_reduction(
    severity: str,
    data_context: str,
    epss_score: Optional[float] = None,
) -> dict:
    """
    Compute Annual Loss Expectancy (ALE) reduction in INR.

    ALE_before = SLE × ARO
    ALE_after  = SLE × 0.02
    ALE_reduction = ALE_before - ALE_after

    Returns:
        {
            "sle_inr": int,
            "aro": float,
            "ale_before_inr": int,
            "ale_after_inr": int,
            "ale_reduction_inr": int,
            "ale_display": str,     # "Fixing this could prevent Rs. 38,25,000 in annual losses"
            "data_context": str,
        }
    """
    sle = SLE_BY_DATA_TYPE.get(data_context, SLE_BY_DATA_TYPE["business_data"])

    # If EPSS available, scale ARO by EPSS (more accurate)
    if epss_score is not None:
        # Use EPSS directly as ARO (it's already a probability 0-1)
        aro = round(min(float(epss_score), 0.99), 4)
    else:
        aro = ARO_BY_SEVERITY.get(severity, 0.15)

    ale_before = int(sle * aro)
    ale_after = int(sle * RESIDUAL_RISK_AFTER_FIX)
    ale_reduction = max(0, ale_before - ale_after)

    # Format in Indian numbering (lakhs/crores)
    ale_display = _format_inr(ale_reduction)

    return {
        "sle_inr": sle,
        "aro": aro,
        "ale_before_inr": ale_before,
        "ale_after_inr": ale_after,
        "ale_reduction_inr": ale_reduction,
        "ale_display": f"Fixing this could prevent {ale_display} in annual losses",
        "data_context": data_context,
    }


def compute_sla(severity: str) -> dict:
    """
    Return SLA deadline and tier for a finding severity.

    Returns:
        {"sla_deadline": "24 hours", "sla_tier": "P0"}
    """
    sla_deadline, sla_tier = SLA_BY_SEVERITY.get(
        severity, SLA_BY_SEVERITY["INFO"]
    )
    return {"sla_deadline": sla_deadline, "sla_tier": sla_tier}


def compute_contextual_severity(
    original_severity: str,
    epss_score: Optional[float],
    in_kev: bool,
    cve_id: Optional[str] = None,
) -> dict:
    """
    Apply EPSS + KEV-based severity override rules.

    Rules (applied in order):
      1. If in CISA KEV → CRITICAL + badge "🚨 CISA KEV"
      2. If EPSS > 0.5 AND not CRITICAL → upgrade to CRITICAL + "⚡ Actively Exploited"
      3. If EPSS > 0.3 AND AMBER → upgrade to RED + "⚠️ High Exploit Probability"
      4. If EPSS < 0.01 AND RED → downgrade to AMBER + "📊 Low Real-World Exploit Rate"

    Returns:
        {
            "contextual_severity": str,
            "severity_adjusted": bool,
            "severity_reason": str | None,
            "epss_badge": str | None,
        }
    """
    # Only apply contextual severity if we have CVE data
    if not cve_id:
        return {
            "contextual_severity": original_severity,
            "severity_adjusted": False,
            "severity_reason": None,
            "epss_badge": None,
        }

    # Rule 1: CISA KEV — always CRITICAL regardless of CVSS
    if in_kev:
        adjusted = "CRITICAL"
        reason = f"Upgraded: CISA KEV — actively exploited in the wild"
        badge = "🚨 CISA KEV"
        return {
            "contextual_severity": adjusted,
            "severity_adjusted": adjusted != original_severity,
            "severity_reason": reason,
            "epss_badge": badge,
        }

    if epss_score is None:
        return {
            "contextual_severity": original_severity,
            "severity_adjusted": False,
            "severity_reason": None,
            "epss_badge": None,
        }

    adjusted = original_severity
    reason = None
    badge = None

    # Rule 2: EPSS > 0.5 → CRITICAL
    if epss_score > 0.5 and original_severity not in ("CRITICAL",):
        adjusted = "CRITICAL"
        reason = f"Upgraded: EPSS {epss_score:.3f} — actively exploited"
        badge = "⚡ Actively Exploited"

    # Rule 3: EPSS > 0.3 AND AMBER → RED
    elif epss_score > 0.3 and original_severity == "AMBER":
        adjusted = "RED"
        reason = f"Upgraded: EPSS {epss_score:.3f} — high exploit probability"
        badge = "⚠️ High Exploit Probability"

    # Rule 4: EPSS < 0.01 AND RED → AMBER (downgrade)
    elif epss_score < 0.01 and original_severity == "RED":
        adjusted = "AMBER"
        reason = f"Downgraded: EPSS {epss_score:.4f} — low real-world exploit rate"
        badge = "📊 Low Real-World Exploit Rate"

    return {
        "contextual_severity": adjusted,
        "severity_adjusted": adjusted != original_severity,
        "severity_reason": reason,
        "epss_badge": badge,
    }


def enrich_finding_with_risk_metrics(
    finding: dict[str, Any],
    scan_data: dict[str, Any],
    epss_score: Optional[float] = None,
    epss_percentile: Optional[int] = None,
    in_kev: bool = False,
) -> dict[str, Any]:
    """
    Add all enterprise risk metrics to a classified finding in-place.

    Attaches:
        rrf_score, rrf_label, rrf_display
        ale_reduction_inr, ale_display, ale_data
        sla_deadline, sla_tier
        contextual_severity, severity_adjusted, severity_reason, epss_badge
        epss_score, epss_percentile, cisa_kev

    Args:
        finding: classified finding dict (modified in-place, also returned)
        scan_data: full raw_findings dict from orchestrator
        epss_score: EPSS probability (0.0–1.0) if CVE-based finding
        epss_percentile: EPSS percentile (0–100) if available
        in_kev: whether this CVE is in CISA KEV catalog

    Returns:
        enriched finding dict
    """
    severity = finding.get("severity", "AMBER")
    cve_id = finding.get("cve_id") or finding.get("data", {}).get("cve_id") if isinstance(finding.get("data"), dict) else None

    # Detect context
    asset_criticality_key = detect_asset_criticality(finding, scan_data)
    data_context = detect_data_context(scan_data)

    # Compute metrics
    rrf_data = compute_rrf(severity, epss_score, asset_criticality_key)
    ale_data = compute_ale_reduction(severity, data_context, epss_score)
    sla_data = compute_sla(severity)
    ctx_data = compute_contextual_severity(severity, epss_score, in_kev, cve_id)

    # Attach to finding
    finding.update({
        # RRF
        "rrf_score": rrf_data["rrf_score"],
        "rrf_label": rrf_data["rrf_label"],
        "rrf_display": rrf_data["rrf_display"],

        # ALE
        "ale_reduction_inr": ale_data["ale_reduction_inr"],
        "ale_display": ale_data["ale_display"],
        "ale_data": ale_data,

        # SLA
        "sla_deadline": sla_data["sla_deadline"],
        "sla_tier": sla_data["sla_tier"],

        # EPSS + KEV
        "epss_score": epss_score,
        "epss_percentile": epss_percentile,
        "cisa_kev": in_kev,

        # Contextual severity
        "contextual_severity": ctx_data["contextual_severity"],
        "severity_adjusted": ctx_data["severity_adjusted"],
        "severity_reason": ctx_data["severity_reason"],
        "epss_badge": ctx_data["epss_badge"],
    })

    # If severity was adjusted, propagate the new severity
    if ctx_data["severity_adjusted"]:
        finding["original_severity"] = severity
        finding["severity"] = ctx_data["contextual_severity"]

    return finding


def compute_portfolio_risk_summary(findings: list[dict]) -> dict:
    """
    Compute a portfolio-level risk summary from enriched findings.

    Returns:
        {
            "total_ale_reduction_inr": int,
            "total_ale_display": str,
            "avg_rrf_score": float,
            "highest_rrf": float,
            "kev_findings_count": int,
            "epss_enriched_count": int,
            "severity_adjusted_count": int,
            "p0_count": int, "p1_count": int, "p2_count": int, "p3_count": int,
        }
    """
    total_ale = sum(f.get("ale_reduction_inr", 0) for f in findings)
    rrf_scores = [f["rrf_score"] for f in findings if f.get("rrf_score") is not None]
    avg_rrf = round(sum(rrf_scores) / len(rrf_scores), 2) if rrf_scores else 0.0

    return {
        "total_ale_reduction_inr": total_ale,
        "total_ale_display": f"Total preventable loss: {_format_inr(total_ale)}",
        "avg_rrf_score": avg_rrf,
        "highest_rrf": max(rrf_scores, default=0.0),
        "kev_findings_count": sum(1 for f in findings if f.get("cisa_kev")),
        "epss_enriched_count": sum(1 for f in findings if f.get("epss_score") is not None),
        "severity_adjusted_count": sum(1 for f in findings if f.get("severity_adjusted")),
        "p0_count": sum(1 for f in findings if f.get("sla_tier") == "P0"),
        "p1_count": sum(1 for f in findings if f.get("sla_tier") == "P1"),
        "p2_count": sum(1 for f in findings if f.get("sla_tier") == "P2"),
        "p3_count": sum(1 for f in findings if f.get("sla_tier") == "P3"),
    }


# ── INR Formatting ────────────────────────────────────────────────────────────

def _format_inr(amount: int) -> str:
    """Format an integer amount in Indian Rupees notation (Rs. X,XX,XXX)."""
    if amount == 0:
        return "Rs. 0"

    # Indian numbering: last 3 digits, then groups of 2
    s = str(amount)
    if len(s) <= 3:
        return f"Rs. {s}"

    last3 = s[-3:]
    rest = s[:-3]

    # Split rest into groups of 2 from the right
    groups = []
    while len(rest) > 2:
        groups.append(rest[-2:])
        rest = rest[:-2]
    if rest:
        groups.append(rest)

    groups.reverse()
    formatted = ",".join(groups) + "," + last3
    return f"Rs. {formatted}"
