"""
DPDP Engine — Digital Personal Data Protection Act 2023 (India).

Section-by-section legal clause mapping with:
- Specific section triggers from existing scan findings
- Data Fiduciary vs Significant Data Fiduciary classification
- Maximum penalty calculations per section violation
- Audit log entry generation

Penalty caps per section (as per the Act):
  S.4  — Rs. 50 Crore
  S.8(1) — Rs. 50 Crore
  S.8(4) — Rs. 250 Crore (MAIN security safeguards clause)
  S.8(6) — Rs. 200 Crore (breach notification)
  S.9   — Rs. 200 Crore (children's data)
  S.16  — Rs. 150 Crore (Significant Data Fiduciary obligations)

Usage:
    from app.services.compliance.dpdp_engine import compute_dpdp_report
    report = compute_dpdp_report(classified_findings, raw_findings)
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class DPDPViolation:
    """A single DPDP Act section violation."""
    section: str                    # "S.8(4)"
    section_title: str              # "Security Safeguards"
    description: str                # Plain English description
    legal_text: str                 # Direct quote/reference from Act
    max_penalty_crore: int          # Maximum fine in crores
    trigger_findings: list[str]     # Finding keys that triggered this
    display_message: str            # Full display string for UI
    severity: str = "CRITICAL"      # CRITICAL / HIGH / MEDIUM


@dataclass
class DPDPReport:
    """Full DPDP compliance report with section-level analysis."""
    dpdp_score: int                               # 0–100
    dpdp_risk_level: str                          # "Compliant" / "At Risk" / "Non-Compliant"
    fiduciary_type: str                           # "Standard" / "Significant"
    violated_sections: list[DPDPViolation]
    passing_controls: list[str]
    total_max_penalty_crore: int
    penalty_display: str                          # "Maximum DPDP Penalty Exposure: ₹X Crore"
    audit_log_entry: dict
    section_count: int = 0
    violated_count: int = 0

    def to_dict(self) -> dict:
        return {
            "dpdp_score": self.dpdp_score,
            "dpdp_risk_level": self.dpdp_risk_level,
            "fiduciary_type": self.fiduciary_type,
            "violated_sections": [_violation_to_dict(v) for v in self.violated_sections],
            "passing_controls": self.passing_controls,
            "total_max_penalty_crore": self.total_max_penalty_crore,
            "penalty_display": self.penalty_display,
            "audit_log_entry": self.audit_log_entry,
            "section_count": self.section_count,
            "violated_count": self.violated_count,
        }


def _violation_to_dict(v: DPDPViolation) -> dict:
    return {
        "section": v.section,
        "section_title": v.section_title,
        "description": v.description,
        "legal_text": v.legal_text,
        "max_penalty_crore": v.max_penalty_crore,
        "trigger_findings": v.trigger_findings,
        "display_message": v.display_message,
        "severity": v.severity,
    }


# ── Section Trigger Definitions ───────────────────────────────────────────────

# Trigger finding keys mapped to DPDP sections
_S4_TRIGGERS = {
    "missing_rate_limiting", "auth_bypass_endpoints", "auth_bypass_api",
    "api_no_auth", "cms_admin_no_auth", "bola_vulnerable_endpoints",
}

_S8_1_TRIGGERS = {
    "api_bola", "idor_confirmed", "bola_confirmed", "forced_browsing_sensitive",
}

_S8_4_TRIGGERS = {
    "ssl_invalid", "ssl_unavailable", "ssl_self_signed",
    "ssl_tls10_supported", "ssl_tls11_supported", "ssl_heartbleed",
    "headers_no_https_redirect", "headers_many_missing",
    "webapp_exposed_.env", "webapp_exposed_.git_config",
    "ports_database_exposed", "ports_redis_no_auth",
    "session_cookie_insecure", "domain_in_breach",
    "public_cloud_bucket", "aws_key_in_source", "api_key_in_source",
    "cors_credentials_wildcard", "cms_api_keys_exposed",
}

_S8_6_TRIGGERS = {
    "domain_in_breach",
}

_S9_TRIGGERS = {
    "cms_user_registration_no_age_verification",
    # Inferred from CMS with /register or /signup and no age gate
}

_S16_TRIGGERS = {
    # Triggered if S8(4) violated AND site scale is large
    "ssl_invalid", "ports_database_exposed", "public_cloud_bucket",
    "domain_in_breach", "cors_credentials_wildcard",
}


def _get_finding_keys(classified_findings: list[dict]) -> set[str]:
    """Extract all finding keys from classified findings list."""
    return {
        f.get("key", "") or f.get("check_type", "") or ""
        for f in classified_findings
    }


def _infer_significant_fiduciary(raw_findings: dict[str, Any]) -> bool:
    """
    Infer if the organization is likely a Significant Data Fiduciary
    (processing data of >500,000 users) based on site scale indicators.
    """
    tech = raw_findings.get("tech", {}).get("data", {}) or {}
    crawl = raw_findings.get("crawl", {}).get("data", {}) or {}

    # Indicators of large-scale operations
    indicators = [
        tech.get("cdn_detected"),                    # CDN = large traffic
        bool(tech.get("technologies")),              # Multiple tech layers
        crawl.get("total_paths_found", 0) > 50,     # Large site
        bool(raw_findings.get("cve", {}).get("data")),  # Has published CVEs
    ]
    # Need 2+ indicators to infer Significant status
    return sum(1 for i in indicators if i) >= 2


def compute_dpdp_report(
    classified_findings: list[dict],
    raw_findings: dict[str, Any],
) -> DPDPReport:
    """
    Compute a full DPDP Act 2023 compliance report.

    Args:
        classified_findings: List of classified finding dicts from classifier
        raw_findings: Raw per-module results dict from orchestrator

    Returns:
        DPDPReport with section-level violations, scores, and penalty exposure
    """
    finding_keys = _get_finding_keys(classified_findings)
    violations: list[DPDPViolation] = []
    triggered_s8_4 = False

    # ── Section 4 — Lawful Processing / Consent Controls ──────────────────────
    s4_hits = finding_keys & _S4_TRIGGERS
    if s4_hits:
        violations.append(DPDPViolation(
            section="S.4",
            section_title="Lawful Processing of Personal Data",
            description=(
                "Authentication endpoints lack rate limiting or access controls, "
                "indicating that consent mechanisms for data collection may be inadequately enforced."
            ),
            legal_text=(
                "Section 4(1) — A person may process the personal data of a Data Principal only in "
                "accordance with the provisions of this Act for a lawful purpose."
            ),
            max_penalty_crore=50,
            trigger_findings=list(s4_hits),
            display_message=(
                "Lack of authentication controls may indicate failure to implement lawful "
                "processing safeguards. Maximum penalty: ₹50 Crore."
            ),
            severity="HIGH",
        ))

    # ── Section 8(1) — Data Accuracy Obligation ───────────────────────────────
    s8_1_hits = finding_keys & _S8_1_TRIGGERS
    if s8_1_hits:
        violations.append(DPDPViolation(
            section="S.8(1)",
            section_title="Data Accuracy Obligation",
            description=(
                "Object-level access control failures (IDOR/BOLA) indicate that "
                "data accuracy obligations may not be enforceable — users may not "
                "be able to reliably update or correct their own data."
            ),
            legal_text=(
                "Section 8(1) — A Data Fiduciary shall make reasonable efforts to ensure "
                "the completeness, accuracy and consistency of personal data."
            ),
            max_penalty_crore=50,
            trigger_findings=list(s8_1_hits),
            display_message=(
                "Authorization failures (IDOR/BOLA) undermine data accuracy obligations. "
                "Maximum penalty: ₹50 Crore."
            ),
            severity="HIGH",
        ))

    # ── Section 8(4) — Security Safeguards (PRIMARY CLAUSE) ──────────────────
    s8_4_hits = finding_keys & _S8_4_TRIGGERS
    if s8_4_hits:
        triggered_s8_4 = True
        violations.append(DPDPViolation(
            section="S.8(4)",
            section_title="Security Safeguards",
            description=(
                "Multiple critical security failures detected: missing encryption, "
                "exposed sensitive files, insecure session management, and/or data breach history. "
                "These directly violate the requirement to implement reasonable security safeguards."
            ),
            legal_text=(
                "Section 8(4) — A Data Fiduciary shall implement appropriate technical and "
                "organisational measures to implement the provisions of this Act and protect "
                "personal data in its possession or under its control."
            ),
            max_penalty_crore=250,
            trigger_findings=list(s8_4_hits),
            display_message=(
                "Direct violation of DPDP Act Section 8(4) — Failure to implement "
                "reasonable security safeguards. Maximum penalty: ₹250 Crore per violation."
            ),
            severity="CRITICAL",
        ))

    # ── Section 8(6) — Breach Notification Obligation ────────────────────────
    s8_6_hits = finding_keys & _S8_6_TRIGGERS
    if s8_6_hits:
        violations.append(DPDPViolation(
            section="S.8(6)",
            section_title="Breach Notification Obligation",
            description=(
                "Domain has been found in known data breach databases. "
                "The organization has a legal obligation to notify the Data Protection "
                "Board of India and all affected Data Principals."
            ),
            legal_text=(
                "Section 8(6) — In the event of a personal data breach, a Data Fiduciary "
                "shall give the Board and each affected Data Principal notice of such breach "
                "in such form and manner as may be prescribed."
            ),
            max_penalty_crore=200,
            trigger_findings=list(s8_6_hits),
            display_message=(
                "You are legally required to notify the Data Protection Board of India "
                "and affected users of this breach. Failure to notify: Maximum penalty ₹200 Crore."
            ),
            severity="CRITICAL",
        ))

    # ── Section 9 — Children's Data ───────────────────────────────────────────
    # Check for user registration without age verification
    crawl_data = raw_findings.get("crawl", {}).get("data", {}) or {}
    paths = crawl_data.get("paths_discovered", [])
    has_registration = any(
        any(sig in str(p) for sig in ["/register", "/signup", "/sign-up"])
        for p in paths
    )
    # Check for parental consent indicators
    page_texts = str(crawl_data.get("page_text_samples", [])).lower()
    has_age_verification = any(
        sig in page_texts
        for sig in ["age verification", "parental consent", "18 years", "13 years", "coppa", "dpdp"]
    )

    if has_registration and not has_age_verification:
        violations.append(DPDPViolation(
            section="S.9",
            section_title="Processing of Children's Data",
            description=(
                "User registration detected without apparent age verification or "
                "parental consent mechanism. If minors can register, this violates "
                "the Act's specific protections for processing children's data."
            ),
            legal_text=(
                "Section 9 — A Data Fiduciary shall, before processing personal data of "
                "a child or a person with disability, obtain verifiable consent of the "
                "parent or lawful guardian of such child or person with disability."
            ),
            max_penalty_crore=200,
            trigger_findings=["registration_no_age_gate"],
            display_message=(
                "User registration detected without age verification — potential violation "
                "of Section 9 (Children's Data Processing). Maximum penalty: ₹200 Crore."
            ),
            severity="HIGH",
        ))

    # ── Section 16 — Significant Data Fiduciary ───────────────────────────────
    is_significant = _infer_significant_fiduciary(raw_findings)
    s16_hits = finding_keys & _S16_TRIGGERS
    if is_significant and triggered_s8_4 and s16_hits:
        violations.append(DPDPViolation(
            section="S.16",
            section_title="Significant Data Fiduciary Obligations",
            description=(
                "Based on site scale indicators (CDN, large crawl, enterprise tech stack), "
                "this organization may qualify as a Significant Data Fiduciary, triggering "
                "additional obligations including annual Data Protection Impact Assessments "
                "and mandatory Data Audits."
            ),
            legal_text=(
                "Section 16 — The Central Government may, having regard to the volume and "
                "sensitivity of personal data processed, notify certain Data Fiduciaries or "
                "class thereof as Significant Data Fiduciaries."
            ),
            max_penalty_crore=150,
            trigger_findings=list(s16_hits),
            display_message=(
                "As a potential Significant Data Fiduciary with security violations, "
                "enhanced obligations apply. Maximum penalty: ₹150 Crore."
            ),
            severity="HIGH",
        ))

    # ── Score Calculation ─────────────────────────────────────────────────────
    total_penalty_crore = sum(v.max_penalty_crore for v in violations)
    num_violations = len(violations)

    # Score: start at 100, deduct per violation severity
    score = 100
    for v in violations:
        if v.severity == "CRITICAL":
            score -= 30
        elif v.severity == "HIGH":
            score -= 15
        else:
            score -= 8
    score = max(0, min(100, score))

    if score >= 80:
        risk_level = "Compliant"
    elif score >= 50:
        risk_level = "At Risk"
    else:
        risk_level = "Non-Compliant"

    fiduciary_type = "Significant" if is_significant else "Standard"

    # ── Passing Controls ──────────────────────────────────────────────────────
    passing_controls = []
    all_keys = _get_finding_keys(classified_findings)
    if "ssl_invalid" not in all_keys and "ssl_unavailable" not in all_keys:
        passing_controls.append("Valid SSL/TLS certificate — data encrypted in transit (S.8(4))")
    if "domain_in_breach" not in all_keys:
        passing_controls.append("No known data breaches detected — breach notification (S.8(6)) not triggered")
    if "ports_database_exposed" not in all_keys:
        passing_controls.append("Database ports not publicly exposed — access controls in place (S.8(4))")
    if "headers_no_https_redirect" not in all_keys:
        passing_controls.append("HTTP forced to HTTPS — encrypted data transmission enforced (S.8(4))")

    # ── Audit Log Entry ───────────────────────────────────────────────────────
    audit_log = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "framework": "DPDP Act 2023",
        "score": score,
        "risk_level": risk_level,
        "fiduciary_type": fiduciary_type,
        "sections_assessed": ["S.4", "S.8(1)", "S.8(4)", "S.8(6)", "S.9", "S.16"],
        "violations_found": num_violations,
        "total_max_penalty_crore": total_penalty_crore,
        "trigger_evidence": {
            v.section: v.trigger_findings for v in violations
        },
    }

    return DPDPReport(
        dpdp_score=score,
        dpdp_risk_level=risk_level,
        fiduciary_type=fiduciary_type,
        violated_sections=violations,
        passing_controls=passing_controls,
        total_max_penalty_crore=total_penalty_crore,
        penalty_display=f"Maximum DPDP Penalty Exposure: ₹{total_penalty_crore} Crore",
        audit_log_entry=audit_log,
        section_count=6,
        violated_count=num_violations,
    )
