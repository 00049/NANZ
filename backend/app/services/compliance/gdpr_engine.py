"""
GDPR Engine — EU General Data Protection Regulation compliance mapping.

Maps scan findings to specific GDPR articles with audit-grade evidence.
Focuses on Articles 25, 32, and 33 as the primary technical security articles.

Usage:
    from app.services.compliance.gdpr_engine import compute_gdpr_report
    report = compute_gdpr_report(classified_findings, raw_findings)
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class GDPRViolation:
    article: str                    # "Art. 32"
    article_title: str
    description: str
    trigger_findings: list[str]
    severity: str                   # "HIGH" / "MEDIUM" / "LOW"
    max_fine_eur: str               # "€20M or 4% global turnover"
    remediation_hint: str


@dataclass
class GDPRReport:
    gdpr_score: int
    gdpr_status: str                # "Compliant" / "Partial" / "Non-Compliant" / "Not Applicable"
    violated_articles: list[GDPRViolation]
    passing_controls: list[str]
    audit_evidence: list[dict]
    breach_notification_required: bool
    dpo_referral_recommended: bool

    def to_dict(self) -> dict:
        return {
            "gdpr_score": self.gdpr_score,
            "gdpr_status": self.gdpr_status,
            "violated_articles": [_article_to_dict(a) for a in self.violated_articles],
            "passing_controls": self.passing_controls,
            "audit_evidence": self.audit_evidence,
            "breach_notification_required": self.breach_notification_required,
            "dpo_referral_recommended": self.dpo_referral_recommended,
        }


def _article_to_dict(v: GDPRViolation) -> dict:
    return {
        "article": v.article,
        "article_title": v.article_title,
        "description": v.description,
        "trigger_findings": v.trigger_findings,
        "severity": v.severity,
        "max_fine_eur": v.max_fine_eur,
        "remediation_hint": v.remediation_hint,
    }


# ── Article Triggers ──────────────────────────────────────────────────────────

_ART25_TRIGGERS = {
    "headers_many_missing", "headers_some_missing",
    "cors_credentials_wildcard", "cors_reflected_origin", "cors_wildcard_api",
    "session_cookie_insecure", "cookie_missing_samesite",
    # Missing CSP implies no privacy by design
}

_ART32_TRIGGERS = {
    "ssl_invalid", "ssl_unavailable", "ssl_self_signed",
    "ssl_tls10_supported", "ssl_tls11_supported", "ssl_heartbleed",
    "ssl_null_cipher", "ssl_rc4_cipher",
    "headers_no_https_redirect",
    "ports_database_exposed", "ports_redis_no_auth",
    "public_cloud_bucket", "aws_key_in_source", "api_key_in_source",
    "cms_api_keys_exposed",
    "webapp_exposed_.env", "webapp_exposed_.git_config",
}

_ART33_TRIGGERS = {
    "domain_in_breach",
}

_ART5_TRIGGERS = {
    "source_map_exposed",
    "headers_server_version_exposed",
    "headers_tech_stack_exposed",
}


def compute_gdpr_report(
    classified_findings: list[dict],
    raw_findings: dict[str, Any],
) -> GDPRReport:
    """Compute GDPR compliance report from scan findings."""
    finding_keys = {
        f.get("key", "") or f.get("check_type", "") or ""
        for f in classified_findings
    }

    violations: list[GDPRViolation] = []
    audit_evidence: list[dict] = []

    # ── Article 5 — Principles of Processing ─────────────────────────────────
    a5_hits = finding_keys & _ART5_TRIGGERS
    if a5_hits:
        violations.append(GDPRViolation(
            article="Art. 5",
            article_title="Principles relating to processing of personal data",
            description=(
                "Technology stack and server version information is exposed, violating "
                "data minimisation and integrity principles — attackers can enumerate "
                "vulnerabilities from disclosed versions."
            ),
            trigger_findings=list(a5_hits),
            severity="MEDIUM",
            max_fine_eur="€10M or 2% global annual turnover",
            remediation_hint="Remove server version headers and source maps from production.",
        ))

    # ── Article 25 — Data Protection by Design and by Default ─────────────────
    a25_hits = finding_keys & _ART25_TRIGGERS
    if a25_hits:
        violations.append(GDPRViolation(
            article="Art. 25",
            article_title="Data protection by design and by default",
            description=(
                "Missing security headers (CSP, X-Frame-Options, HSTS) and insecure "
                "CORS policies indicate that data protection was not considered at the "
                "design phase of the system architecture."
            ),
            trigger_findings=list(a25_hits),
            severity="MEDIUM",
            max_fine_eur="€10M or 2% global annual turnover",
            remediation_hint=(
                "Implement Content-Security-Policy, Strict-Transport-Security, and "
                "restrict CORS to your own domains only."
            ),
        ))
        audit_evidence.append({
            "article": "Art. 25",
            "evidence_type": "missing_technical_controls",
            "findings": list(a25_hits),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    # ── Article 32 — Security of Processing ───────────────────────────────────
    a32_hits = finding_keys & _ART32_TRIGGERS
    if a32_hits:
        violations.append(GDPRViolation(
            article="Art. 32",
            article_title="Security of processing",
            description=(
                "Multiple failures in technical security measures: invalid/weak encryption, "
                "exposed credentials, publicly accessible databases, or unencrypted data "
                "transmission. These directly violate the requirement for appropriate "
                "technical measures to ensure data security."
            ),
            trigger_findings=list(a32_hits),
            severity="HIGH",
            max_fine_eur="€10M or 2% global annual turnover",
            remediation_hint=(
                "Enforce TLS 1.2+, remove exposed credentials, firewall databases, "
                "and ensure all data is encrypted in transit and at rest."
            ),
        ))
        audit_evidence.append({
            "article": "Art. 32",
            "evidence_type": "encryption_and_access_failures",
            "findings": list(a32_hits),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    # ── Article 33 — Notification of Personal Data Breach ────────────────────
    a33_hits = finding_keys & _ART33_TRIGGERS
    breach_required = bool(a33_hits)
    if a33_hits:
        violations.append(GDPRViolation(
            article="Art. 33",
            article_title="Notification of a personal data breach",
            description=(
                "Domain found in known data breach databases. GDPR requires notification "
                "to the supervisory authority within 72 hours of becoming aware of the breach, "
                "and to affected data subjects without undue delay if the breach is high-risk."
            ),
            trigger_findings=list(a33_hits),
            severity="HIGH",
            max_fine_eur="€10M or 2% global annual turnover",
            remediation_hint=(
                "Immediately notify your Data Protection Officer (DPO), assess breach scope, "
                "and file notification with supervisory authority within 72 hours."
            ),
        ))

    # ── Score Calculation ─────────────────────────────────────────────────────
    score = 100
    for v in violations:
        deduction = {"HIGH": 25, "MEDIUM": 12, "LOW": 5}.get(v.severity, 10)
        score -= deduction
    score = max(0, min(100, score))

    if score >= 80:
        status = "Compliant"
    elif score >= 50:
        status = "Partial"
    else:
        status = "Non-Compliant"

    # ── Passing Controls ──────────────────────────────────────────────────────
    passing_controls = []
    all_keys = _get_finding_keys(classified_findings)
    if "ssl_invalid" not in all_keys:
        passing_controls.append("Art. 32 — Valid SSL/TLS certificate in use")
    if "headers_no_https_redirect" not in all_keys:
        passing_controls.append("Art. 32 — HTTP forced to HTTPS")
    if "domain_in_breach" not in all_keys:
        passing_controls.append("Art. 33 — No known data breaches detected")
    if "public_cloud_bucket" not in all_keys:
        passing_controls.append("Art. 32 — No publicly accessible cloud storage")

    dpo_needed = score < 60 or breach_required

    return GDPRReport(
        gdpr_score=score,
        gdpr_status=status,
        violated_articles=violations,
        passing_controls=passing_controls,
        audit_evidence=audit_evidence,
        breach_notification_required=breach_required,
        dpo_referral_recommended=dpo_needed,
    )


def _get_finding_keys(classified_findings: list[dict]) -> set[str]:
    return {
        f.get("key", "") or f.get("check_type", "") or ""
        for f in classified_findings
    }
