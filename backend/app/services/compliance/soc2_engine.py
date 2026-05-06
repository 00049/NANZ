"""
SOC 2 Type II Engine — Service Organization Control 2 compliance mapping.

Maps scan findings to SOC 2 Trust Service Criteria (TSC) — specifically
the Common Criteria (CC) relevant to cloud-hosted SaaS security.

Key criteria mapped:
  CC6.1 — Logical and physical access controls
  CC6.6 — Threats from external sources
  CC7.2 — System monitoring for anomalies
  CC9.2 — Risk mitigation activities

Usage:
    from app.services.compliance.soc2_engine import compute_soc2_report
    report = compute_soc2_report(classified_findings, raw_findings)
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SOC2CriteriaViolation:
    criteria_id: str               # "CC6.1"
    criteria_title: str
    description: str
    trigger_findings: list[str]
    severity: str
    auditor_note: str              # Note for Type II auditor


@dataclass
class SOC2Report:
    soc2_score: int
    soc2_status: str               # "Compliant" / "Partial" / "Non-Compliant"
    violated_criteria: list[SOC2CriteriaViolation]
    passing_controls: list[str]
    audit_evidence: list[dict]
    continuous_monitoring_gaps: list[str]

    def to_dict(self) -> dict:
        return {
            "soc2_score": self.soc2_score,
            "soc2_status": self.soc2_status,
            "violated_criteria": [_criteria_to_dict(c) for c in self.violated_criteria],
            "passing_controls": self.passing_controls,
            "audit_evidence": self.audit_evidence,
            "continuous_monitoring_gaps": self.continuous_monitoring_gaps,
        }


def _criteria_to_dict(v: SOC2CriteriaViolation) -> dict:
    return {
        "criteria_id": v.criteria_id,
        "criteria_title": v.criteria_title,
        "description": v.description,
        "trigger_findings": v.trigger_findings,
        "severity": v.severity,
        "auditor_note": v.auditor_note,
    }


# ── Criteria Trigger Mappings ─────────────────────────────────────────────────

_CC6_1_TRIGGERS = {
    "auth_bypass_api", "auth_bypass_endpoints",
    "cms_admin_no_auth", "ports_redis_no_auth",
    "ports_database_exposed",
    "jwt_no_expiry", "jwt_none_algorithm",
    "api_bola", "idor_confirmed",
    "cors_credentials_wildcard",
}

_CC6_6_TRIGGERS = {
    "dns_zone_transfer",
    "dangerous_ports_exposed",
    "public_cloud_bucket",
    "cors_reflected_origin", "cors_wildcard_api",
    "source_map_exposed",
    "webapp_exposed_.git_config", "webapp_exposed_.env",
    "ssl_heartbleed", "ssl_robot",
    "domain_in_breach",
}

_CC7_2_TRIGGERS = {
    "iast_stack_trace", "iast_db_error",
    "debug_code_in_production",
    "headers_server_version_exposed",
    # No 429 on LLM endpoints → CC7.2 monitoring gap
    "llm_no_rate_limiting",
}

_CC9_2_TRIGGERS = {
    "domain_in_breach",
    "cms_api_keys_exposed", "aws_key_in_source",
    "rep_virustotal_malicious", "rep_google_unsafe",
    "cms_wp_vulnerable_plugins",
    "llm_unauthenticated_access",
}


def compute_soc2_report(
    classified_findings: list[dict],
    raw_findings: dict[str, Any],
) -> SOC2Report:
    """Compute SOC 2 Type II compliance report."""
    finding_keys = {
        f.get("key", "") or f.get("check_type", "") or ""
        for f in classified_findings
    }

    violations: list[SOC2CriteriaViolation] = []
    audit_evidence: list[dict] = []
    monitoring_gaps: list[str] = []
    now_ts = datetime.now(timezone.utc).isoformat()

    # ── CC6.1 — Logical Access Controls ──────────────────────────────────────
    hits = finding_keys & _CC6_1_TRIGGERS
    if hits:
        violations.append(SOC2CriteriaViolation(
            criteria_id="CC6.1",
            criteria_title="Logical and Physical Access Controls",
            description=(
                "The entity implements logical access security software, infrastructure, "
                "and architectures over protected information assets. "
                "Authentication bypass, unauthorized admin access, and exposed databases "
                "indicate logical access controls are inadequate."
            ),
            trigger_findings=list(hits),
            severity="HIGH",
            auditor_note=(
                "SOC 2 auditor will test all authentication paths. Provide evidence of: "
                "MFA enforcement, least-privilege role matrix, access review logs, "
                "and privileged access management (PAM) controls."
            ),
        ))
        audit_evidence.append({
            "criteria": "CC6.1",
            "control_type": "Logical Access",
            "violations": list(hits),
            "timestamp": now_ts,
        })

    # ── CC6.6 — Threats from External Sources ─────────────────────────────────
    hits = finding_keys & _CC6_6_TRIGGERS
    if hits:
        violations.append(SOC2CriteriaViolation(
            criteria_id="CC6.6",
            criteria_title="Security Against Threats from External Sources",
            description=(
                "The entity implements controls to prevent or detect unauthorized "
                "external access. Zone transfer exposure, public buckets, exposed "
                "source code, and breach history indicate external threats are not "
                "adequately controlled."
            ),
            trigger_findings=list(hits),
            severity="HIGH",
            auditor_note=(
                "Auditor will review perimeter controls, network segmentation, "
                "and external threat monitoring. Document firewall rules, IDS/IPS "
                "configuration, and vulnerability management process."
            ),
        ))
        audit_evidence.append({
            "criteria": "CC6.6",
            "control_type": "External Threat Protection",
            "violations": list(hits),
            "timestamp": now_ts,
        })

    # ── CC7.2 — Anomaly Detection and Monitoring ───────────────────────────────
    hits = finding_keys & _CC7_2_TRIGGERS
    if hits:
        violations.append(SOC2CriteriaViolation(
            criteria_id="CC7.2",
            criteria_title="System Monitoring for Security Anomalies",
            description=(
                "The entity monitors system components for anomalies indicating "
                "malicious acts, natural disasters, or errors. "
                "Stack trace leakage, debug code in production, and verbose error "
                "responses indicate monitoring and hardening gaps."
            ),
            trigger_findings=list(hits),
            severity="MEDIUM",
            auditor_note=(
                "Provide SIEM/logging evidence. Auditor will request log samples, "
                "alert configurations, and incident response timeline from last 12 months. "
                "Error verbosity must be disabled in production."
            ),
        ))
        monitoring_gaps.append("Error verbosity in production responses — disable debug mode")
        monitoring_gaps.append("No rate limiting detected on sensitive endpoints")

    if "llm_no_rate_limiting" in finding_keys:
        monitoring_gaps.append("LLM endpoints lack rate limiting — unbounded consumption not monitored")

    # ── CC9.2 — Risk Mitigation ───────────────────────────────────────────────
    hits = finding_keys & _CC9_2_TRIGGERS
    if hits:
        violations.append(SOC2CriteriaViolation(
            criteria_id="CC9.2",
            criteria_title="Risk Mitigation Activities",
            description=(
                "The entity selects and develops risk mitigation activities for risks "
                "arising from potential business disruptions. "
                "Known data breaches, exposed secrets, and malware flags indicate "
                "risk mitigation activities are insufficient."
            ),
            trigger_findings=list(hits),
            severity="HIGH",
            auditor_note=(
                "Risk treatment plan required. Document how each identified risk has been "
                "accepted, transferred, mitigated, or avoided. Vendor risk assessments "
                "must be current. Provide evidence of annual risk assessment."
            ),
        ))
        audit_evidence.append({
            "criteria": "CC9.2",
            "control_type": "Risk Mitigation",
            "violations": list(hits),
            "timestamp": now_ts,
        })

    # ── Score ─────────────────────────────────────────────────────────────────
    score = 100
    for v in violations:
        deduction = {"HIGH": 20, "MEDIUM": 10, "LOW": 5}.get(v.severity, 8)
        score -= deduction
    score = max(0, min(100, score))

    status = "Compliant" if score >= 80 else ("Partial" if score >= 50 else "Non-Compliant")

    # ── Passing Controls ──────────────────────────────────────────────────────
    passing_controls = []
    all_keys = {f.get("key", "") or f.get("check_type", "") or "" for f in classified_findings}
    if "auth_bypass_api" not in all_keys and "cms_admin_no_auth" not in all_keys:
        passing_controls.append("CC6.1 — No authentication bypass detected")
    if "domain_in_breach" not in all_keys:
        passing_controls.append("CC9.2 — No data breach history detected")
    if "public_cloud_bucket" not in all_keys:
        passing_controls.append("CC6.6 — No publicly accessible cloud storage")
    if "iast_db_error" not in all_keys and "iast_stack_trace" not in all_keys:
        passing_controls.append("CC7.2 — No error verbosity or stack trace leakage detected")

    return SOC2Report(
        soc2_score=score,
        soc2_status=status,
        violated_criteria=violations,
        passing_controls=passing_controls,
        audit_evidence=audit_evidence,
        continuous_monitoring_gaps=monitoring_gaps,
    )
