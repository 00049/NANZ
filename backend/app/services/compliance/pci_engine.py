"""
PCI DSS v4.0 Engine — Payment Card Industry Data Security Standard compliance.

Maps scan findings to specific PCI DSS v4.0 requirements.
Relevant for any organization processing, storing, or transmitting cardholder data.

Key requirements mapped:
  Req 4.2.1 — Strong cryptography for data in transit
  Req 6.3.3 — All software protected from known vulnerabilities
  Req 6.4.1 — Public-facing web apps protected against attacks
  Req 7.2   — Access control systems implemented
  Req 1.3.2 — Restrict inbound/outbound traffic

Usage:
    from app.services.compliance.pci_engine import compute_pci_report
    report = compute_pci_report(classified_findings, raw_findings)
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PCIRequirementViolation:
    requirement: str           # "Req 4.2.1"
    requirement_title: str
    description: str
    trigger_findings: list[str]
    severity: str              # "CRITICAL" / "HIGH" / "MEDIUM"
    qsa_note: str              # Note for Qualified Security Assessor


@dataclass
class PCIDSSReport:
    pci_score: int
    pci_status: str            # "Compliant" / "Partial" / "Non-Compliant" / "Not Applicable"
    pci_applicable: bool       # False if no payment signals detected
    violated_requirements: list[PCIRequirementViolation]
    passing_controls: list[str]
    audit_evidence: list[dict]
    waf_detected: bool         # Req 6.4.1 requires WAF or DAST

    def to_dict(self) -> dict:
        return {
            "pci_score": self.pci_score,
            "pci_status": self.pci_status,
            "pci_applicable": self.pci_applicable,
            "violated_requirements": [_req_to_dict(r) for r in self.violated_requirements],
            "passing_controls": self.passing_controls,
            "audit_evidence": self.audit_evidence,
            "waf_detected": self.waf_detected,
        }


def _req_to_dict(v: PCIRequirementViolation) -> dict:
    return {
        "requirement": v.requirement,
        "requirement_title": v.requirement_title,
        "description": v.description,
        "trigger_findings": v.trigger_findings,
        "severity": v.severity,
        "qsa_note": v.qsa_note,
    }


# ── Requirement Trigger Mappings ──────────────────────────────────────────────

_REQ_4_2_1_TRIGGERS = {
    "ssl_invalid", "ssl_unavailable", "ssl_self_signed",
    "ssl_tls10_supported", "ssl_tls11_supported",
    "ssl_null_cipher", "ssl_rc4_cipher", "ssl_des_cipher", "ssl_export_cipher",
    "ssl_heartbleed", "ssl_robot",
    "headers_no_https_redirect",
    "mixed_content_detected",
}

_REQ_6_3_3_TRIGGERS = {
    "cms_wp_vulnerable_plugins", "cms_wp_core_vulnerable", "cms_outdated",
    "jquery_outdated", "js_library_outdated",
    "ssl_heartbleed",
    # CVE-enriched findings are handled separately
}

_REQ_6_4_1_TRIGGERS = {
    "cors_credentials_wildcard", "cors_reflected_origin", "cors_wildcard_api",
    "webapp_sql_injection", "trace_with_reflection",
    "iast_db_error", "oast_ssrf_confirmed",
    # WAF absence is checked separately
}

_REQ_7_2_TRIGGERS = {
    "cms_admin_no_auth", "api_bola", "idor_confirmed", "bola_confirmed",
    "auth_bypass_api", "auth_bypass_endpoints",
    "ports_database_exposed", "ports_redis_no_auth",
}

_REQ_1_3_2_TRIGGERS = {
    "ports_database_exposed", "dangerous_ports_exposed",
    "public_cloud_bucket", "dns_zone_transfer",
}

_REQ_2_2_7_TRIGGERS = {
    "headers_server_version_exposed", "headers_tech_stack_exposed",
    "source_map_exposed",
}

_PAYMENT_SIGNALS = {
    "stripe", "razorpay", "paypal", "braintree", "square", "payment", "checkout",
}


def _detect_payment_scope(raw_findings: dict[str, Any]) -> bool:
    """Check if site processes payments — determines PCI applicability."""
    tech = raw_findings.get("tech", {}).get("data", {}) or {}
    js = raw_findings.get("javascript", {}).get("data", {}) or {}
    crawl = raw_findings.get("crawl", {}).get("data", {}) or {}

    tech_str = " ".join(t.get("name", "").lower() for t in tech.get("technologies", []))
    js_str = str(js.get("payment_processors_detected", [])).lower()
    paths_str = " ".join(str(p) for p in crawl.get("paths_discovered", [])).lower()
    secrets_str = str(js.get("secrets_found", [])).lower()

    return any(
        sig in text
        for sig in _PAYMENT_SIGNALS
        for text in [tech_str, js_str, paths_str, secrets_str]
    )


def compute_pci_report(
    classified_findings: list[dict],
    raw_findings: dict[str, Any],
) -> PCIDSSReport:
    """Compute PCI DSS v4.0 compliance report."""
    finding_keys = {
        f.get("key", "") or f.get("check_type", "") or ""
        for f in classified_findings
    }

    pci_applicable = _detect_payment_scope(raw_findings)
    waf_data = raw_findings.get("waf", {}).get("data", {}) or {}
    waf_detected = bool(waf_data.get("waf_detected"))

    violations: list[PCIRequirementViolation] = []
    audit_evidence: list[dict] = []
    now_ts = datetime.now(timezone.utc).isoformat()

    # ── Req 4.2.1 — Strong Cryptography in Transit ────────────────────────────
    hits = finding_keys & _REQ_4_2_1_TRIGGERS
    if hits:
        violations.append(PCIRequirementViolation(
            requirement="Req 4.2.1",
            requirement_title="Strong Cryptography for Data in Transit",
            description=(
                "Cardholder data must be encrypted using strong cryptography "
                "(TLS 1.2+) during transmission. Weak ciphers, deprecated protocols, "
                "or absent HTTPS enforcement violate this requirement."
            ),
            trigger_findings=list(hits),
            severity="CRITICAL",
            qsa_note=(
                "QSA will require evidence of TLS 1.2+ enforcement across all "
                "systems in the cardholder data environment. Provide ASV scan reports."
            ),
        ))
        audit_evidence.append({"requirement": "Req 4.2.1", "violations": list(hits), "timestamp": now_ts})

    # ── Req 6.3.3 — Protect from Known Vulnerabilities ───────────────────────
    hits = finding_keys & _REQ_6_3_3_TRIGGERS
    if hits:
        violations.append(PCIRequirementViolation(
            requirement="Req 6.3.3",
            requirement_title="Protect Against Known Vulnerabilities",
            description=(
                "All system components must be protected from known vulnerabilities "
                "by installing applicable security patches/updates. Outdated CMS, "
                "plugins, or JavaScript libraries with known CVEs violate this requirement."
            ),
            trigger_findings=list(hits),
            severity="HIGH",
            qsa_note=(
                "Document your patch management process. QSA will verify patch "
                "cadence against CVE publication dates — critical patches within 30 days."
            ),
        ))
        audit_evidence.append({"requirement": "Req 6.3.3", "violations": list(hits), "timestamp": now_ts})

    # ── Req 6.4.1 — Protect Public-Facing Web Apps ────────────────────────────
    hits = finding_keys & _REQ_6_4_1_TRIGGERS
    waf_absent = not waf_detected
    if hits or waf_absent:
        all_hits = list(hits) + (["waf_not_detected"] if waf_absent else [])
        violations.append(PCIRequirementViolation(
            requirement="Req 6.4.1",
            requirement_title="Public-Facing Web Application Protection",
            description=(
                "Public-facing web applications must be protected against known attacks "
                "either by a WAF or through a rigorous annual DAST review. "
                + ("No WAF detected — automated protection is missing. " if waf_absent else "")
                + ("Known web application vulnerabilities were detected. " if hits else "")
            ),
            trigger_findings=all_hits,
            severity="HIGH",
            qsa_note=(
                "Deploy a WAF in blocking mode OR conduct an annual penetration test "
                "and DAST scan. WAF rules must be kept current. Document both options for QSA."
            ),
        ))
        audit_evidence.append({"requirement": "Req 6.4.1", "violations": all_hits, "timestamp": now_ts})

    # ── Req 7.2 — Access Control Systems ─────────────────────────────────────
    hits = finding_keys & _REQ_7_2_TRIGGERS
    if hits:
        violations.append(PCIRequirementViolation(
            requirement="Req 7.2",
            requirement_title="Access Control Systems",
            description=(
                "Access to system components and cardholder data must be restricted "
                "to only those individuals whose job requires such access. "
                "Authorization failures (IDOR/BOLA, admin without auth, exposed databases) "
                "violate this principle."
            ),
            trigger_findings=list(hits),
            severity="CRITICAL",
            qsa_note=(
                "QSA will test access controls. Provide role matrix and demonstrate "
                "least-privilege implementation. Document all admin access paths."
            ),
        ))
        audit_evidence.append({"requirement": "Req 7.2", "violations": list(hits), "timestamp": now_ts})

    # ── Req 1.3.2 — Restrict Inbound/Outbound Traffic ────────────────────────
    hits = finding_keys & _REQ_1_3_2_TRIGGERS
    if hits:
        violations.append(PCIRequirementViolation(
            requirement="Req 1.3.2",
            requirement_title="Restrict Inbound and Outbound Traffic",
            description=(
                "Network controls must restrict inbound and outbound traffic to only "
                "that which is necessary for the cardholder data environment. "
                "Exposed database ports and DNS zone transfers violate network segmentation."
            ),
            trigger_findings=list(hits),
            severity="CRITICAL",
            qsa_note=(
                "Network segmentation test required. QSA will perform scoping exercise "
                "to verify CDE isolation. Firewall rules must be documented and reviewed."
            ),
        ))
        audit_evidence.append({"requirement": "Req 1.3.2", "violations": list(hits), "timestamp": now_ts})

    # ── Req 2.2.7 — System Configuration ─────────────────────────────────────
    hits = finding_keys & _REQ_2_2_7_TRIGGERS
    if hits:
        violations.append(PCIRequirementViolation(
            requirement="Req 2.2.7",
            requirement_title="System Configuration Standards",
            description=(
                "All system components must be configured in accordance with industry-accepted "
                "hardening standards. Exposing server version banners and source maps assists "
                "attackers in identifying vulnerable configurations."
            ),
            trigger_findings=list(hits),
            severity="MEDIUM",
            qsa_note=(
                "Review hardening standards applied. Remove version banners from HTTP headers. "
                "Map to CIS Benchmarks or equivalent for QSA documentation."
            ),
        ))

    # ── Score ─────────────────────────────────────────────────────────────────
    score = 100
    for v in violations:
        deduction = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 8}.get(v.severity, 8)
        score -= deduction
    score = max(0, min(100, score))

    if not pci_applicable:
        status = "Not Applicable"
    elif score >= 80:
        status = "Compliant"
    elif score >= 50:
        status = "Partial"
    else:
        status = "Non-Compliant"

    # ── Passing Controls ──────────────────────────────────────────────────────
    passing_controls = []
    all_keys = {f.get("key", "") or f.get("check_type", "") or "" for f in classified_findings}
    if "ssl_invalid" not in all_keys and "ssl_tls10_supported" not in all_keys:
        passing_controls.append("Req 4.2.1 — TLS 1.2+ enforced, no weak protocols")
    if waf_detected:
        passing_controls.append("Req 6.4.1 — WAF detected in active mode")
    if "ports_database_exposed" not in all_keys:
        passing_controls.append("Req 1.3.2 — Database ports not exposed to internet")
    if "cms_wp_vulnerable_plugins" not in all_keys:
        passing_controls.append("Req 6.3.3 — No known vulnerable plugins detected")

    return PCIDSSReport(
        pci_score=score,
        pci_status=status,
        pci_applicable=pci_applicable,
        violated_requirements=violations,
        passing_controls=passing_controls,
        audit_evidence=audit_evidence,
        waf_detected=waf_detected,
    )
