"""
Compliance Mapper — NANZ v2.0

Maps every security finding to specific violated clauses across 5 regulatory frameworks:
  - DPDP Act (India) — Digital Personal Data Protection Act 2023
  - GDPR (EU) — General Data Protection Regulation
  - PCI DSS v4.0 — Payment Card Industry Data Security Standard
  - SOC 2 Type II — Service Organization Control 2
  - DORA (EU) — Digital Operational Resilience Act

Usage:
    from app.services.compliance_mapper import map_to_frameworks
    result = map_to_frameworks(risk_items)
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ComplianceClause:
    framework: str
    clause_id: str
    clause_title: str
    description: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW


@dataclass
class FrameworkReport:
    framework: str
    full_name: str
    readiness_score: int          # 0–100
    violated_clauses: list[ComplianceClause] = field(default_factory=list)
    compliant_controls: list[str] = field(default_factory=list)
    summary: str = ""


@dataclass
class ComplianceReport:
    dpdp: FrameworkReport
    gdpr: FrameworkReport
    pci_dss: FrameworkReport
    soc2: FrameworkReport
    dora: FrameworkReport

    def to_dict(self) -> dict:
        return {
            "dpdp":    asdict(self.dpdp),
            "gdpr":    asdict(self.gdpr),
            "pci_dss": asdict(self.pci_dss),
            "soc2":    asdict(self.soc2),
            "dora":    asdict(self.dora),
        }


# ---------------------------------------------------------------------------
# Clause definitions — keyed by (check_type / finding key)
# ---------------------------------------------------------------------------

# Each entry: finding_key -> list of (framework, clause_id, clause_title, description, severity)
FINDING_TO_CLAUSES: dict[str, list[tuple]] = {

    # ── SSL / TLS ──────────────────────────────────────────────────────────
    "ssl_invalid": [
        ("dpdp",    "S.8(4)",     "Data Fiduciary Security Obligations",       "Failure to maintain valid encryption violates the requirement to implement appropriate security safeguards for personal data.", "CRITICAL"),
        ("gdpr",    "Art.32",     "Security of Processing",                    "Invalid SSL means personal data may be transmitted without adequate technical measures.", "CRITICAL"),
        ("pci_dss", "Req.4.2.1", "Strong Cryptography in Transit",             "Cardholder data must be encrypted using strong cryptography during transmission over open/public networks.", "CRITICAL"),
        ("soc2",    "CC6.7",      "Transmission Security",                     "System data must be protected during transmission with appropriate security controls.", "CRITICAL"),
        ("dora",    "Art.9(2)",   "ICT Security — Protection of Information", "ICT systems must ensure confidentiality of data in transit using current encryption standards.", "CRITICAL"),
    ],
    "ssl_self_signed": [
        ("gdpr",    "Art.32",     "Security of Processing",                    "Self-signed certificates do not provide verifiable identity assurance, undermining data security.", "HIGH"),
        ("pci_dss", "Req.4.2.1", "Strong Cryptography in Transit",             "Self-signed certificates are not acceptable for protecting cardholder data in transit.", "HIGH"),
        ("soc2",    "CC6.7",      "Transmission Security",                     "Self-signed certificates indicate inadequate transmission security controls.", "HIGH"),
    ],
    "ssl_tls10_supported": [
        ("gdpr",    "Art.32",     "Security of Processing",                    "TLS 1.0 is a deprecated protocol with known vulnerabilities (BEAST, POODLE). Its use is not considered adequate security.", "HIGH"),
        ("pci_dss", "Req.4.2.1", "Strong Cryptography in Transit",             "PCI DSS explicitly prohibits TLS 1.0. All payment data transmissions must use TLS 1.2 or higher.", "CRITICAL"),
        ("dora",    "Art.9(2)",   "ICT Security — Protection",                "Use of deprecated cryptographic protocols violates ICT security protection requirements.", "HIGH"),
    ],
    "ssl_tls11_supported": [
        ("gdpr",    "Art.32",     "Security of Processing",                    "TLS 1.1 is deprecated and should be disabled to maintain adequate security standards.", "MEDIUM"),
        ("pci_dss", "Req.4.2.1", "Strong Cryptography in Transit",             "TLS 1.1 is prohibited by PCI DSS. Organizations must migrate to TLS 1.2+.", "HIGH"),
    ],
    "ssl_heartbleed": [
        ("gdpr",    "Art.32",     "Security of Processing",                    "Heartbleed vulnerability exposes private keys and user session data — a critical breach of data security obligations.", "CRITICAL"),
        ("pci_dss", "Req.6.3.3", "Security Patches Applied",                  "Known critical vulnerability not patched — violates requirement to protect system components from vulnerabilities.", "CRITICAL"),
        ("dora",    "Art.10",     "Detection of ICT-Related Incidents",        "A known critical vulnerability that is unpatched represents a failure in ICT risk detection and management.", "CRITICAL"),
    ],
    "ssl_wildcard_cert": [
        ("pci_dss", "Req.4.2.1", "Strong Cryptography",                       "Wildcard certificates increase blast radius if private key is compromised — review against PCI DSS scoping requirements.", "MEDIUM"),
        ("soc2",    "CC6.1",      "Logical Access Controls",                   "Wildcard certificates may grant unintended access across subdomains, weakening logical access boundary controls.", "LOW"),
    ],

    # ── HTTP Headers ───────────────────────────────────────────────────────
    "headers_many_missing": [
        ("gdpr",    "Art.25",     "Data Protection by Design and by Default",  "Missing security headers (CSP, HSTS, X-Frame-Options) indicate failure to implement data protection by design.", "MEDIUM"),
        ("pci_dss", "Req.6.4.1", "Web-Facing Application Protection",         "Web-facing applications must be protected against known attacks. Missing headers enable XSS, clickjacking, and MIME sniffing attacks.", "HIGH"),
        ("soc2",    "CC6.6",      "Threats from External Sources",             "Absence of protective HTTP headers leaves the system vulnerable to a broad class of web-based attacks.", "MEDIUM"),
    ],
    "headers_no_https_redirect": [
        ("gdpr",    "Art.32",     "Security of Processing",                    "Failure to redirect HTTP to HTTPS means personal data can be transmitted in cleartext.", "HIGH"),
        ("dpdp",    "S.8(4)",     "Data Fiduciary Security Obligations",       "Unencrypted HTTP access allows interception of personal data — a direct violation of data security obligations.", "HIGH"),
        ("pci_dss", "Req.4.2.1", "Strong Cryptography in Transit",             "All web traffic carrying cardholder data must be forced to HTTPS.", "HIGH"),
    ],
    "headers_server_version_exposed": [
        ("pci_dss", "Req.2.2.7", "System Configuration",                      "Exposing server version information assists attackers in identifying known vulnerabilities — violates secure configuration requirements.", "MEDIUM"),
        ("soc2",    "CC7.1",      "Vulnerability Detection",                   "Server version disclosure provides information that can be leveraged to identify unpatched vulnerabilities.", "LOW"),
    ],

    # ── DNS & Email Security ────────────────────────────────────────────────
    "dns_no_email_protection": [
        ("gdpr",    "Art.32",     "Security of Processing",                    "Without SPF/DMARC/DKIM, your domain can be used to send phishing emails impersonating your organization, creating a data breach risk.", "HIGH"),
        ("dpdp",    "S.8(4)",     "Data Fiduciary Security Obligations",       "Domain spoofing enabled by missing email security records can be used to steal personal data via phishing.", "HIGH"),
        ("pci_dss", "Req.5.4.1", "Anti-Phishing Mechanisms",                  "PCI DSS requires controls to detect and protect against phishing attacks, including email authentication records.", "HIGH"),
    ],
    "dns_no_spf": [
        ("gdpr",    "Art.32",     "Security of Processing",                    "Missing SPF record allows any server to send emails as your domain.", "MEDIUM"),
        ("pci_dss", "Req.5.4.1", "Anti-Phishing Mechanisms",                  "SPF record is a baseline anti-phishing control required for protecting cardholder communications.", "MEDIUM"),
    ],
    "dns_no_dmarc": [
        ("gdpr",    "Art.32",     "Security of Processing",                    "Without DMARC, unauthenticated emails can reach recipients even if SPF/DKIM fail.", "MEDIUM"),
        ("pci_dss", "Req.5.4.1", "Anti-Phishing Mechanisms",                  "DMARC is required as a control to enforce email authentication policies.", "MEDIUM"),
    ],
    "dns_dmarc_not_enforced": [
        ("gdpr",    "Art.32",     "Security of Processing",                    "A DMARC policy of 'none' provides monitoring only and does not prevent spoofed emails from reaching inboxes.", "MEDIUM"),
    ],
    "dns_no_dnssec": [
        ("dora",    "Art.9(2)",   "ICT Security — Protection",                "DNSSEC protects DNS resolution integrity. Its absence allows DNS poisoning attacks that can redirect users to malicious infrastructure.", "MEDIUM"),
        ("soc2",    "CC6.6",      "Threats from External Sources",             "Absence of DNSSEC leaves the organization vulnerable to DNS cache poisoning and man-in-the-middle attacks.", "MEDIUM"),
    ],
    "dns_no_caa": [
        ("pci_dss", "Req.4.2.1", "Strong Cryptography",                       "Without CAA records, any Certificate Authority can issue SSL certificates for your domain, enabling impersonation attacks.", "LOW"),
    ],
    "dns_zone_transfer": [
        ("pci_dss", "Req.1.3.2", "Network Security Controls",                 "Zone transfer exposes the full internal network map — a direct violation of network security requirements.", "CRITICAL"),
        ("dora",    "Art.9(2)",   "ICT Security — Protection",                "Zone transfer exposure reveals internal ICT infrastructure details to unauthorized parties.", "CRITICAL"),
        ("soc2",    "CC6.6",      "Threats from External Sources",             "DNS zone transfer allows an attacker to enumerate all internal hosts and services.", "CRITICAL"),
    ],

    # ── Ports & Services ───────────────────────────────────────────────────
    "ports_database_exposed": [
        ("dpdp",    "S.8(4)",     "Data Fiduciary Security Obligations",       "A publicly accessible database port means personal data is at immediate risk of unauthorized access.", "CRITICAL"),
        ("gdpr",    "Art.32",     "Security of Processing",                    "Direct internet access to database servers constitutes a failure to implement appropriate technical security measures.", "CRITICAL"),
        ("pci_dss", "Req.1.3.2", "Restrict Inbound and Outbound Traffic",     "Database servers must not be accessible from untrusted networks. Public database ports violate network segmentation requirements.", "CRITICAL"),
        ("soc2",    "CC6.1",      "Logical Access Controls",                   "Publicly exposed database ports allow unauthorized access to confidential data.", "CRITICAL"),
        ("dora",    "Art.9(2)",   "ICT Security — Protection",                "Exposed database services represent a critical ICT infrastructure security failure.", "CRITICAL"),
    ],
    "dangerous_ports_exposed": [
        ("pci_dss", "Req.1.3.2", "Restrict Inbound and Outbound Traffic",     "Services on dangerous ports (Telnet, RDP, SMB) must not be accessible from the internet.", "HIGH"),
        ("soc2",    "CC6.6",      "Threats from External Sources",             "Dangerous ports exposed to the internet significantly increase the attack surface from external threats.", "HIGH"),
        ("dora",    "Art.9(2)",   "ICT Security — Protection",                "Uncontrolled access to management interfaces violates ICT security protection requirements.", "HIGH"),
    ],

    # ── Web Application ────────────────────────────────────────────────────
    "webapp_exposed_.env": [
        ("dpdp",    "S.8(4)",     "Data Fiduciary Security Obligations",       "A publicly accessible .env file likely contains database credentials and API keys — constitutes a critical personal data breach risk.", "CRITICAL"),
        ("gdpr",    "Art.32",     "Security of Processing",                    "Exposed credentials constitute a failure of technical security measures and likely trigger a data breach notification obligation under Art.33.", "CRITICAL"),
        ("gdpr",    "Art.33",     "Notification of a Personal Data Breach",    "Exposure of credentials in .env file may constitute a personal data breach requiring 72-hour notification to supervisory authority.", "CRITICAL"),
        ("pci_dss", "Req.3.4.1", "Primary Account Number Protection",         "Exposed configuration files may reveal access credentials to cardholder data environments.", "CRITICAL"),
        ("soc2",    "CC6.1",      "Logical Access Controls",                   "Exposed .env file undermines all logical access controls by revealing authentication credentials.", "CRITICAL"),
    ],
    "webapp_exposed_.git_config": [
        ("pci_dss", "Req.6.3.1", "Inventory of Bespoke Software",             "Exposed .git directory reveals source code and historical credentials, violating secure software development requirements.", "CRITICAL"),
        ("soc2",    "CC6.6",      "Threats from External Sources",             "Exposed source code repository provides attackers with detailed knowledge of application logic and hardcoded credentials.", "CRITICAL"),
    ],
    "webapp_sql_injection": [
        ("dpdp",    "S.8(4)",     "Data Fiduciary Security Obligations",       "SQL injection allows unauthorized extraction of all personal data stored in the database.", "CRITICAL"),
        ("gdpr",    "Art.32",     "Security of Processing",                    "Failure to prevent SQL injection represents a severe inadequacy of technical security measures.", "CRITICAL"),
        ("pci_dss", "Req.6.4.1", "Web Application Vulnerability Protection",  "SQL injection is listed as a specific threat that web-facing applications must be protected against.", "CRITICAL"),
    ],

    # ── CORS ───────────────────────────────────────────────────────────────
    "cors_wildcard_api": [
        ("gdpr",    "Art.25",     "Data Protection by Design and by Default",  "Wildcard CORS on API endpoints allows any website to read sensitive user data — a failure of privacy by design.", "HIGH"),
        ("pci_dss", "Req.6.4.1", "Web Application Vulnerability Protection",  "Wildcard CORS enables cross-origin attacks that can expose cardholder data.", "HIGH"),
    ],
    "cors_credentials_wildcard": [
        ("gdpr",    "Art.32",     "Security of Processing",                    "CORS with credentials and wildcard origin allows any website to make authenticated API calls as the victim user.", "CRITICAL"),
        ("pci_dss", "Req.6.4.1", "Web Application Vulnerability Protection",  "Credential-bearing wildcard CORS is a critical misconfiguration enabling cross-origin attacks on authenticated sessions.", "CRITICAL"),
    ],

    # ── Cloud & Infrastructure ─────────────────────────────────────────────
    "public_cloud_bucket": [
        ("dpdp",    "S.8(4)",     "Data Fiduciary Security Obligations",       "A publicly accessible cloud storage bucket may expose personal data to the entire internet.", "CRITICAL"),
        ("gdpr",    "Art.32",     "Security of Processing",                    "Public cloud storage containing personal data constitutes a failure to implement access control — likely triggering breach notification.", "CRITICAL"),
        ("gdpr",    "Art.33",     "Notification of a Personal Data Breach",    "Public cloud bucket exposure likely constitutes a personal data breach requiring 72-hour notification.", "CRITICAL"),
        ("pci_dss", "Req.1.3.2", "Restrict Traffic to Cardholder Data",       "Publicly accessible cloud storage that may contain cardholder data violates network access restrictions.", "CRITICAL"),
        ("soc2",    "CC6.1",      "Logical Access Controls",                   "Public cloud buckets eliminate logical access controls entirely for stored data.", "CRITICAL"),
    ],
    "aws_key_in_source": [
        ("dpdp",    "S.8(4)",     "Data Fiduciary Security Obligations",       "Exposed cloud credentials allow unauthorized access to all data stored in cloud infrastructure.", "CRITICAL"),
        ("gdpr",    "Art.32",     "Security of Processing",                    "Exposed AWS keys can grant unlimited access to personal data stored in cloud services.", "CRITICAL"),
        ("pci_dss", "Req.3.4.1", "Protect Stored Account Data",               "Hardcoded cloud credentials can provide access to payment data storage systems.", "CRITICAL"),
    ],

    # ── Cookies ────────────────────────────────────────────────────────────
    "cookie_missing_httponly": [
        ("gdpr",    "Art.32",     "Security of Processing",                    "Session cookies accessible to JavaScript enable session theft via XSS attacks, compromising user accounts and their personal data.", "MEDIUM"),
        ("pci_dss", "Req.6.4.1", "Web Application Vulnerability Protection",  "HttpOnly flag must be set on session cookies to prevent XSS-based session hijacking.", "MEDIUM"),
    ],
    "cookie_missing_secure": [
        ("gdpr",    "Art.32",     "Security of Processing",                    "Session cookies transmitted over HTTP allow session tokens to be intercepted in transit.", "HIGH"),
        ("pci_dss", "Req.4.2.1", "Strong Cryptography in Transit",             "Session cookies must be marked Secure to prevent transmission over unencrypted connections.", "HIGH"),
    ],
    "cookie_missing_samesite": [
        ("gdpr",    "Art.25",     "Data Protection by Design",                 "Missing SameSite attribute exposes the application to Cross-Site Request Forgery attacks that could be used to manipulate personal data.", "MEDIUM"),
    ],

    # ── Reputation ─────────────────────────────────────────────────────────
    "rep_google_unsafe": [
        ("dpdp",    "S.8(4)",     "Data Fiduciary Security Obligations",       "A domain flagged by Google Safe Browsing is actively serving malware or phishing content — immediate action required.", "CRITICAL"),
        ("gdpr",    "Art.32",     "Security of Processing",                    "Serving malware or phishing content constitutes a personal data breach and a failure of all security obligations.", "CRITICAL"),
    ],
    "rep_virustotal_malicious": [
        ("dpdp",    "S.8(4)",     "Data Fiduciary Security Obligations",       "Domain flagged as malicious by multiple threat intelligence vendors.", "CRITICAL"),
        ("gdpr",    "Art.32",     "Security of Processing",                    "Confirmed malicious domain activity represents a severe breach of data processing security obligations.", "CRITICAL"),
    ],

    # ── Performance / Availability ─────────────────────────────────────────
    "high_ttfb": [
        ("dora",    "Art.11(1)",  "Response and Recovery",                     "Excessive TTFB indicates potential performance degradation that may affect ICT service availability and resilience.", "LOW"),
        ("soc2",    "A1.2",       "Availability — Performance Monitoring",     "Response time monitoring is required to demonstrate service availability commitments.", "LOW"),
    ],

    # ── JavaScript ─────────────────────────────────────────────────────────
    "source_map_exposed": [
        ("pci_dss", "Req.6.3.1", "Inventory and Vulnerability Management",    "Exposed source maps reveal proprietary application logic and may expose hardcoded credentials or API endpoints.", "HIGH"),
        ("soc2",    "CC6.6",      "Threats from External Sources",             "Source map exposure assists attackers in understanding application internals and identifying additional attack surfaces.", "MEDIUM"),
    ],
    "mixed_content_detected": [
        ("gdpr",    "Art.32",     "Security of Processing",                    "HTTP resources on an HTTPS page can be intercepted, potentially leaking session tokens or personal data.", "MEDIUM"),
        ("pci_dss", "Req.4.2.1", "Strong Cryptography in Transit",             "Mixed content bypasses HTTPS protection, allowing interception of potentially sensitive data.", "MEDIUM"),
    ],

    # ── HTTP Methods ────────────────────────────────────────────────────────
    "trace_enabled": [
        ("pci_dss", "Req.6.4.1", "Web Application Vulnerability Protection",  "HTTP TRACE method enables Cross-Site Tracing (XST) attacks that can bypass HttpOnly cookie restrictions.", "HIGH"),
        ("soc2",    "CC6.6",      "Threats from External Sources",             "TRACE method provides an attack vector for session hijacking via Cross-Site Tracing.", "MEDIUM"),
    ],
}

# ---------------------------------------------------------------------------
# Positive controls — things that improve the score
# ---------------------------------------------------------------------------

POSITIVE_INDICATORS: list[tuple[str, str, str, str]] = [
    # (check_key_or_condition, framework, clause_id, description)
    ("hsts_enforced",      "pci_dss", "Req.4.2.1", "HSTS enforced — all traffic uses strong encryption"),
    ("dmarc_enforced",     "gdpr",    "Art.32",    "DMARC policy enforced — email spoofing is prevented"),
    ("dmarc_enforced",     "pci_dss", "Req.5.4.1", "DMARC enforced — anti-phishing controls in place"),
    ("no_critical_ports",  "pci_dss", "Req.1.3.2", "No dangerous ports exposed — network segmentation controls effective"),
    ("valid_ssl",          "gdpr",    "Art.32",    "Valid SSL/TLS certificate — data encrypted in transit"),
    ("valid_ssl",          "pci_dss", "Req.4.2.1", "Valid certificate in use for cardholder data transmission"),
    ("caa_present",        "pci_dss", "Req.4.2.1", "CAA records restrict unauthorized certificate issuance"),
    ("dnssec_enabled",     "dora",    "Art.9(2)",  "DNSSEC enabled — DNS integrity cryptographically guaranteed"),
]

# Per-framework base scores (deducted per violation)
FRAMEWORK_VIOLATION_WEIGHTS: dict[str, dict[str, int]] = {
    "dpdp":    {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 7, "LOW": 3},
    "gdpr":    {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2},
    "pci_dss": {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 8, "LOW": 3},
    "soc2":    {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2},
    "dora":    {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2},
}

FRAMEWORK_METADATA: dict[str, tuple[str, str]] = {
    "dpdp":    ("DPDP Act (India)",    "India's Digital Personal Data Protection Act 2023 — governs collection, processing, and storage of Indian citizens' personal digital data."),
    "gdpr":    ("GDPR (EU)",           "EU General Data Protection Regulation — sets global standards for data protection and privacy for EU data subjects."),
    "pci_dss": ("PCI DSS v4.0",        "Payment Card Industry Data Security Standard v4.0 — mandatory for all organizations processing cardholder data."),
    "soc2":    ("SOC 2 Type II",       "Service Organization Control 2 — audit standard for the security, availability, and confidentiality of cloud-hosted services."),
    "dora":    ("DORA (EU)",           "Digital Operational Resilience Act — EU regulation for ICT risk management and operational resilience for financial entities."),
}


# ---------------------------------------------------------------------------
# Core mapping function
# ---------------------------------------------------------------------------

def map_to_frameworks(risk_items: list[dict]) -> ComplianceReport:
    """
    Given a list of classified risk_items from the scanner, annotate each with
    compliance violations and return a full ComplianceReport with per-framework scores.
    """
    # Accumulators per framework
    violations: dict[str, list[ComplianceClause]] = {
        "dpdp": [], "gdpr": [], "pci_dss": [], "soc2": [], "dora": []
    }
    score_deductions: dict[str, int] = {k: 0 for k in violations}
    seen_clauses: dict[str, set] = {k: set() for k in violations}

    for item in risk_items:
        key = item.get("check_type") or item.get("key") or ""
        mapped = FINDING_TO_CLAUSES.get(key, [])

        item_clauses: list[dict] = []
        for (fw, clause_id, clause_title, desc, sev) in mapped:
            clause_key = f"{clause_id}"
            # Avoid counting the same clause twice
            if clause_key not in seen_clauses[fw]:
                seen_clauses[fw].add(clause_key)
                clause = ComplianceClause(
                    framework=FRAMEWORK_METADATA[fw][0],
                    clause_id=clause_id,
                    clause_title=clause_title,
                    description=desc,
                    severity=sev,
                )
                violations[fw].append(clause)
                # Deduct from framework score
                weight = FRAMEWORK_VIOLATION_WEIGHTS[fw].get(sev, 2)
                score_deductions[fw] = min(score_deductions[fw] + weight, 100)

            item_clauses.append({
                "framework": FRAMEWORK_METADATA[fw][0],
                "clause_id": clause_id,
                "clause_title": clause_title,
                "severity": sev,
            })

        # Annotate the finding in-place
        item["compliance_violations"] = item_clauses

    # Build per-framework readiness scores
    framework_reports: dict[str, FrameworkReport] = {}
    for fw, (full_name, summary_blurb) in FRAMEWORK_METADATA.items():
        raw_score = max(0, 100 - score_deductions[fw])
        fw_violations = violations[fw]

        # Build compliant controls list (things that are OK)
        compliant = _derive_compliant_controls(fw, risk_items)

        # Generate a readable summary
        n = len(fw_violations)
        if raw_score >= 85:
            quality = "Strong"
            verdict = f"Your platform demonstrates strong {full_name} compliance posture with {n} identified gap(s)."
        elif raw_score >= 60:
            quality = "Moderate"
            verdict = f"Moderate {full_name} compliance — {n} violation(s) require remediation before an audit."
        elif raw_score >= 35:
            quality = "Weak"
            verdict = f"Significant {full_name} gaps identified — {n} violations could result in regulatory penalties."
        else:
            quality = "Non-Compliant"
            verdict = f"Critical {full_name} non-compliance — {n} violations present immediate regulatory risk. Immediate action required."

        framework_reports[fw] = FrameworkReport(
            framework=fw.upper(),
            full_name=full_name,
            readiness_score=raw_score,
            violated_clauses=fw_violations,
            compliant_controls=compliant,
            summary=verdict,
        )

    return ComplianceReport(
        dpdp=framework_reports["dpdp"],
        gdpr=framework_reports["gdpr"],
        pci_dss=framework_reports["pci_dss"],
        soc2=framework_reports["soc2"],
        dora=framework_reports["dora"],
    )


def _derive_compliant_controls(fw: str, risk_items: list[dict]) -> list[str]:
    """Return a list of compliance controls that are currently passing."""
    item_keys = {(item.get("check_type") or item.get("key") or "") for item in risk_items}
    compliant = []

    # Check positive indicators
    if "ssl_invalid" not in item_keys and "ssl_unavailable" not in item_keys:
        if fw in ("gdpr", "pci_dss", "dpdp"):
            compliant.append("Valid SSL/TLS certificate in use — data encrypted in transit")
    if "headers_no_https_redirect" not in item_keys:
        if fw in ("gdpr", "pci_dss"):
            compliant.append("HTTP to HTTPS redirect enforced")
    if "dns_no_dmarc" not in item_keys and "dns_dmarc_not_enforced" not in item_keys:
        if fw in ("gdpr", "pci_dss"):
            compliant.append("DMARC email authentication policy configured")
    if "ports_database_exposed" not in item_keys:
        if fw in ("pci_dss", "soc2", "dora"):
            compliant.append("Database services not directly exposed to the internet")
    if "public_cloud_bucket" not in item_keys:
        if fw in ("dpdp", "gdpr", "pci_dss"):
            compliant.append("No publicly accessible cloud storage buckets detected")
    if "rep_google_unsafe" not in item_keys:
        if fw in ("dpdp", "gdpr"):
            compliant.append("Domain not flagged by Google Safe Browsing threat intelligence")

    return compliant
