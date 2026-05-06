"""
Expanded report schemas — FullReport with 8 domain-specific sub-reports,
CRITICAL severity level, DPDP compliance, and comprehensive risk items.
"""

from pydantic import BaseModel, ConfigDict, EmailStr, field_validator
from typing import Literal, Optional, Any
from uuid import UUID
from datetime import datetime


class RiskItem(BaseModel):
    """Expanded risk item with enterprise financial risk metrics and compliance mapping."""

    id: str = ""
    title: str
    severity: Literal["CRITICAL", "RED", "AMBER", "GREEN", "INFO"]
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    check_domain: str = ""
    check_type: str = ""
    business_impact: str
    technical_detail: str = ""
    fix_action: str
    fix_difficulty: Literal["Easy", "Medium", "Hard"] = "Medium"
    estimated_fix_time: str = ""
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = "MEDIUM"
    references: list[str] = []

    # ── EPSS + CISA KEV enrichment ──────────────────────────────────────────
    epss_score: Optional[float] = None          # 0.0–1.0 exploit probability
    epss_percentile: Optional[int] = None       # 0–100
    cisa_kev: bool = False                      # In CISA Known Exploited Vulns catalog
    actively_exploited: bool = False            # kev OR epss >= 0.5
    epss_badge: Optional[str] = None           # "🚨 CISA KEV" | "⚡ Actively Exploited" | ...

    # ── Contextual severity override ────────────────────────────────────────
    contextual_severity: Optional[str] = None   # Adjusted severity after EPSS/KEV
    severity_adjusted: bool = False             # True if severity was changed
    severity_reason: Optional[str] = None       # Explanation for adjustment
    original_severity: Optional[str] = None     # Pre-adjustment severity

    # ── RRF (Risk Reduction Factor) ─────────────────────────────────────────
    rrf_score: Optional[float] = None           # 0.00–3.00
    rrf_label: Optional[str] = None             # "High" | "Medium" | "Low"
    rrf_display: Optional[str] = None           # "Risk Reduction: 2.14 (High)"

    # ── ALE (Annual Loss Expectancy) — in INR ───────────────────────────────
    ale_reduction_inr: Optional[int] = None     # Rupee value
    ale_display: Optional[str] = None           # Human-readable INR display
    ale_data: Optional[dict] = None             # Full ALE breakdown dict

    # ── SLA Tier ─────────────────────────────────────────────────────────────
    sla_deadline: Optional[str] = None          # "24 hours" | "7 days" | "30 days" | "90 days"
    sla_tier: Optional[str] = None              # "P0" | "P1" | "P2" | "P3"

    # ── Scanner provenance ────────────────────────────────────────────────────
    source_scanner: Optional[str] = None        # "semgrep" | "snyk" | "trivy" | ...
    ingested: bool = False                      # True if from BYOS ingestion
    confirmed_by: list[str] = []                # All scanners that confirmed this finding

    @field_validator("title")
    def title_not_too_long(cls, v: str) -> str:
        """Validate title length for business-readable report cards."""
        if len(v.split()) > 12:
            raise ValueError("Title too long")
        return v

    model_config = ConfigDict(from_attributes=True)


class DomainDetailReport(BaseModel):
    """Generic domain detail report — used for each of the 8 domains."""

    domain_name: str = ""
    data: dict = {}
    error: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class FullReport(BaseModel):
    """Full expanded security report with all enterprise intelligence fields."""

    scan_id: UUID
    domain: str
    scan_duration_seconds: float = 0.0
    overall_severity: Literal["CRITICAL", "RED", "AMBER", "GREEN"]
    overall_score: int = 0  # 0-100 security score

    # Executive summary (AI generated)
    executive_summary: str = ""

    # Risk items by severity
    critical_risks: list[RiskItem] = []
    high_risks: list[RiskItem] = []
    medium_risks: list[RiskItem] = []
    low_risks: list[RiskItem] = []
    info_risks: list[RiskItem] = []

    # Domain-by-domain detailed results
    ssl_report: Optional[dict] = None
    headers_report: Optional[dict] = None
    dns_report: Optional[dict] = None
    ports_report: Optional[dict] = None
    webapp_report: Optional[dict] = None
    cms_report: Optional[dict] = None
    reputation_report: Optional[dict] = None
    infra_report: Optional[dict] = None

    # Stats
    total_checks_run: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # ── Legacy DPDP Compliance (basic) ───────────────────────────────────────
    dpdp_compliance_score: int = 0
    dpdp_issues: list[str] = []

    # ── Enterprise Compliance v2 (section-level) ──────────────────────────────
    compliance_report_v2: Optional[dict] = None     # Full DPDP/GDPR/PCI/SOC2 deep report
    dpdp_penalty_crore: Optional[int] = None        # Total max DPDP penalty exposure (crore)
    dpdp_risk_level: Optional[str] = None           # "Compliant" | "At Risk" | "Non-Compliant"
    gdpr_status: Optional[str] = None               # "Compliant" | "Partial" | "Non-Compliant"
    pci_status: Optional[str] = None                # "Compliant" | "Partial" | "Not Applicable"
    soc2_status: Optional[str] = None              # "Compliant" | "Partial" | "Non-Compliant"

    # ── OWASP Coverage ────────────────────────────────────────────────────────
    owasp_coverage: Optional[dict] = None           # OWASP Top 10 2021 coverage map
    owasp_llm_coverage: Optional[dict] = None       # OWASP LLM Top 10 2025 coverage map
    owasp_coverage_score: int = 0                   # 0–100 percentage
    owasp_llm_coverage_score: int = 0

    # ── Risk Quantification Summary ───────────────────────────────────────────
    total_ale_reduction_inr: Optional[int] = None   # Total preventable annual loss (INR)
    total_ale_display: Optional[str] = None         # Human-readable INR summary
    avg_rrf_score: Optional[float] = None
    kev_findings_count: int = 0                     # Findings in CISA KEV
    epss_enriched_count: int = 0                    # Findings with EPSS data
    severity_adjusted_count: int = 0               # Findings with adjusted severity
    p0_count: int = 0
    p1_count: int = 0
    p2_count: int = 0
    p3_count: int = 0

    # ── SBOM ─────────────────────────────────────────────────────────────────
    sbom_generated: bool = False
    sbom_component_count: int = 0

    # ── BYOS Ingestion ────────────────────────────────────────────────────────
    ingested_findings_count: int = 0
    deduplication_savings: int = 0
    ingestion_sources: list[str] = []

    # Metadata
    generated_at: datetime = datetime.utcnow()
    is_paid: bool = False

    model_config = ConfigDict(from_attributes=True)


class ReportEmailRequest(BaseModel):
    """Request body for emailing a paid report."""

    email: EmailStr

    model_config = ConfigDict(from_attributes=True)


class FreePreviewResponse(BaseModel):
    """Free locked preview — limited data shown to unpaid users."""

    scan_id: UUID
    domain: str
    overall_severity: Literal["CRITICAL", "RED", "AMBER", "GREEN"]
    overall_score: int
    executive_summary: str = ""  # 2 sentences only for free

    # Top 3 risks — title + business_impact only
    top_risks: list[dict] = []

    # Counts
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    total_findings: int = 0

    locked_risks_count: int = 0
    is_paid: bool = False

    model_config = ConfigDict(from_attributes=True)


class ReportResponse(BaseModel):
    """Full paid report response — backwards compatible."""

    id: UUID
    scan_id: UUID
    overall_severity: str
    risk_items: list[RiskItem]
    ai_summary: Optional[str] = None
    checks_run: dict
    ssl_score: Optional[int] = None
    header_score: Optional[int] = None
    is_paid: bool
    generated_at: datetime

    # Expanded fields
    overall_score: int = 0
    executive_summary: str = ""
    domain_reports: Optional[dict] = None
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    dpdp_compliance_score: int = 0
    dpdp_issues: list[str] = []

    model_config = ConfigDict(from_attributes=True)
