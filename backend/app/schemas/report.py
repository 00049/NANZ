"""
Expanded report schemas — FullReport with 8 domain-specific sub-reports,
CRITICAL severity level, DPDP compliance, and comprehensive risk items.
"""

from pydantic import BaseModel, ConfigDict, EmailStr, field_validator
from typing import Literal, Optional, Any
from uuid import UUID
from datetime import datetime


class RiskItem(BaseModel):
    """Expanded risk item with technical detail and fix metadata."""

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
    confidence: Literal["HIGH", "MEDIUM", "LOW"]
    references: list[str] = []

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
    """Full expanded security report with all 8 domains."""

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

    # DPDP Compliance
    dpdp_compliance_score: int = 0
    dpdp_issues: list[str] = []

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
