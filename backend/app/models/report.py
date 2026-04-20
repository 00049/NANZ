import uuid
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.db.base import Base


class Report(Base):
    """
    Report model containing the processed, plain-English findings ready for the client.
    Expanded to support full detailed reports across 8 security domains.
    """
    __tablename__ = "reports"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()")
    )
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), unique=True, nullable=False)
    overall_severity = Column(String(10), nullable=False)  # CRITICAL/RED/AMBER/GREEN
    overall_score = Column(Integer, default=0)  # 0-100 security score
    risk_items = Column(JSONB, nullable=False)  # List of RiskItem dicts
    ai_summary = Column(Text, nullable=True)
    executive_summary = Column(Text, nullable=True)
    checks_run = Column(JSONB, nullable=False)

    # Domain-specific detailed reports (JSONB)
    domain_reports = Column(JSONB, nullable=True)  # {ssl: {...}, headers: {...}, ...}

    # Legacy score fields (kept for backward compat)
    ssl_score = Column(Integer, nullable=True)
    header_score = Column(Integer, nullable=True)

    # Finding counts
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)

    # DPDP compliance
    dpdp_compliance_score = Column(Integer, default=0)
    dpdp_issues = Column(JSONB, nullable=True)  # List of DPDP issue strings

    is_paid = Column(Boolean, default=False)
    generated_at = Column(DateTime(timezone=True), server_default=text("now()"))
