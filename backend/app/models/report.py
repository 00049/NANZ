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

    # New v2 fields
    waf_detected = Column(Boolean, default=False)
    waf_provider = Column(String(50), nullable=True)
    javascript_findings = Column(JSONB, nullable=True)
    cors_findings = Column(JSONB, nullable=True)
    cloud_findings = Column(JSONB, nullable=True)

    # New v3 fields
    email_findings = Column(JSONB, nullable=True)
    performance_findings = Column(JSONB, nullable=True)
    tech_findings = Column(JSONB, nullable=True)
    crawl_findings = Column(JSONB, nullable=True)
    cve_findings = Column(JSONB, nullable=True)

    # v4 — Advanced module fields (Modules 1–10)
    compliance_report = Column(JSONB, nullable=True)    # Module 9: DPDP/GDPR/PCI/SOC2/DORA
    brand_threats = Column(JSONB, nullable=True)        # Module 5: CT log & homoglyph
    bola_findings = Column(JSONB, nullable=True)        # Module 1: BOLA/IDOR
    api_findings = Column(JSONB, nullable=True)         # Module 3: API/GraphQL discovery
    llm_findings = Column(JSONB, nullable=True)         # Module 6: LLM/OWASP security
    oast_interactions = Column(JSONB, nullable=True)    # Module 4: OAST callbacks

    is_paid = Column(Boolean, default=False)
    generated_at = Column(DateTime(timezone=True), server_default=text("now()"))

    # v5 — Enterprise Intelligence Engine
    # Risk Quantification
    ale_reduction_total = Column(Integer, nullable=True)         # Total ALE reduction (INR)
    epss_enriched = Column(Boolean, default=False)               # Whether EPSS data was fetched
    kev_findings_count = Column(Integer, default=0)              # CVEs in CISA KEV catalog
    severity_adjusted_count = Column(Integer, default=0)         # Findings with contextual severity

    # OWASP Coverage
    owasp_coverage = Column(JSONB, nullable=True)                # OWASP Top 10 2021 coverage map
    owasp_llm_coverage = Column(JSONB, nullable=True)            # OWASP LLM Top 10 2025 map

    # Enterprise Compliance v2
    compliance_report_v2 = Column(JSONB, nullable=True)          # Deep DPDP/GDPR/PCI/SOC2 report
    dpdp_penalty_crore = Column(Integer, nullable=True)          # Max DPDP penalty exposure

    # LLM Security Module
    llm_security_data = Column(JSONB, nullable=True)             # LLM security check results

    # SBOM
    sbom_generated = Column(Boolean, default=False)
    sbom_component_count = Column(Integer, default=0)

    # BYOS Ingestion
    ingested_findings = Column(JSONB, nullable=True)             # Findings from third-party scanners
    ingestion_sources = Column(JSONB, nullable=True)             # List of source scanner names
    deduplication_savings = Column(Integer, default=0)           # Findings deduplicated
