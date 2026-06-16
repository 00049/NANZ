"""Migration 006: Enterprise Scoring — v5 columns for ASPM intelligence engine.

Adds new JSONB and Integer columns to the reports table for:
  - EPSS enrichment flags
  - OWASP coverage maps (Top 10 + LLM)
  - Enterprise compliance v2 (DPDP/GDPR/PCI/SOC2 deep reports)
  - SBOM tracking flags
  - BYOS ingestion store

NOTE: All new columns have defaults, making this migration backward-compatible
with existing reports rows.
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = '006_enterprise_scoring'
down_revision = '005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add v5 enterprise intelligence columns to reports table."""
    with op.batch_alter_table('reports', schema=None) as batch_op:
        # Risk Quantification
        batch_op.add_column(sa.Column(
            'ale_reduction_total',
            sa.Integer(),
            nullable=True,
            comment='Total Annual Loss Expectancy reduction in INR'
        ))
        batch_op.add_column(sa.Column(
            'epss_enriched',
            sa.Boolean(),
            server_default='false',
            nullable=False,
            comment='Whether EPSS data was fetched for CVE findings'
        ))
        batch_op.add_column(sa.Column(
            'kev_findings_count',
            sa.Integer(),
            server_default='0',
            nullable=False,
            comment='Number of findings in CISA Known Exploited Vulnerabilities catalog'
        ))
        batch_op.add_column(sa.Column(
            'severity_adjusted_count',
            sa.Integer(),
            server_default='0',
            nullable=False,
            comment='Number of findings with contextual severity override'
        ))

        # OWASP Coverage
        batch_op.add_column(sa.Column(
            'owasp_coverage',
            JSONB(),
            nullable=True,
            comment='OWASP Top 10 2021 structured coverage map'
        ))
        batch_op.add_column(sa.Column(
            'owasp_llm_coverage',
            JSONB(),
            nullable=True,
            comment='OWASP LLM Top 10 2025 structured coverage map'
        ))

        # Enterprise Compliance v2
        batch_op.add_column(sa.Column(
            'compliance_report_v2',
            JSONB(),
            nullable=True,
            comment='Full section-level compliance report: DPDP/GDPR/PCI DSS/SOC 2'
        ))
        batch_op.add_column(sa.Column(
            'dpdp_penalty_crore',
            sa.Integer(),
            nullable=True,
            comment='Maximum DPDP Act penalty exposure in Indian Crores'
        ))

        # LLM Security
        batch_op.add_column(sa.Column(
            'llm_security_data',
            JSONB(),
            nullable=True,
            comment='LLM OWASP security check results'
        ))

        # SBOM
        batch_op.add_column(sa.Column(
            'sbom_generated',
            sa.Boolean(),
            server_default='false',
            nullable=False,
            comment='Whether an SBOM was generated for this scan'
        ))
        batch_op.add_column(sa.Column(
            'sbom_component_count',
            sa.Integer(),
            server_default='0',
            nullable=False,
            comment='Number of software components in the SBOM'
        ))

        # BYOS Ingestion
        batch_op.add_column(sa.Column(
            'ingested_findings',
            JSONB(),
            nullable=True,
            comment='Findings ingested from third-party scanners (SARIF/Snyk/Trivy/Semgrep)'
        ))
        batch_op.add_column(sa.Column(
            'ingestion_sources',
            JSONB(),
            nullable=True,
            comment='List of scanner names that contributed ingested findings'
        ))
        batch_op.add_column(sa.Column(
            'deduplication_savings',
            sa.Integer(),
            server_default='0',
            nullable=False,
            comment='Number of ingested findings merged with existing results (deduplication count)'
        ))


def downgrade() -> None:
    """Remove v5 enterprise intelligence columns from reports table."""
    with op.batch_alter_table('reports', schema=None) as batch_op:
        for col in [
            'ale_reduction_total',
            'epss_enriched',
            'kev_findings_count',
            'severity_adjusted_count',
            'owasp_coverage',
            'owasp_llm_coverage',
            'compliance_report_v2',
            'dpdp_penalty_crore',
            'llm_security_data',
            'sbom_generated',
            'sbom_component_count',
            'ingested_findings',
            'ingestion_sources',
            'deduplication_savings',
        ]:
            batch_op.drop_column(col)
