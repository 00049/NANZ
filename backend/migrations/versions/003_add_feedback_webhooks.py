"""003 — Add v2 report columns, scan_feedback and scan_webhooks tables.

Revision ID: 003
Revises: 002
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── New columns on reports ──
    op.add_column("reports", sa.Column("waf_detected", sa.Boolean(), server_default="false"))
    op.add_column("reports", sa.Column("waf_provider", sa.String(50), nullable=True))
    op.add_column("reports", sa.Column("javascript_findings", JSONB(), nullable=True))
    op.add_column("reports", sa.Column("cors_findings", JSONB(), nullable=True))
    op.add_column("reports", sa.Column("cloud_findings", JSONB(), nullable=True))

    # ── scan_feedback table ──
    op.create_table(
        "scan_feedback",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", sa.String(50), nullable=False),
        sa.Column("check_type", sa.String(50), nullable=False),
        sa.Column("feedback_type", sa.String(20), nullable=False),  # false_positive / confirmed / fixed
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_scan_feedback_check_type_feedback", "scan_feedback", ["check_type", "feedback_type"])

    # ── scan_webhooks table ──
    op.create_table(
        "scan_webhooks",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("webhook_url", sa.Text(), nullable=False),
        sa.Column("webhook_secret", sa.String(100), nullable=False),
        sa.Column("delivered", sa.Boolean(), server_default="false"),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )


def downgrade() -> None:
    op.drop_table("scan_webhooks")
    op.drop_index("ix_scan_feedback_check_type_feedback", table_name="scan_feedback")
    op.drop_table("scan_feedback")
    op.drop_column("reports", "cloud_findings")
    op.drop_column("reports", "cors_findings")
    op.drop_column("reports", "javascript_findings")
    op.drop_column("reports", "waf_provider")
    op.drop_column("reports", "waf_detected")
