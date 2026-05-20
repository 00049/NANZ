"""Safe add all missing columns (idempotent)

Revision ID: f001_safe_missing
Revises: c6ba008bc491
Create Date: 2026-05-20

Adds any columns that may be missing due to previous failed migrations.
Uses IF NOT EXISTS so it is safe to run multiple times.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy import text

# revision identifiers
revision = 'f001_safe_missing'
down_revision = 'c6ba008bc491'
branch_labels = None
depends_on = None


def column_exists(table, column):
    """Check if a column exists in a table."""
    conn = op.get_bind()
    result = conn.execute(text(
        "SELECT COUNT(*) FROM information_schema.columns "
        "WHERE table_name = :t AND column_name = :c"
    ), {"t": table, "c": column})
    return result.scalar() > 0


def add_if_missing(table, column, col_type):
    if not column_exists(table, column):
        op.add_column(table, sa.Column(column, col_type, nullable=True))


def upgrade() -> None:
    # ── reports table ─────────────────────────────────────────────────────────
    jsonb = postgresql.JSONB(astext_type=sa.Text())

    # From migration 002_expand_reports_table
    add_if_missing('reports', 'waf_detected',       sa.Boolean())
    add_if_missing('reports', 'waf_provider',       sa.String(length=100))
    add_if_missing('reports', 'javascript_findings', jsonb)
    add_if_missing('reports', 'cors_findings',      jsonb)
    add_if_missing('reports', 'cloud_findings',     jsonb)
    add_if_missing('reports', 'ai_summary',         sa.Text())
    add_if_missing('reports', 'executive_summary',  sa.Text())
    add_if_missing('reports', 'compliance_report',  jsonb)
    add_if_missing('reports', 'brand_threats',      jsonb)
    add_if_missing('reports', 'bola_findings',      jsonb)
    add_if_missing('reports', 'api_findings',       jsonb)
    add_if_missing('reports', 'llm_findings',       jsonb)
    add_if_missing('reports', 'oast_interactions',  jsonb)

    # From migration ce1290e8dfe3 (v3 report fields)
    add_if_missing('reports', 'email_findings',       jsonb)
    add_if_missing('reports', 'performance_findings', jsonb)
    add_if_missing('reports', 'tech_findings',        jsonb)
    add_if_missing('reports', 'crawl_findings',       jsonb)
    add_if_missing('reports', 'cve_findings',         jsonb)

    # ── scans table ──────────────────────────────────────────────────────────
    # From migration c6ba008bc491 (add user_id + domain_id to scan)
    add_if_missing('scans', 'user_id',   sa.UUID())
    add_if_missing('scans', 'domain_id', sa.UUID())

    # ── users table ──────────────────────────────────────────────────────────
    # From migration 10d6f468f3d8
    add_if_missing('users', 'hashed_password', sa.String(length=255))
    add_if_missing('users', 'name',            sa.String(length=255))
    add_if_missing('users', 'company',         sa.String(length=255))
    add_if_missing('users', 'role',            sa.String(length=50))
    add_if_missing('users', 'email_verified',  sa.Boolean())
    add_if_missing('users', 'scan_credits',    sa.Integer())


def downgrade() -> None:
    pass  # This migration is intentionally non-reversible (safety net only)
