"""expand reports table for full scan engine

Revision ID: 002
Revises: 001
Create Date: 2026-04-19 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '002'
down_revision: Union[str, None] = '001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add new columns to reports table
    op.add_column('reports', sa.Column('overall_score', sa.Integer(), server_default='0', nullable=True))
    op.add_column('reports', sa.Column('executive_summary', sa.Text(), nullable=True))
    op.add_column('reports', sa.Column('domain_reports', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column('reports', sa.Column('total_findings', sa.Integer(), server_default='0', nullable=True))
    op.add_column('reports', sa.Column('critical_count', sa.Integer(), server_default='0', nullable=True))
    op.add_column('reports', sa.Column('high_count', sa.Integer(), server_default='0', nullable=True))
    op.add_column('reports', sa.Column('medium_count', sa.Integer(), server_default='0', nullable=True))
    op.add_column('reports', sa.Column('low_count', sa.Integer(), server_default='0', nullable=True))
    op.add_column('reports', sa.Column('info_count', sa.Integer(), server_default='0', nullable=True))
    op.add_column('reports', sa.Column('dpdp_compliance_score', sa.Integer(), server_default='0', nullable=True))
    op.add_column('reports', sa.Column('dpdp_issues', postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade() -> None:
    op.drop_column('reports', 'dpdp_issues')
    op.drop_column('reports', 'dpdp_compliance_score')
    op.drop_column('reports', 'info_count')
    op.drop_column('reports', 'low_count')
    op.drop_column('reports', 'medium_count')
    op.drop_column('reports', 'high_count')
    op.drop_column('reports', 'critical_count')
    op.drop_column('reports', 'total_findings')
    op.drop_column('reports', 'domain_reports')
    op.drop_column('reports', 'executive_summary')
    op.drop_column('reports', 'overall_score')
