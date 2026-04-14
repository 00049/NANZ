"""initial schema

Revision ID: 001
Revises: 
Create Date: 2024-05-18 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Users table
    op.create_table('users',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('email_verified', sa.Boolean(), nullable=True),
        sa.Column('scan_credits', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)

    # Scans table
    op.create_table('scans',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('scan_type', sa.String(length=10), nullable=True),
        sa.Column('raw_findings', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('scan_duration_ms', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('requester_ip', sa.String(length=45), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_scans_domain', 'scans', ['domain'], unique=False)
    op.create_index('idx_scans_requester_ip', 'scans', ['requester_ip', 'created_at'], unique=False)
    op.create_index('idx_scans_status', 'scans', ['status'], unique=False)
    op.create_index('idx_scans_url', 'scans', ['url'], unique=False)

    # Reports table
    op.create_table('reports',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('overall_severity', sa.String(length=10), nullable=False),
        sa.Column('risk_items', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('ai_summary', sa.Text(), nullable=True),
        sa.Column('checks_run', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('ssl_score', sa.Integer(), nullable=True),
        sa.Column('header_score', sa.Integer(), nullable=True),
        sa.Column('is_paid', sa.Boolean(), nullable=True),
        sa.Column('generated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('scan_id')
    )

    # Payments table
    op.create_table('payments',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('user_email', sa.String(length=255), nullable=False),
        sa.Column('amount_paise', sa.Integer(), nullable=False),
        sa.Column('currency', sa.String(length=3), nullable=True),
        sa.Column('razorpay_order_id', sa.String(length=100), nullable=False),
        sa.Column('razorpay_payment_id', sa.String(length=100), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('paid_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('razorpay_order_id'),
        sa.UniqueConstraint('scan_id')
    )
    op.create_index('idx_payments_status', 'payments', ['status'], unique=False)


def downgrade() -> None:
    op.drop_index('idx_payments_status', table_name='payments')
    op.drop_table('payments')
    op.drop_table('reports')
    op.drop_index('idx_scans_url', table_name='scans')
    op.drop_index('idx_scans_status', table_name='scans')
    op.drop_index('idx_scans_requester_ip', table_name='scans')
    op.drop_index('idx_scans_domain', table_name='scans')
    op.drop_table('scans')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
