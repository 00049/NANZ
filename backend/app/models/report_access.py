import uuid
from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, text, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base import Base

class ReportShareLink(Base):
    """
    Secure share links for reports, granting read-only access with optional expiration.
    """
    __tablename__ = "report_share_links"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()")
    )
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    token = Column(String(255), unique=True, nullable=False, index=True)
    created_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    
    expires_at = Column(DateTime(timezone=True), nullable=True)
    is_revoked = Column(Boolean, default=False)
    
    created_at = Column(DateTime(timezone=True), server_default=text("now()"))

    __table_args__ = (
        Index("idx_report_shares_scan", "scan_id", "is_revoked"),
    )


class ReportAuditLog(Base):
    """
    Audit log tracking who viewed which report and when, for enterprise compliance.
    """
    __tablename__ = "report_audit_logs"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()")
    )
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    viewer_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    
    viewer_ip = Column(String(45), nullable=True)
    action = Column(String(50), default="view") # view, download_pdf
    
    share_token_used = Column(String(255), nullable=True) # If accessed via a share link
    
    timestamp = Column(DateTime(timezone=True), server_default=text("now()"), index=True)

    __table_args__ = (
        Index("idx_report_audit_scan", "scan_id", "timestamp"),
    )
