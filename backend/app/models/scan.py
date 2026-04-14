import uuid
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, text, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.db.base import Base

class Scan(Base):
    """
    Scan model storing raw findings and execution status.
    """
    __tablename__ = "scans"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()")
    )
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    url = Column(Text, nullable=False)
    domain = Column(String(255), nullable=False)
    ip_address = Column(String(45), nullable=True)
    status = Column(String(20), default="pending")  # pending/running/complete/failed
    scan_type = Column(String(10), default="free")  # free/paid
    
    raw_findings = Column(JSONB, nullable=True)
    scan_duration_ms = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    
    created_at = Column(DateTime(timezone=True), server_default=text("now()"))
    completed_at = Column(DateTime(timezone=True), nullable=True)
    requester_ip = Column(String(45), nullable=True)

    __table_args__ = (
        Index("idx_scans_url", "url"),
        Index("idx_scans_status", "status"),
        Index("idx_scans_domain", "domain"),
        Index("idx_scans_requester_ip", "requester_ip", "created_at"),
    )
