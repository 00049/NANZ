import uuid
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.db.base import Base

class Report(Base):
    """
    Report model containing the processed, plain-English findings ready for the client.
    """
    __tablename__ = "reports"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()")
    )
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), unique=True, nullable=False)
    overall_severity = Column(String(10), nullable=False)  # RED/AMBER/GREEN
    risk_items = Column(JSONB, nullable=False)
    ai_summary = Column(Text, nullable=True)
    checks_run = Column(JSONB, nullable=False)
    
    ssl_score = Column(Integer, nullable=True)
    header_score = Column(Integer, nullable=True)
    
    is_paid = Column(Boolean, default=False)
    generated_at = Column(DateTime(timezone=True), server_default=text("now()"))
