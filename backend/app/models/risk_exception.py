import uuid
from sqlalchemy import Column, DateTime, ForeignKey, String, Text, text, Enum
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base

class RiskException(Base):
    """
    Model for Accepted Risks / False Positives on a per-domain, per-finding_key basis.
    """
    __tablename__ = "risk_exceptions"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()")
    )
    domain_id = Column(UUID(as_uuid=True), ForeignKey("domains.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # The unique finding key (e.g., 'ssl_heartbleed', 'dns_no_spf')
    finding_key = Column(String(255), nullable=False, index=True)
    
    status = Column(String(50), nullable=False, default="accepted") # accepted, mitigated, false_positive
    justification = Column(Text, nullable=False)
    owner = Column(String(255), nullable=False)
    
    expires_at = Column(DateTime(timezone=True), nullable=True)
    
    created_at = Column(DateTime(timezone=True), server_default=text("now()"))
    updated_at = Column(DateTime(timezone=True), server_default=text("now()"), onupdate=text("now()"))
    
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)


class RiskExceptionHistory(Base):
    """
    Audit trail for changes to RiskExceptions.
    """
    __tablename__ = "risk_exception_history"
    
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()")
    )
    exception_id = Column(UUID(as_uuid=True), ForeignKey("risk_exceptions.id", ondelete="CASCADE"), nullable=False, index=True)
    
    action = Column(String(50), nullable=False) # created, updated, revoked, expired
    previous_status = Column(String(50), nullable=True)
    new_status = Column(String(50), nullable=False)
    
    actor_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=text("now()"))
    notes = Column(Text, nullable=True)
