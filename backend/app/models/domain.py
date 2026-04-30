import uuid
from datetime import datetime
from sqlalchemy import Column, DateTime, String, ForeignKey, text, Boolean, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base import Base

class Domain(Base):
    """
    Domain model for assets tracked by users in their SaaS dashboard.
    """
    __tablename__ = "domains"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()")
    )
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    domain_name = Column(String(255), nullable=False)
    status = Column(String(50), default="pending") # pending, verified, active, paused
    is_verified = Column(Boolean, default=False)
    
    monitoring_frequency = Column(String(50), default="weekly") # daily, weekly, monthly
    last_scan_id = Column(UUID(as_uuid=True), nullable=True) # Optional link to last scan
    
    created_at = Column(DateTime(timezone=True), server_default=text("now()"))
    updated_at = Column(DateTime(timezone=True), server_default=text("now()"), onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", backref="domains")
