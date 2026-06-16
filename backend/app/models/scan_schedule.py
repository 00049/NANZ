from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, String
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)
    domain = Column(String, index=True, nullable=False)
    frequency = Column(String, nullable=False)  # 'daily', 'weekly', 'monthly'
    is_active = Column(Boolean, default=True)
    last_scan_id = Column(UUID(as_uuid=True), nullable=True)
    last_scan_time = Column(DateTime(timezone=True), nullable=True)
    next_scan_time = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
