import uuid
from sqlalchemy import Column, DateTime, String, text
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base

class APIWaitlist(Base):
    """
    Model for the API access waitlist.
    """
    __tablename__ = "api_waitlist"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()")
    )
    email = Column(String(255), unique=True, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=text("now()"))
