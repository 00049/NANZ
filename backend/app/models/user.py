import uuid
from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, Integer, String, text
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base

class User(Base):
    """
    User model to store registered users (via email from payments).
    """
    __tablename__ = "users"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()")
    )
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=True) # Nullable for OAuth or legacy users
    name = Column(String(255), nullable=True)
    company = Column(String(255), nullable=True)
    role = Column(String(50), default="user") # 'user', 'admin'
    
    email_verified = Column(Boolean, default=False)
    scan_credits = Column(Integer, default=0)
    
    created_at = Column(DateTime(timezone=True), server_default=text("now()"))
    updated_at = Column(DateTime(timezone=True), server_default=text("now()"), onupdate=datetime.utcnow)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
