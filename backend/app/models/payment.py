import uuid
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, text, Index
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base

class Payment(Base):
    """
    Payment model mapping to Razorpay orders and transactions.
    """
    __tablename__ = "payments"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()")
    )
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), unique=True, nullable=False)
    user_email = Column(String(255), nullable=False)
    amount_paise = Column(Integer, nullable=False)
    currency = Column(String(3), default="INR")
    
    razorpay_order_id = Column(String(100), unique=True, nullable=False)
    razorpay_payment_id = Column(String(100), nullable=True)
    status = Column(String(20), default="created")  # created/paid/failed/refunded
    
    paid_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=text("now()"))

    __table_args__ = (
        Index("idx_payments_status", "status"),
    )
