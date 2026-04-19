from pydantic import BaseModel, ConfigDict, EmailStr
from uuid import UUID

class PaymentCreateRequest(BaseModel):
    """Request body for creating a Razorpay order."""

    scan_id: UUID
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)

class PaymentCreateResponse(BaseModel):
    """Razorpay order details returned to the frontend."""

    order_id: str
    amount: int
    currency: str
    key_id: str

    model_config = ConfigDict(from_attributes=True)

class PaymentVerifyRequest(BaseModel):
    """Request body for verifying Razorpay payment success."""

    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)

class PaymentVerifyResponse(BaseModel):
    """JWT response for paid report access."""

    access_token: str
    token_type: str = "bearer"

    model_config = ConfigDict(from_attributes=True)
