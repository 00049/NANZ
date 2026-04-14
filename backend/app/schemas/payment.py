from pydantic import BaseModel, ConfigDict, EmailStr
from uuid import UUID

class PaymentCreateRequest(BaseModel):
    scan_id: UUID
    email: EmailStr

class PaymentCreateResponse(BaseModel):
    order_id: str
    amount: int
    currency: str
    key_id: str

class PaymentVerifyRequest(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str
    email: EmailStr

class PaymentVerifyResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

    model_config = ConfigDict(from_attributes=True)
