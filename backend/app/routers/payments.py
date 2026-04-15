import hmac
import hashlib
from uuid import UUID
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone

from app.db.session import get_db
from app.models.scan import Scan
from app.models.report import Report
from app.models.payment import Payment
from app.models.user import User
from app.schemas.payment import PaymentCreateRequest, PaymentCreateResponse, PaymentVerifyRequest, PaymentVerifyResponse
from app.schemas.common import WrappedResponse, success_response, error_response
from app.utils.auth import create_report_token
from app.config import settings
from app.main import limiter

try:
    from app.services.razorpay_service import create_razorpay_order
except ImportError:
    create_razorpay_order = None

router = APIRouter(tags=["Payments"])

@router.post("/create", response_model=WrappedResponse[PaymentCreateResponse])
@limiter.limit("10/hour")
async def create_payment(request: Request, body: PaymentCreateRequest, db: AsyncSession = Depends(get_db)):
    # Verify scan exists and is complete
    scan_result = await db.execute(select(Scan).where(Scan.id == body.scan_id))
    scan = scan_result.scalars().first()
    if not scan or scan.status != "complete":
        return JSONResponse(status_code=400, content=error_response("Scan not ready for payment or not found"))

    # Check if already paid
    existing_payment_result = await db.execute(
        select(Payment).where(Payment.scan_id == body.scan_id, Payment.status == "paid")
    )
    if existing_payment_result.scalars().first():
        return JSONResponse(status_code=400, content=error_response("Already paid for this scan"))

    # Create Razorpay order
    if not create_razorpay_order:
        return JSONResponse(status_code=500, content=error_response("Razorpay service unavailable"))
        
    amount_paise = 49900  # Rs. 499
    order_id = create_razorpay_order(amount_paise, receipt=str(body.scan_id))

    # Store payment
    payment = Payment(
        scan_id=body.scan_id,
        user_email=body.email,
        amount_paise=amount_paise,
        razorpay_order_id=order_id
    )
    db.add(payment)
    await db.commit()
    await db.refresh(payment)

    return success_response(PaymentCreateResponse(
        order_id=order_id,
        amount=amount_paise,
        currency="INR",
        key_id=settings.RAZORPAY_KEY_ID
    ).model_dump())


@router.post("/verify", response_model=WrappedResponse[PaymentVerifyResponse])
async def verify_payment(body: PaymentVerifyRequest, db: AsyncSession = Depends(get_db)):
    order_id = body.razorpay_order_id
    payment_id = body.razorpay_payment_id
    signature = body.razorpay_signature
    email = body.email

    # Verify HMAC signature
    msg = f"{order_id}|{payment_id}"
    expected_sig = hmac.new(
        key=settings.RAZORPAY_KEY_SECRET.encode("utf-8"),
        msg=msg.encode("utf-8"),
        digestmod=hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, signature):
        return JSONResponse(status_code=400, content=error_response("Invalid payment signature"))

    # Retrieve payment record
    payment_result = await db.execute(select(Payment).where(Payment.razorpay_order_id == order_id))
    payment = payment_result.scalars().first()
    if not payment:
        return JSONResponse(status_code=404, content=error_response("Order not found"))

    # Upsert user based on email
    user_result = await db.execute(select(User).where(User.email == email))
    user = user_result.scalars().first()
    if not user:
        user = User(email=email)
        db.add(user)
        await db.commit()
        await db.refresh(user)

    # Check for idempotency
    if payment.status == "paid":
        token = create_report_token(str(user.id), str(payment.scan_id))
        return success_response(PaymentVerifyResponse(access_token=token).model_dump())

    # Update payment and report
    payment.status = "paid"
    payment.razorpay_payment_id = payment_id
    payment.paid_at = datetime.now(timezone.utc)
    
    report_result = await db.execute(select(Report).where(Report.scan_id == payment.scan_id))
    report = report_result.scalars().first()
    if report:
        report.is_paid = True
        
    await db.commit()

    # Issue JWT token
    token = create_report_token(str(user.id), str(payment.scan_id))
    return success_response(PaymentVerifyResponse(access_token=token).model_dump())
