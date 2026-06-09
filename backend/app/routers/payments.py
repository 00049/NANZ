import hmac
import hashlib
import logging
from uuid import UUID
from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timezone

from app.db.session import get_db
from app.models import Payment, Report, Scan, User
from app.schemas.payment import PaymentCreateRequest, PaymentCreateResponse, PaymentVerifyRequest, PaymentVerifyResponse
from app.utils.auth import create_report_token
from app.config import settings
from app.main import limiter

try:
    from app.services.razorpay_service import create_razorpay_order
except ImportError:
    create_razorpay_order = None

router = APIRouter(tags=["Payments"])
logger = logging.getLogger(__name__)


@router.post("/create", response_model=PaymentCreateResponse)
@limiter.limit("10/hour")
async def create_payment(request: Request, body: PaymentCreateRequest, db: AsyncSession = Depends(get_db)) -> PaymentCreateResponse:
    """Create a Razorpay order for a completed scan report."""
    scan_result = await db.execute(select(Scan).where(Scan.id == body.scan_id))
    scan = scan_result.scalars().first()
    if not scan or scan.status != "complete":
        raise HTTPException(status_code=400, detail="Scan not ready for payment or not found")

    existing_payment_result = await db.execute(
        select(Payment).where(Payment.scan_id == body.scan_id, Payment.status == "paid")
    )
    if existing_payment_result.scalars().first():
        raise HTTPException(status_code=400, detail="Already paid for this scan")

    if not create_razorpay_order:
        raise HTTPException(status_code=500, detail="Payment provider unavailable")
        
    amount_paise = 49900
    try:
        order_id = create_razorpay_order(amount_paise, receipt=str(body.scan_id))
    except (ValueError, RuntimeError, KeyError) as e:
        logger.error(f"Razorpay order creation failed for scan_id={body.scan_id}: {e}", exc_info=True)
        raise HTTPException(status_code=503, detail="Payment provider unavailable") from e

    payment = Payment(
        scan_id=body.scan_id,
        user_email=body.email,
        amount_paise=amount_paise,
        razorpay_order_id=order_id
    )
    try:
        db.add(payment)
        await db.commit()
        await db.refresh(payment)
    except SQLAlchemyError as e:
        logger.error(f"Database error storing payment for scan_id={body.scan_id}: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(status_code=503, detail="Database temporarily unavailable") from e

    return PaymentCreateResponse(
        order_id=order_id,
        amount=amount_paise,
        currency="INR",
        key_id=settings.RAZORPAY_KEY_ID
    )


@router.post("/verify", response_model=PaymentVerifyResponse)
async def verify_payment(body: PaymentVerifyRequest, db: AsyncSession = Depends(get_db)) -> PaymentVerifyResponse:
    """Verify a Razorpay payment HMAC and issue a report access JWT."""
    order_id = body.razorpay_order_id
    payment_id = body.razorpay_payment_id
    signature = body.razorpay_signature
    email = body.email

    msg = f"{order_id}|{payment_id}"
    expected_sig = hmac.new(
        key=settings.RAZORPAY_KEY_SECRET.encode("utf-8"),
        msg=msg.encode("utf-8"),
        digestmod=hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, signature):
        raise HTTPException(status_code=400, detail="Invalid payment signature")

    payment_result = await db.execute(select(Payment).where(Payment.razorpay_order_id == order_id))
    payment = payment_result.scalars().first()
    if not payment:
        raise HTTPException(status_code=404, detail="Order not found")

    user_result = await db.execute(select(User).where(User.email == email))
    user = user_result.scalars().first()
    if not user:
        user = User(email=email)
        db.add(user)
        await db.commit()
        await db.refresh(user)

    if payment.status == "paid":
        token = create_report_token(str(user.id), str(payment.scan_id))
        return PaymentVerifyResponse(access_token=token)

    payment.status = "paid"
    payment.razorpay_payment_id = payment_id
    payment.paid_at = datetime.now(timezone.utc)
    
    report_result = await db.execute(select(Report).where(Report.scan_id == payment.scan_id))
    report = report_result.scalars().first()
    if report:
        report.is_paid = True
        
    await db.commit()
    
    # Send payment confirmation email asynchronously
    try:
        from app.services.email_service import send_payment_confirmation_email
        import asyncio
        
        # we need domain which we can get from scan
        scan_result = await db.execute(select(Scan).where(Scan.id == payment.scan_id))
        scan = scan_result.scalars().first()
        domain = scan.domain if scan else "your domain"
        
        asyncio.create_task(asyncio.to_thread(
            send_payment_confirmation_email, 
            email, 
            domain, 
            payment.amount_paise / 100.0, 
            str(payment.scan_id)
        ))
    except Exception as e:
        logger.error(f"Failed to trigger payment confirmation email: {e}")

    token = create_report_token(str(user.id), str(payment.scan_id))
    return PaymentVerifyResponse(access_token=token)

from app.core.security import get_current_user

@router.get("/history")
async def get_payment_history(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Get the user's payment history."""
    query = (
        select(Payment, Scan.domain)
        .join(Scan, Payment.scan_id == Scan.id)
        .where(Payment.user_email == current_user.email, Payment.status == "paid")
        .order_by(Payment.created_at.desc())
    )
    result = await db.execute(query)
    rows = result.all()
    
    history = []
    for payment, domain in rows:
        history.append({
            "order_id": payment.razorpay_order_id,
            "amount": payment.amount_paise / 100.0,
            "created_at": payment.created_at.isoformat() if payment.created_at else None,
            "scan_id": str(payment.scan_id),
            "status": payment.status,
            "domain": domain
        })
        
    return history
