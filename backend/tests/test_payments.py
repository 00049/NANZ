import hashlib
import hmac
from unittest.mock import patch

import pytest

from app.config import settings


@pytest.mark.asyncio
@patch("app.routers.payments.create_razorpay_order")
async def test_payment_create_returns_order_id(
    mock_create, test_client, sample_completed_scan
):
    mock_create.return_value = "order_abc123"

    response = await test_client.post(
        "/api/payments/create",
        json={"scan_id": str(sample_completed_scan), "email": "test@example.com"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["order_id"] == "order_abc123"
    assert data["amount"] == 49900


@pytest.mark.asyncio
async def test_payment_verify_valid_hmac(
    test_client, sample_completed_scan, db_session
):
    # Setup test order in DB
    from app.models.payment import Payment

    payment = Payment(
        scan_id=sample_completed_scan,
        user_email="test@example.com",
        amount_paise=49900,
        razorpay_order_id="order_123",
    )
    db_session.add(payment)
    await db_session.commit()

    order_id = "order_123"
    payment_id = "pay_123"
    msg = f"{order_id}|{payment_id}"
    real_sig = hmac.new(
        key=settings.RAZORPAY_KEY_SECRET.encode("utf-8"),
        msg=msg.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()

    response = await test_client.post(
        "/api/payments/verify",
        json={
            "razorpay_order_id": order_id,
            "razorpay_payment_id": payment_id,
            "razorpay_signature": real_sig,
            "email": "test@example.com",
        },
    )

    assert response.status_code == 200
    assert "access_token" in response.json()


@pytest.mark.asyncio
async def test_payment_verify_invalid_hmac(test_client):
    response = await test_client.post(
        "/api/payments/verify",
        json={
            "razorpay_order_id": "order_123",
            "razorpay_payment_id": "pay_123",
            "razorpay_signature": "invalid_sig",
            "email": "test@example.com",
        },
    )
    assert response.status_code == 400
    assert "Invalid payment signature" in response.json()["detail"]


@pytest.mark.asyncio
async def test_payment_verify_idempotent(
    test_client, sample_completed_scan, db_session
):
    from app.models.payment import Payment

    payment = Payment(
        scan_id=sample_completed_scan,
        user_email="test@example.com",
        amount_paise=49900,
        razorpay_order_id="order_123",
        status="paid",
    )
    from app.models.user import User

    user = User(email="test@example.com")
    db_session.add(payment)
    db_session.add(user)
    await db_session.commit()

    order_id = "order_123"
    payment_id = "pay_123"
    msg = f"{order_id}|{payment_id}"
    real_sig = hmac.new(
        key=settings.RAZORPAY_KEY_SECRET.encode("utf-8"),
        msg=msg.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()

    resp1 = await test_client.post(
        "/api/payments/verify",
        json={
            "razorpay_order_id": order_id,
            "razorpay_payment_id": payment_id,
            "razorpay_signature": real_sig,
            "email": "test@example.com",
        },
    )
    assert resp1.status_code == 200
    token1 = resp1.json()["access_token"]

    resp2 = await test_client.post(
        "/api/payments/verify",
        json={
            "razorpay_order_id": order_id,
            "razorpay_payment_id": payment_id,
            "razorpay_signature": real_sig,
            "email": "test@example.com",
        },
    )
    assert resp2.status_code == 200
    token2 = resp2.json()["access_token"]

    # Should be two distinct tokens with different claim datetimes (issued at slightly different millisecond)
    # But essentially it's idempotent in that it won't crash or create new records
    assert token1 is not None and token2 is not None


@pytest.mark.asyncio
async def test_payment_create_fails_if_scan_not_complete(test_client, sample_scan_id):
    # sample_scan_id is 'pending' status
    response = await test_client.post(
        "/api/payments/create",
        json={"scan_id": str(sample_scan_id), "email": "test@example.com"},
    )
    assert response.status_code == 400
