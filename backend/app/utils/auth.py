from datetime import UTC, datetime, timedelta

from jose import JWTError, jwt

from app.config import settings


def create_report_token(user_id: str, scan_id: str) -> str:
    """Creates a JWT token for accessing a paid report."""
    to_encode = {
        "sub": str(user_id),
        "scan_id": str(scan_id),
        "type": "report_access",
        "exp": datetime.now(UTC) + timedelta(hours=24),
    }
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET, algorithm="HS256")
    return encoded_jwt


def verify_report_token(token: str) -> dict | None:
    """Verifies a report access JWT token."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
        return payload
    except JWTError:
        return None
