from pydantic import BaseModel, ConfigDict, EmailStr, field_validator
from typing import Literal, Optional, List
from uuid import UUID
from datetime import datetime

class RiskItem(BaseModel):
    """Plain-English risk item returned to users."""

    title: str
    severity: Literal["RED", "AMBER", "GREEN"]
    business_impact: str
    fix_action: str
    confidence: Literal["HIGH", "MEDIUM", "LOW"]

    @field_validator("title")
    def title_not_too_long(cls, v: str) -> str:
        """Validate title length for business-readable report cards."""
        if len(v.split()) > 12:
            raise ValueError("Title too long")
        return v

    model_config = ConfigDict(from_attributes=True)

class ReportEmailRequest(BaseModel):
    """Request body for emailing a paid report."""

    email: EmailStr

    model_config = ConfigDict(from_attributes=True)

class ReportResponse(BaseModel):
    """Full paid report response."""

    id: UUID
    scan_id: UUID
    overall_severity: str
    risk_items: List[RiskItem]
    ai_summary: Optional[str] = None
    checks_run: dict
    ssl_score: Optional[int] = None
    header_score: Optional[int] = None
    is_paid: bool
    generated_at: datetime

    model_config = ConfigDict(from_attributes=True)
