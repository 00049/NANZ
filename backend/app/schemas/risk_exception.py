from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, Field

class RiskExceptionBase(BaseModel):
    finding_key: str = Field(..., description="The unique key of the finding, e.g., 'ssl_heartbleed'")
    status: str = Field(..., description="Exception status: 'accepted', 'mitigated', or 'false_positive'")
    justification: str = Field(..., description="Reason for the exception")
    owner: str = Field(..., description="Person or team owning this risk")
    expires_at: Optional[datetime] = Field(None, description="When this exception should expire")

class RiskExceptionCreate(RiskExceptionBase):
    pass

class RiskExceptionUpdate(BaseModel):
    status: Optional[str] = None
    justification: Optional[str] = None
    owner: Optional[str] = None
    expires_at: Optional[datetime] = None

class RiskExceptionResponse(RiskExceptionBase):
    id: UUID
    domain_id: UUID
    created_at: datetime
    updated_at: datetime
    created_by: Optional[UUID] = None

    class Config:
        from_attributes = True

class RiskExceptionHistoryResponse(BaseModel):
    id: UUID
    exception_id: UUID
    action: str
    previous_status: Optional[str] = None
    new_status: str
    actor_id: Optional[UUID] = None
    timestamp: datetime
    notes: Optional[str] = None

    class Config:
        from_attributes = True
