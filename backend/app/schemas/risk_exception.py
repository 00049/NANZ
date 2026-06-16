from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class RiskExceptionBase(BaseModel):
    finding_key: str = Field(
        ..., description="The unique key of the finding, e.g., 'ssl_heartbleed'"
    )
    status: str = Field(
        ...,
        description="Exception status: 'accepted', 'mitigated', or 'false_positive'",
    )
    justification: str = Field(..., description="Reason for the exception")
    owner: str = Field(..., description="Person or team owning this risk")
    expires_at: datetime | None = Field(
        None, description="When this exception should expire"
    )


class RiskExceptionCreate(RiskExceptionBase):
    pass


class RiskExceptionUpdate(BaseModel):
    status: str | None = None
    justification: str | None = None
    owner: str | None = None
    expires_at: datetime | None = None


class RiskExceptionResponse(RiskExceptionBase):
    id: UUID
    domain_id: UUID
    created_at: datetime
    updated_at: datetime
    created_by: UUID | None = None

    class Config:
        from_attributes = True


class RiskExceptionHistoryResponse(BaseModel):
    id: UUID
    exception_id: UUID
    action: str
    previous_status: str | None = None
    new_status: str
    actor_id: UUID | None = None
    timestamp: datetime
    notes: str | None = None

    class Config:
        from_attributes = True
