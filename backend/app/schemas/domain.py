from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, constr


class DomainBase(BaseModel):
    domain_name: constr(min_length=3, max_length=255)
    monitoring_frequency: str | None = "weekly"


class DomainCreate(DomainBase):
    pass


class DomainResponse(DomainBase):
    id: UUID
    user_id: UUID
    status: str
    is_verified: bool
    last_scan_id: UUID | None = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
