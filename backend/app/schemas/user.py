from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    email: EmailStr
    name: str | None = None
    company: str | None = None


class UserCreate(UserBase):
    password: str


class UserResponse(UserBase):
    id: UUID
    role: str
    email_verified: bool
    scan_credits: int
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None = None

    class Config:
        from_attributes = True


class UserUpdate(BaseModel):
    name: str | None = None
    company: str | None = None
