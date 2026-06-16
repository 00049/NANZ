from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from .user import UserResponse


class WorkspaceBase(BaseModel):
    name: str


class WorkspaceResponse(WorkspaceBase):
    id: UUID
    created_by_id: UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class WorkspaceMemberBase(BaseModel):
    role: str
    status: str


class WorkspaceMemberCreate(BaseModel):
    email: str
    role: str


class WorkspaceMemberResponse(WorkspaceMemberBase):
    id: UUID
    workspace_id: UUID
    user_id: UUID
    user: UserResponse | None = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
