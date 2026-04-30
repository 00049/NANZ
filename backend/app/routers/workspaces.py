from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID

from app.db.session import get_db
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMember
from app.schemas.workspace import WorkspaceResponse, WorkspaceMemberResponse, WorkspaceMemberCreate
from app.core.security import get_current_user

router = APIRouter(tags=["Workspaces"])

@router.get("/my", response_model=List[WorkspaceResponse])
async def get_my_workspaces(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all workspaces the current user is a member of."""
    m_result = await db.execute(select(WorkspaceMember).where(WorkspaceMember.user_id == current_user.id))
    memberships = m_result.scalars().all()
    workspace_ids = [m.workspace_id for m in memberships]
    
    if not workspace_ids:
        return []
        
    w_result = await db.execute(select(Workspace).where(Workspace.id.in_(workspace_ids)))
    workspaces = w_result.scalars().all()
    return workspaces

@router.get("/{workspace_id}/members", response_model=List[WorkspaceMemberResponse])
async def get_workspace_members(
    workspace_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get members of a specific workspace."""
    # Check if user is in workspace
    m_result = await db.execute(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == current_user.id
        )
    )
    membership = m_result.scalars().first()
    
    if not membership:
        raise HTTPException(status_code=403, detail="Not a member of this workspace")
        
    all_m_result = await db.execute(select(WorkspaceMember).where(WorkspaceMember.workspace_id == workspace_id))
    members = all_m_result.scalars().all()
    return members

@router.post("/{workspace_id}/invite", response_model=WorkspaceMemberResponse)
async def invite_member(
    workspace_id: UUID,
    invite_in: WorkspaceMemberCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Invite a user to the workspace."""
    # Check if current user is owner/admin
    m_result = await db.execute(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == current_user.id
        )
    )
    membership = m_result.scalars().first()
    
    if not membership or membership.role not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions to invite members")
        
    u_result = await db.execute(select(User).where(User.email == invite_in.email))
    target_user = u_result.scalars().first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found with this email. They must register first.")
        
    e_result = await db.execute(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == target_user.id
        )
    )
    existing = e_result.scalars().first()
    
    if existing:
        raise HTTPException(status_code=400, detail="User is already in the workspace")
        
    new_member = WorkspaceMember(
        workspace_id=workspace_id,
        user_id=target_user.id,
        role=invite_in.role,
        status="active"
    )
    db.add(new_member)
    await db.commit()
    await db.refresh(new_member)
    return new_member
