from uuid import UUID
from datetime import datetime, timezone
from fastapi import Request, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import Optional

from app.db.session import get_db
from app.core.security import get_current_user_optional
from app.models.user import User
from app.models.scan import Scan
from app.models.report_access import ReportShareLink, ReportAuditLog
from app.models.workspace import WorkspaceMember

async def verify_report_access(
    scan_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
) -> Scan:
    """
    Enterprise authorization guard for report access.
    Validates owner, workspace members, admins, and active share links.
    Also logs the access attempt.
    """
    # Check if a share token was provided in query params
    share_token = request.query_params.get("token")
    
    # 1. Fetch the Scan
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    has_access = False
    access_method = None

    # 2. Check Share Token
    if share_token:
        token_result = await db.execute(
            select(ReportShareLink).where(
                ReportShareLink.scan_id == scan_id,
                ReportShareLink.token == share_token,
                ReportShareLink.is_revoked == False
            )
        )
        share_link = token_result.scalars().first()
        if share_link:
            if share_link.expires_at and share_link.expires_at < datetime.now(timezone.utc):
                raise HTTPException(status_code=403, detail="Share link has expired")
            has_access = True
            access_method = "share_link"
        else:
            raise HTTPException(status_code=403, detail="Invalid or revoked share link")

    # 3. Check User Access (if not already granted via share token)
    if not has_access and current_user:
        if current_user.role == "admin":
            has_access = True
            access_method = "admin"
        elif scan.user_id == current_user.id:
            has_access = True
            access_method = "owner"
        elif scan.workspace_id:
            # Check if user is in the scan's workspace
            member_result = await db.execute(
                select(WorkspaceMember).where(
                    WorkspaceMember.workspace_id == scan.workspace_id,
                    WorkspaceMember.user_id == current_user.id,
                    WorkspaceMember.status == "active"
                )
            )
            if member_result.scalars().first():
                has_access = True
                access_method = "workspace_member"
        elif scan.user_id:
            # Implicit workspace sharing: User is in the same workspace as the scan owner
            member_result = await db.execute(
                select(WorkspaceMember.workspace_id).where(
                    WorkspaceMember.user_id == current_user.id,
                    WorkspaceMember.status == "active"
                )
            )
            user_workspaces = member_result.scalars().all()
            if user_workspaces:
                owner_member_result = await db.execute(
                    select(WorkspaceMember).where(
                        WorkspaceMember.user_id == scan.user_id,
                        WorkspaceMember.workspace_id.in_(user_workspaces),
                        WorkspaceMember.status == "active"
                    )
                )
                if owner_member_result.scalars().first():
                    has_access = True
                    access_method = "implicit_workspace_member"
                    
    print(f"DEBUG GUARD: scan_id={scan_id}, scan_type='{scan.scan_type}', current_user={current_user.id if current_user else None}, has_access={has_access}")
    
    # Allow public access to free scans (they will be gated by 402 in get_report)
    if not has_access and scan.scan_type == "free":
        print("DEBUG GUARD: Granting free scan access")
        has_access = True
        access_method = "free_scan_public"

    if not has_access:
        # User is not authenticated and no valid share link provided, OR
        # User is authenticated but has no relation to the scan.
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")
        raise HTTPException(status_code=403, detail="Access Denied. You do not have permission to view this report.")

    # 4. Create Audit Log
    client_ip = request.client.host if request.client else None
    # For privacy, respect proxy headers if trusted, but fallback to client.host
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    audit_log = ReportAuditLog(
        scan_id=scan_id,
        viewer_user_id=current_user.id if current_user else None,
        viewer_ip=client_ip,
        action="view",
        share_token_used=share_token if access_method == "share_link" else None
    )
    db.add(audit_log)
    await db.commit()

    return scan
