import secrets
from uuid import UUID
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.db.session import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.scan import Scan
from app.models.report_access import ReportShareLink, ReportAuditLog
from app.core.report_guard import verify_report_access

router = APIRouter(tags=["Report Sharing"])

@router.post("/scans/{scan_id}/share")
async def create_share_link(
    scan_id: UUID,
    expires_in_days: int = 7,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> dict:
    """
    Generate a secure share link for a report. 
    Only the report owner or an admin can generate a link.
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    if scan.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only the report owner can create share links")
        
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days) if expires_in_days > 0 else None
    
    share_link = ReportShareLink(
        scan_id=scan_id,
        token=token,
        created_by_id=current_user.id,
        expires_at=expires_at
    )
    db.add(share_link)
    await db.commit()
    
    return {
        "status": "success",
        "token": token,
        "expires_at": expires_at.isoformat() if expires_at else None
    }

@router.get("/scans/{scan_id}/shares")
async def list_share_links(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> dict:
    """List active share links for a report."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan or (scan.user_id != current_user.id and current_user.role != "admin"):
        raise HTTPException(status_code=403, detail="Access Denied")
        
    result = await db.execute(
        select(ReportShareLink).where(ReportShareLink.scan_id == scan_id, ReportShareLink.is_revoked == False)
    )
    links = result.scalars().all()
    
    return {
        "shares": [
            {
                "id": str(link.id),
                "token_prefix": link.token[:8] + "...",
                "created_at": link.created_at.isoformat(),
                "expires_at": link.expires_at.isoformat() if link.expires_at else None
            }
            for link in links
        ]
    }

@router.delete("/scans/{scan_id}/shares/{share_id}")
async def revoke_share_link(
    scan_id: UUID,
    share_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> dict:
    """Revoke a specific share link."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan or (scan.user_id != current_user.id and current_user.role != "admin"):
        raise HTTPException(status_code=403, detail="Access Denied")
        
    result = await db.execute(select(ReportShareLink).where(ReportShareLink.id == share_id))
    link = result.scalars().first()
    if not link:
        raise HTTPException(status_code=404, detail="Share link not found")
        
    link.is_revoked = True
    await db.commit()
    
    return {"status": "success", "message": "Link revoked successfully"}

@router.get("/scans/{scan_id}/audit-logs")
async def view_audit_logs(
    scan_id: UUID,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> dict:
    """View access logs for a report."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan or (scan.user_id != current_user.id and current_user.role != "admin"):
        raise HTTPException(status_code=403, detail="Access Denied")
        
    result = await db.execute(
        select(ReportAuditLog)
        .where(ReportAuditLog.scan_id == scan_id)
        .order_by(ReportAuditLog.timestamp.desc())
        .limit(limit)
    )
    logs = result.scalars().all()
    
    return {
        "logs": [
            {
                "timestamp": log.timestamp.isoformat(),
                "viewer_ip": log.viewer_ip,
                "action": log.action,
                "via_share_link": bool(log.share_token_used)
            }
            for log in logs
        ]
    }
