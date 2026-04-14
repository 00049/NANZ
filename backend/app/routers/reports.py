from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.models.report import Report
from app.schemas.report import ReportResponse, ReportEmailRequest
from app.utils.auth import verify_report_token
try:
    from app.services.email_service import send_report_email
except ImportError:
    send_report_email = None

router = APIRouter(tags=["Reports"])
security = HTTPBearer()

async def get_current_token_payload(credentials: HTTPAuthorizationCredentials = Security(security)):
    payload = verify_report_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token")
    return payload

@router.get("/{scan_id}", response_model=ReportResponse)
async def get_report(scan_id: UUID, payload: dict = Depends(get_current_token_payload), db: AsyncSession = Depends(get_db)):
    if payload.get("scan_id") != str(scan_id):
        raise HTTPException(status_code=403, detail="Token not valid for this scan")
        
    result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    report = result.scalars().first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
        
    return report

@router.post("/{scan_id}/email")
async def email_report(scan_id: UUID, body: ReportEmailRequest, payload: dict = Depends(get_current_token_payload), db: AsyncSession = Depends(get_db)):
    if payload.get("scan_id") != str(scan_id):
        raise HTTPException(status_code=403, detail="Token not valid for this scan")

    result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    report = result.scalars().first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if send_report_email:
        # Pass dict representing report data
        report_data = {
            "overall_severity": report.overall_severity,
            "risk_items": report.risk_items,
        }
        success = await send_report_email(body.email, report_data, "shieldcheck-site") # Domain could be extracted from scan
        if success:
            return {"message": f"Report sent to {body.email}"}
        else:
            raise HTTPException(status_code=500, detail="Failed to send email")
    else:
        raise HTTPException(status_code=500, detail="Email service unavailable")
