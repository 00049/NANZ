from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Security, Response
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.models.report import Report
from app.schemas.report import ReportResponse, ReportEmailRequest
from app.schemas.common import WrappedResponse, success_response, error_response
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

@router.get("/{scan_id}", response_model=WrappedResponse[ReportResponse])
async def get_report(scan_id: UUID, payload: dict = Depends(get_current_token_payload), db: AsyncSession = Depends(get_db)):
    if payload.get("scan_id") != str(scan_id):
        return JSONResponse(status_code=403, content=error_response("Token not valid for this scan"))
        
    result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    report = result.scalars().first()
    if not report:
        return JSONResponse(status_code=404, content=error_response("Report not found"))
        
    return success_response(report)

@router.post("/{scan_id}/email", response_model=WrappedResponse[dict])
async def email_report(scan_id: UUID, body: ReportEmailRequest, payload: dict = Depends(get_current_token_payload), db: AsyncSession = Depends(get_db)):
    if payload.get("scan_id") != str(scan_id):
        return JSONResponse(status_code=403, content=error_response("Token not valid for this scan"))

    result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    report = result.scalars().first()
    if not report:
        return JSONResponse(status_code=404, content=error_response("Report not found"))

    if send_report_email:
        # Pass dict representing report data
        report_data = {
            "overall_severity": report.overall_severity,
            "risk_items": report.risk_items,
        }
        success = await send_report_email(body.email, report_data, "shieldcheck-site") # Domain could be extracted from scan
        if success:
            return success_response({"message": f"Report sent to {body.email}"})
        else:
            return JSONResponse(status_code=500, content=error_response("Failed to send email"))
    else:
        return JSONResponse(status_code=500, content=error_response("Email service unavailable"))
