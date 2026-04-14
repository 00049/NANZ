import hashlib
import json
from uuid import UUID
from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from redis.asyncio import Redis

from app.db.session import get_db
from app.models.scan import Scan
from app.models.report import Report
from app.schemas.scan import ScanCreateRequest, ScanResponse, ScanStatusResponse, ScanPreviewResponse
from app.utils.url_validator import validate_scan_url
from app.config import settings
from app.main import limiter
try:
    from app.tasks.scan_tasks import run_scan
except ImportError:
    run_scan = None  # Prevent import error before tasks are created

router = APIRouter(tags=["Scans"])

# Global redis client for routers
redis_client = Redis.from_url(settings.REDIS_URL, decode_responses=True)

@router.post("", response_model=ScanResponse, status_code=202)
@limiter.limit("5/hour")
async def create_scan(request: Request, body: ScanCreateRequest, db: AsyncSession = Depends(get_db)):
    url = body.url.strip()
    is_valid, resolved_ip_or_error = validate_scan_url(url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=resolved_ip_or_error)
        
    url_hash = hashlib.sha256(url.lower().encode('utf-8')).hexdigest()
    cache_key = f"scan:url:{url_hash}"
    
    # Check cache for duplicate scan
    cached_scan_id = await redis_client.get(cache_key)
    if cached_scan_id:
        result = await db.execute(select(Scan).where(Scan.id == cached_scan_id))
        existing_scan = result.scalars().first()
        if existing_scan and existing_scan.status == "complete":
            return ScanResponse(
                scan_id=existing_scan.id,
                status="complete",
                estimated_duration_seconds=0
            )

    # Create new scan record
    domain = url.split("//")[-1].split("/")[0]
    client_ip = request.client.host if request.client else None
    
    scan = Scan(
        url=url,
        domain=domain,
        ip_address=resolved_ip_or_error,  # At this point, it's the resolved IP
        requester_ip=client_ip
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    
    # Dispatch celery task
    if run_scan:
        run_scan.delay(str(scan.id), url)
        
    return ScanResponse(
        scan_id=scan.id,
        status="pending",
        estimated_duration_seconds=45
    )


@router.get("/{scan_id}", response_model=ScanStatusResponse)
@limiter.limit("60/minute")
async def get_scan_status(request: Request, scan_id: UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Fetch progress from Redis
    progress_key = f"scan:progress:{scan_id}"
    progress_raw = await redis_client.get(progress_key)
    progress = json.loads(progress_raw) if progress_raw else {}

    response_data = {
        "scan_id": scan.id,
        "status": scan.status,
        "progress": progress
    }

    if scan.status == "complete":
        report_result = await db.execute(select(Report).where(Report.scan_id == scan_id))
        report = report_result.scalars().first()
        if report:
            response_data["overall_severity"] = report.overall_severity
            if report.risk_items and len(report.risk_items) > 0:
                response_data["preview_risk"] = report.risk_items[0]
                
    elif scan.status == "failed":
        response_data["error_message"] = scan.error_message
        
    return response_data

@router.get("/{scan_id}/preview", response_model=ScanPreviewResponse)
async def get_scan_preview(scan_id: UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan or scan.status != "complete":
        raise HTTPException(status_code=400, detail="Scan not ready or not found")
        
    report_result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    report = report_result.scalars().first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not generated")
        
    risk_item = report.risk_items[0] if report.risk_items else {}
    return ScanPreviewResponse(
        overall_severity=report.overall_severity,
        risk_item=risk_item,
        locked_risks_count=2,
        is_paid=report.is_paid
    )
