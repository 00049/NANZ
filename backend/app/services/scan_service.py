import hashlib
import json
import logging
from uuid import UUID
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from redis.asyncio import Redis
from urllib.parse import urlparse

from app.models import Report, Scan
from app.config import settings
from app.tasks.scan_tasks import run_scan

logger = logging.getLogger(__name__)


async def create_new_scan(url: str, resolved_ip: str, client_ip: str | None, db: AsyncSession, redis_client: Redis) -> dict:
    """Create or reuse a recent completed scan and enqueue background processing."""
    url_hash = hashlib.sha256(url.lower().encode('utf-8')).hexdigest()
    cache_key = f"scan:url:{url_hash}"

    try:
        import asyncio
        cached_scan_id = await asyncio.wait_for(redis_client.get(cache_key), timeout=1.0)
        if cached_scan_id:
            result = await db.execute(select(Scan).where(Scan.id == cached_scan_id))
            existing = result.scalars().first()
            if existing and existing.status == "complete":
                return {
                    "scan_id": existing.id,
                    "status": "complete",
                    "estimated_duration_seconds": 0
                }
    except (TimeoutError, ConnectionError, OSError, ValueError) as e:
        logger.error(f"Redis cache check failed before scan creation: {e}", exc_info=True)

    parsed = urlparse(url)
    domain = parsed.hostname

    scan = Scan(
        url=url,
        domain=domain,
        ip_address=resolved_ip,
        requester_ip=client_ip
    )
    try:
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
    except SQLAlchemyError as e:
        logger.error(f"Database error creating scan record: {e}", exc_info=True)
        await db.rollback()
        return {"error": "Database temporarily unavailable"}

    try:
        run_scan.delay(str(scan.id), url)
    except (ConnectionError, TimeoutError, OSError, RuntimeError) as e:
        logger.error(f"Failed to enqueue scan_id={scan.id}; scan remains pending: {e}", exc_info=True)

    return {
        "scan_id": scan.id,
        "status": "pending",
        "estimated_duration_seconds": 45
    }


async def get_scan_status_data(scan_id: UUID, db: AsyncSession, redis_client: Redis) -> dict:
    """Return scan status, progress metadata, and preview data when complete."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        return {"error": "Scan not found"}

    try:
        progress_raw = await redis_client.get(f"scan:progress:{scan_id}")
        progress = json.loads(progress_raw) if progress_raw else {}
    except Exception as e:
        logger.error(f"Redis error retrieving scan_id={scan_id} progress: {e}", exc_info=True)
        progress = {}

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


async def get_scan_preview_data(scan_id: UUID, db: AsyncSession) -> dict:
    """Return the unlocked free preview for a completed scan."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan or scan.status != "complete":
        return {"error": "Scan not ready or not found"}
        
    report_result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    report = report_result.scalars().first()
    
    if not report:
        return {"error": "Report not generated"}
        
    risk_item = report.risk_items[0] if report.risk_items else {}
    return {
        "overall_severity": report.overall_severity,
        "risk_item": risk_item,
        "locked_risks_count": 2,
        "is_paid": report.is_paid
    }
