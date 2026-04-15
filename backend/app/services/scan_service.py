import hashlib
import json
import logging
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from redis.asyncio import Redis
from urllib.parse import urlparse
from starlette.concurrency import run_in_threadpool

from app.models.scan import Scan
from app.models.report import Report
from app.tasks.scan_tasks import run_scan

logger = logging.getLogger(__name__)

async def create_new_scan(url: str, resolved_ip: str, client_ip: str | None, db: AsyncSession, redis_client: Redis) -> dict:
    url_hash = hashlib.sha256(url.lower().encode('utf-8')).hexdigest()
    cache_key = f"scan:url:{url_hash}"
    lock_key = f"scan:lock:{url_hash}"
    
    try:
        # Wrap redis cache and locking in a strict async timeout to enforce fail-fast behavior when database is offline
        import asyncio
        async def check_redis():
            cached_scan_id = await redis_client.get(cache_key)
            if cached_scan_id:
                result = await db.execute(select(Scan).where(Scan.id == cached_scan_id))
                existing = result.scalars().first()
                if existing and existing.status == "complete":
                    return True, existing.id
            lock_acquired = await redis_client.set(lock_key, "1", nx=True, ex=60)
            return False, lock_acquired

        cached, result_val = await asyncio.wait_for(check_redis(), timeout=1.0)
        
        if cached:
            return {
                "scan_id": result_val,
                "status": "complete",
                "estimated_duration_seconds": 0
            }
        elif not result_val:
            return {"error": "Scan already in progress for this domain"}
            
    except Exception as e:
        logger.error(f"Redis error during cache/lock check: {e}")
        # Proceed with scan even if Redis is down

    # Create DB Record
    parsed = urlparse(url)
    domain = parsed.hostname
    
    scan = Scan(
        url=url,
        domain=domain,
        ip_address=resolved_ip,
        requester_ip=client_ip
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    
    try:
        # Dispatch Celery Task
        # Kombu hangs aggressively if broker is entirely dead; we MUST force an async timeout to prevent API freezes.
        import asyncio
        await asyncio.wait_for(
            run_in_threadpool(run_scan.apply_async, args=[str(scan.id), url, url_hash], expires=120, ignore_result=True),
            timeout=2.0
        )
    except Exception as e:
        logger.error(f"Failed to enqueue scan task to Redis: {e}")
        scan.status = "failed"
        scan.error_message = "Message queue unavailable"
        await db.commit()
        return {"error": "Message queue unavailable, please try later"}
        
    return {
        "scan_id": scan.id,
        "status": "pending",
        "estimated_duration_seconds": 60
    }

async def get_scan_status_data(scan_id: UUID, db: AsyncSession, redis_client: Redis) -> dict:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        return {"error": "Scan not found"}

    try:
        progress_key = f"scan:progress:{scan_id}"
        progress_raw = await redis_client.get(progress_key)
        progress = json.loads(progress_raw) if progress_raw else {}
    except Exception as e:
        logger.error(f"Redis error getting progress: {e}")
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
