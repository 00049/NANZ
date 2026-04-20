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
        "estimated_duration_seconds": 90  # Increased for expanded checks
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
            response_data["overall_score"] = report.overall_score
            response_data["total_findings"] = report.total_findings
            if report.risk_items and len(report.risk_items) > 0:
                response_data["preview_risk"] = report.risk_items[0]

    elif scan.status == "failed":
        response_data["error_message"] = scan.error_message

    return response_data


async def get_scan_preview_data(scan_id: UUID, db: AsyncSession) -> dict:
    """
    Return the free preview for a completed scan.

    FREE gate shows:
    - Overall severity badge
    - Overall security score (0-100)
    - Top 3 risk items (title + business_impact only)
    - Count breakdown
    - Executive summary (2 sentences only)
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan or scan.status != "complete":
        return {"error": "Scan not ready or not found"}

    report_result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    report = report_result.scalars().first()

    if not report:
        return {"error": "Report not generated"}

    # Free preview: top 3 risks with limited fields
    top_risks = []
    if report.risk_items:
        for item in report.risk_items[:3]:
            top_risks.append({
                "title": item.get("title", ""),
                "severity": item.get("severity", ""),
                "business_impact": item.get("business_impact", ""),
            })

    # Truncate executive summary to ~2 sentences for free
    exec_summary = report.executive_summary or ""
    sentences = exec_summary.split(". ")
    free_summary = ". ".join(sentences[:2]) + "." if len(sentences) > 1 else exec_summary

    total_findings = report.total_findings or 0
    locked_count = max(0, total_findings - 3)

    return {
        "scan_id": str(scan.id),
        "domain": scan.domain,
        "overall_severity": report.overall_severity,
        "overall_score": report.overall_score or 0,
        "executive_summary": free_summary,
        "top_risks": top_risks,
        "critical_count": report.critical_count or 0,
        "high_count": report.high_count or 0,
        "medium_count": report.medium_count or 0,
        "low_count": report.low_count or 0,
        "info_count": report.info_count or 0,
        "total_findings": total_findings,
        "locked_risks_count": locked_count,
        "is_paid": report.is_paid,
    }
