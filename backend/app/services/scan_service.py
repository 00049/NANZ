import asyncio
import hashlib
import json
import logging
import ssl
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


async def create_new_scan(
    url: str,
    resolved_ip: str,
    client_ip: str | None,
    db: AsyncSession,
    redis_client: Redis,
    user_id=None,
    background_tasks=None,
) -> dict:
    """Create a scan record and dispatch the scanner.

    Dispatch strategy:
      - Primary: FastAPI BackgroundTasks (asyncio, always works on Render free tier)
      - Bonus: also try Celery.delay() so a worker can pick it up if one exists
        (duplicate-safe because run_full_scan checks status != 'pending' guard)

    The asyncio path is ALWAYS used — Celery is attempted as a bonus only.
    """
    url_hash = hashlib.sha256(url.lower().encode("utf-8")).hexdigest()
    cache_key = f"scan:url:{url_hash}"

    # ── Cache check ──
    try:
        cached_scan_id = await asyncio.wait_for(redis_client.get(cache_key), timeout=1.0)
        if cached_scan_id:
            result = await db.execute(select(Scan).where(Scan.id == cached_scan_id))
            existing = result.scalars().first()
            if existing and existing.status == "complete":
                return {
                    "scan_id": existing.id,
                    "status": "complete",
                    "estimated_duration_seconds": 0,
                }
    except Exception as e:
        logger.warning(f"Redis cache check failed: {e}")

    # ── Create scan record ──
    parsed = urlparse(url)
    domain = parsed.hostname

    scan = Scan(
        url=url,
        domain=domain,
        ip_address=resolved_ip,
        requester_ip=client_ip,
        user_id=user_id,
    )
    try:
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
    except SQLAlchemyError as e:
        logger.error(f"Database error creating scan record: {e}", exc_info=True)
        await db.rollback()
        return {"error": "Database temporarily unavailable"}

    scan_id_str = str(scan.id)

    # ── Build the asyncio background coroutine ──
    from app.services.scanner.orchestrator import run_full_scan

    async def _run_scan_async() -> None:
        """Run the full scan in FastAPI's asyncio event loop."""
        # Build a redis client for the orchestrator with SSL support
        redis_url = settings.REDIS_URL
        ssl_ctx = None
        if redis_url and redis_url.startswith("rediss://"):
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        async_redis = Redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=3.0,
            socket_timeout=5.0,
            ssl_cert_reqs=None if ssl_ctx else None,
        )
        try:
            logger.info(f"[BackgroundTask] Starting scan {scan_id_str} for {url}")
            await run_full_scan(scan_id_str, url, async_redis)
            logger.info(f"[BackgroundTask] Scan {scan_id_str} completed.")
        except Exception as exc:
            logger.error(f"[BackgroundTask] Scan {scan_id_str} failed: {exc}", exc_info=True)
        finally:
            await async_redis.aclose()

    # ── PRIMARY: Always dispatch via asyncio ──
    if background_tasks is not None:
        background_tasks.add_task(_run_scan_async)
        logger.info(f"Scan {scan_id_str} dispatched via FastAPI BackgroundTasks.")
    else:
        # Fallback if no BackgroundTasks available (shouldn't happen with the router fix)
        asyncio.create_task(_run_scan_async())
        logger.info(f"Scan {scan_id_str} dispatched via asyncio.create_task.")

    # ── BONUS: Also try Celery (no-op if worker not running) ──
    try:
        run_scan.delay(scan_id_str, url)
        logger.info(f"Scan {scan_id_str} also enqueued in Celery queue (bonus).")
    except Exception as e:
        logger.debug(f"Celery enqueue skipped: {e}")

    return {
        "scan_id": scan.id,
        "status": "pending",
        "estimated_duration_seconds": 90,
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
        logger.warning(f"Redis error for scan_id={scan_id}: {e}")
        progress = {}

    response_data = {
        "scan_id": scan.id,
        "status": scan.status,
        "progress": progress,
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

    top_risks = []
    if report.risk_items:
        for item in report.risk_items[:3]:
            top_risks.append(
                {
                    "title": item.get("title", ""),
                    "severity": item.get("severity", ""),
                    "business_impact": item.get("business_impact", ""),
                }
            )

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
