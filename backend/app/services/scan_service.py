import asyncio
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


def _is_celery_worker_alive(timeout: float = 0.8) -> bool:
    """
    Ping the Celery worker pool and return True only if at least one worker
    responds within *timeout* seconds.

    This is a synchronous, blocking call that takes at most *timeout* seconds.
    Using it before run_scan.delay() prevents tasks from silently piling up in
    Redis when no worker is running (common on Render free tier).
    """
    try:
        from app.core.celery_app import celery as celery_app
        response = celery_app.control.ping(timeout=timeout)
        return bool(response)
    except Exception as exc:
        logger.debug(f"Celery ping failed: {exc}")
        return False


async def create_new_scan(
    url: str,
    resolved_ip: str,
    client_ip: str | None,
    db: AsyncSession,
    redis_client: Redis,
    user_id=None,
    background_tasks=None,
) -> dict:
    """Create or reuse a recent completed scan and enqueue background processing.

    Dispatch strategy (in priority order):
      1. Celery worker (if one responds to ping within 0.8 s) — distributed, retryable
      2. FastAPI BackgroundTasks (if background_tasks arg provided) — clean lifecycle
      3. asyncio.create_task() — last resort, always works in a running event loop

    This guarantees scans always execute even on Render free tier where the
    Celery background process is frequently killed due to memory constraints.
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
    except (TimeoutError, ConnectionError, OSError, ValueError) as e:
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

    # ── Build the asyncio fallback coroutine (used if Celery unavailable) ──
    from app.services.scanner.orchestrator import run_full_scan

    async def _background_scan() -> None:
        async_redis = Redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=2.0,
            socket_timeout=2.0,
        )
        try:
            await run_full_scan(scan_id_str, url, async_redis)
        except Exception as exc:
            logger.error(f"Background scan {scan_id_str} failed: {exc}", exc_info=True)
        finally:
            await async_redis.aclose()

    # ── Dispatch: prefer Celery if a live worker exists ──
    # Run the ping in a thread so we don't block the async event loop.
    try:
        worker_alive = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, _is_celery_worker_alive),
            timeout=1.5,
        )
    except Exception:
        worker_alive = False

    if worker_alive:
        try:
            run_scan.delay(scan_id_str, url)
            logger.info(f"Scan {scan_id_str} enqueued via Celery (worker is alive).")
        except Exception as e:
            logger.warning(f"Celery enqueue failed despite worker ping: {e}. Falling back.")
            worker_alive = False

    if not worker_alive:
        if background_tasks is not None:
            background_tasks.add_task(_background_scan)
            logger.info(f"Scan {scan_id_str} dispatched via FastAPI BackgroundTasks (no Celery worker).")
        else:
            asyncio.create_task(_background_scan())
            logger.info(f"Scan {scan_id_str} dispatched via asyncio.create_task (no Celery worker).")

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
