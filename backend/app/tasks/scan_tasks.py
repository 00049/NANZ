import asyncio
import logging

from redis.asyncio import Redis

from app.config import settings
from app.core.celery_app import celery
from app.services.scanner.orchestrator import run_full_scan

logger = logging.getLogger(__name__)

celery.conf.update(
    broker_url=settings.REDIS_URL,
    result_backend=settings.REDIS_URL,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_time_limit=300,  # Hard limit: 5 minutes (expanded checks take longer)
    task_soft_time_limit=240,  # Soft limit: 4 minutes
)

redis_client = Redis.from_url(
    settings.REDIS_URL,
    decode_responses=True,
    socket_connect_timeout=1.0,
    socket_timeout=1.0,
)


@celery.task(name="app.tasks.scan_tasks.process_dead_letter")
def process_dead_letter(scan_id: str, url: str, error_msg: str) -> None:
    """
    Dead-Letter Queue (DLQ) task for persistently failing scans.
    Records the final failure state to the database.
    """
    logger.error(
        f"[DLQ] Processing dead letter for scan {scan_id} ({url}): {error_msg}"
    )
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    async def _mark_failed():
        from sqlalchemy import select

        from app.db.session import async_session_maker
        from app.models.scan import Scan

        async with async_session_maker() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalars().first()
            if scan:
                scan.status = "failed"
                scan.error_message = f"Max retries exceeded: {error_msg}"
                await db.commit()

    loop.run_until_complete(_mark_failed())


@celery.task(
    bind=True,
    name="run_scan",
    max_retries=3,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
)
def run_scan(self, scan_id: str, url: str) -> None:
    """
    Celery task entry point to run a full orchestrated scan asynchronously.
    Expanded to support 10 check modules across 8 security domains.
    """
    logger.info(
        f"Starting expanded scan task for scan_id: {scan_id}, url: {url} (Attempt {self.request.retries + 1}/{self.max_retries + 1})"
    )

    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(run_full_scan(scan_id, url, redis_client))
        logger.info(f"Scan task completed for scan_id: {scan_id}")
    except Exception as e:
        logger.error(f"Scan task failed for scan_id {scan_id}: {e}", exc_info=True)
        if self.request.retries >= self.max_retries:
            logger.error(f"Max retries reached for scan_id {scan_id}. Routing to DLQ.")
            process_dead_letter.apply_async(
                args=[scan_id, url, str(e)], queue="celery_dlq"
            )
        raise e


@celery.task(name="check_scheduled_scans")
def check_scheduled_scans_task() -> None:
    """Periodic task to check and run due scheduled rescans."""
    logger.info("Checking for scheduled rescans...")

    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    from app.db.session import async_session_maker
    from app.services.scheduler import execute_scheduled_scan, get_due_schedules

    async def _process_schedules():
        async with async_session_maker() as db:
            schedules = await get_due_schedules(db)
            for schedule in schedules:
                try:
                    await execute_scheduled_scan(schedule, db, redis_client)
                except Exception as e:
                    logger.error(
                        f"Failed to process schedule {schedule.id}: {e}", exc_info=True
                    )

    loop.run_until_complete(_process_schedules())


celery.conf.beat_schedule = {
    "run-scheduled-scans-every-hour": {
        "task": "check_scheduled_scans",
        "schedule": 3600.0,  # every 1 hour
    },
}
