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
    task_time_limit=120,
    task_soft_time_limit=90,
)

redis_client = Redis.from_url(settings.REDIS_URL, decode_responses=True, socket_connect_timeout=1.0, socket_timeout=1.0)


@celery.task(bind=True, name="run_scan", max_retries=0)
def run_scan(self, scan_id: str, url: str) -> None:
    """
    Celery task entry point to run a full orchestrated scan asynchronously.
    """
    logger.info(f"Starting scan task for scan_id: {scan_id}, url: {url}")
    
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
