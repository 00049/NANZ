from celery import Celery
import asyncio
from redis.asyncio import Redis
import logging
import multiprocessing

from app.config import settings
from app.services.scanner.orchestrator import run_full_scan

logger = logging.getLogger(__name__)

celery_app = Celery(
    "scan_tasks",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_time_limit=60,
    task_soft_time_limit=45,
    worker_concurrency=multiprocessing.cpu_count() * 2,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    broker_connection_timeout=1.0,
    broker_connection_retry=False,
    broker_connection_retry_on_startup=False
)

redis_client = Redis.from_url(settings.REDIS_URL, decode_responses=True, socket_connect_timeout=1.0, socket_timeout=1.0)

@celery_app.task(bind=True, name="run_scan", max_retries=3, acks_late=True)
def run_scan(self, scan_id: str, url: str, url_hash: str) -> None:
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
        loop.run_until_complete(run_full_scan(scan_id, url, url_hash, redis_client))
        logger.info(f"Scan task completed for scan_id: {scan_id}")
    except Exception as e:
        logger.error(f"Scan task failed for scan_id {scan_id}: {e}", exc_info=True)
        # Check if error is network/timeout related to retry
        retry_exceptions = (TimeoutError, ConnectionError, asyncio.TimeoutError)
        if isinstance(e, retry_exceptions):
            countdown = 2 ** self.request.retries * 10
            raise self.retry(exc=e, countdown=countdown)
