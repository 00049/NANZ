import ssl
from celery import Celery
from app.config import settings

# For Upstash rediss:// URLs, Celery requires ssl_cert_reqs=CERT_NONE
redis_url = settings.REDIS_URL
if redis_url and redis_url.startswith("rediss://") and "ssl_cert_reqs=" not in redis_url:
    redis_url += "?ssl_cert_reqs=CERT_NONE" if "?" not in redis_url else "&ssl_cert_reqs=CERT_NONE"

celery = Celery(
    "shieldcheck",
    broker=redis_url,
    backend=redis_url,
    include=["app.tasks.scan_tasks"]
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    redis_backend_use_ssl={"ssl_cert_reqs": ssl.CERT_NONE} if redis_url.startswith("rediss://") else None,
    broker_use_ssl={"ssl_cert_reqs": ssl.CERT_NONE} if redis_url.startswith("rediss://") else None
)