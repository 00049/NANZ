import ssl

from celery import Celery

from app.config import settings

# Override DNS resolver to use reliable public nameservers
# (system DNS often has broken IPv6 nameservers that cause 2s timeouts)
try:
    import dns.asyncresolver
    import dns.resolver

    _public_resolver = dns.resolver.Resolver(configure=False)
    _public_resolver.nameservers = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
    _public_resolver.lifetime = 5.0
    _public_resolver.timeout = 3.0
    dns.resolver.default_resolver = _public_resolver

    _public_async_resolver = dns.asyncresolver.Resolver(configure=False)
    _public_async_resolver.nameservers = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
    _public_async_resolver.lifetime = 5.0
    _public_async_resolver.timeout = 3.0
    dns.asyncresolver.default_resolver = _public_async_resolver
except Exception:
    pass

# For Upstash rediss:// URLs, Celery requires ssl_cert_reqs=CERT_NONE
redis_url = settings.REDIS_URL
if (
    redis_url
    and redis_url.startswith("rediss://")
    and "ssl_cert_reqs=" not in redis_url
):
    redis_url += (
        "?ssl_cert_reqs=CERT_NONE"
        if "?" not in redis_url
        else "&ssl_cert_reqs=CERT_NONE"
    )

celery = Celery(
    "shieldcheck", broker=redis_url, backend=redis_url, include=["app.tasks.scan_tasks"]
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    worker_send_task_events=True,  # Heartbeat monitoring
    task_acks_late=True,  # Retry if worker crashes mid-task
    worker_prefetch_multiplier=1,  # Fair dispatch
    task_default_queue="celery",
    task_routes={"app.tasks.scan_tasks.process_dead_letter": {"queue": "celery_dlq"}},
    redis_backend_use_ssl=(
        {"ssl_cert_reqs": ssl.CERT_NONE} if redis_url.startswith("rediss://") else None
    ),
    broker_use_ssl=(
        {"ssl_cert_reqs": ssl.CERT_NONE} if redis_url.startswith("rediss://") else None
    ),
)
