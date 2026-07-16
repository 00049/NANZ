#!/bin/bash

# Run migrations (non-fatal — tables may already exist)
echo "Running database migrations..."
alembic upgrade head && echo "Migrations OK" || echo "WARNING: Migrations failed (tables may already be up to date)"

# Start Celery worker in the background (non-fatal if Redis is unavailable)
if [ -n "$REDIS_URL" ] && [ "$REDIS_URL" != "redis://localhost:6379" ]; then
    echo "Starting Celery worker..."
    celery -A app.core.celery_app worker --loglevel=info -c 2 &
    echo "Celery started."
else
    echo "WARNING: REDIS_URL not set or is localhost — skipping Celery worker."
fi

# Start Uvicorn in the foreground
uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
