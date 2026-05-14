#!/bin/bash
set -e

# Run migrations
alembic upgrade head

# Start Celery worker in the background
celery -A app.core.celery_app worker --loglevel=info -c 2 &

# Start Uvicorn in the foreground
uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
