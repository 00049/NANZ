#!/bin/bash
# ─────────────────────────────────────────────────────────────────
#  NAANZ / ShieldCheck — Local Dev Startup Script
#  Ensures PostgreSQL, Redis, Celery, and Uvicorn are all running.
# ─────────────────────────────────────────────────────────────────

set -e
BACKEND_DIR="$(cd "$(dirname "$0")" && pwd)"
PG_DATA="/opt/homebrew/var/postgresql@16"
PG_LOG="/opt/homebrew/var/log/postgresql@16.log"

echo "🔍 Checking PostgreSQL..."

# Fix stale postmaster.pid if postgres isn't actually running
if [ -f "$PG_DATA/postmaster.pid" ]; then
  LOCK_PID=$(head -1 "$PG_DATA/postmaster.pid")
  # Check if that PID is actually a postgres process
  if ! ps -p "$LOCK_PID" -o comm= 2>/dev/null | grep -q "postgres"; then
    echo "⚠️  Stale postmaster.pid found (PID $LOCK_PID is not postgres). Removing..."
    rm -f "$PG_DATA/postmaster.pid"
    brew services stop postgresql@16 2>/dev/null || true
  fi
fi

# Start/restart PostgreSQL if not accepting connections
if ! pg_isready -h localhost -p 5432 -q 2>/dev/null; then
  echo "🚀 Starting PostgreSQL@16..."
  brew services start postgresql@16
  # Wait up to 15s for it to come up
  for i in $(seq 1 15); do
    sleep 1
    if pg_isready -h localhost -p 5432 -q 2>/dev/null; then
      echo "✅ PostgreSQL is ready."
      break
    fi
    if [ "$i" -eq 15 ]; then
      echo "❌ PostgreSQL failed to start. Check: $PG_LOG"
      exit 1
    fi
  done
else
  echo "✅ PostgreSQL already running."
fi

echo "🔍 Checking Redis..."
if ! redis-cli ping -q 2>/dev/null | grep -q "PONG"; then
  echo "🚀 Starting Redis..."
  brew services start redis
  sleep 2
fi
echo "✅ Redis is ready."

# Activate venv
cd "$BACKEND_DIR"
source venv/bin/activate

echo "📦 Ensuring DB is migrated..."
alembic upgrade head && echo "✅ Migrations OK" || echo "⚠️  Migration warning (tables may already exist)"

echo "🌿 Starting Celery worker..."
pkill -f "celery.*shieldcheck" 2>/dev/null || true
sleep 1
celery -A app.core.celery_app worker --loglevel=info -c 2 \
  --logfile="$BACKEND_DIR/celery_dev.log" &
CELERY_PID=$!
echo "✅ Celery started (PID $CELERY_PID)"

echo "🚀 Starting Uvicorn (FastAPI)..."
uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --reload \
  --log-level info
