from datetime import UTC, datetime
import os
import asyncio

from fastapi import APIRouter, HTTPException

router = APIRouter()


@router.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint to verify the service is running."""
    return {
        "status": "ok",
        "version": "1.0.0",
        "timestamp": datetime.now(UTC).isoformat(),
    }


@router.get("/", tags=["System"])
async def root_redirect():
    """Root endpoint to show basic API info and reduce 404s for browsers."""
    return {
        "message": "Welcome to the ShieldCheck API. System is Operational.",
        "docs": "/docs",
        "health": "/health",
        "versions": ["v1"],
    }


@router.post("/api/admin/migrate", tags=["System"])
async def run_migrations(secret: str):
    """Trigger Alembic migrations — protected by secret key."""
    expected = os.environ.get("APP_SECRET_KEY", "")
    if not secret or secret != expected:
        raise HTTPException(status_code=403, detail="Forbidden")

    try:
        from alembic import command
        from alembic.config import Config

        def _run():
            alembic_cfg = Config("alembic.ini")
            alembic_cfg.set_main_option("script_location", "migrations")
            command.upgrade(alembic_cfg, "head")

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _run)
        return {"status": "ok", "message": "Migrations applied successfully."}
    except Exception as e:
        return {"status": "error", "message": str(e)}
