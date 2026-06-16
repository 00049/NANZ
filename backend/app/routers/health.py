from datetime import UTC, datetime

from fastapi import APIRouter

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
