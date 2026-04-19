from uuid import UUID
from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

from app.db.session import get_db
from app.schemas.scan import ScanCreateRequest
from app.utils.url_validator import validate_scan_url
from app.config import settings
from app.main import limiter
from app.services.scan_service import create_new_scan, get_scan_status_data, get_scan_preview_data

router = APIRouter(tags=["Scans"])

redis_client = Redis.from_url(settings.REDIS_URL, decode_responses=True, socket_connect_timeout=1.0, socket_timeout=1.0)


@router.post("", status_code=202)
@limiter.limit(f"{settings.MAX_SCANS_PER_IP_PER_HOUR}/hour")
async def create_scan(request: Request, body: ScanCreateRequest, db: AsyncSession = Depends(get_db)) -> dict:
    """Create a scan request and dispatch the passive scanner task."""
    url = body.url.strip()
    if not url:
        raise HTTPException(status_code=422, detail="URL cannot be empty")

    is_valid, resolved_ip_or_error = validate_scan_url(url)
    if not is_valid:
        status_code = 422 if "http://" in resolved_ip_or_error or "https://" in resolved_ip_or_error else 400
        raise HTTPException(status_code=status_code, detail=resolved_ip_or_error)

    client_ip = request.client.host if request.client else None
    result = await create_new_scan(url, resolved_ip_or_error, client_ip, db, redis_client)
    if "error" in result:
        status_code = 503 if "Database" in result["error"] else 400
        raise HTTPException(status_code=status_code, detail=result["error"])
    return result


@router.get("/{scan_id}")
@limiter.limit("60/minute")
async def get_scan_status(request: Request, scan_id: UUID, db: AsyncSession = Depends(get_db)) -> dict:
    """Return current scan status and any available preview details."""
    result = await get_scan_status_data(scan_id, db, redis_client)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/{scan_id}/preview")
async def get_scan_preview(scan_id: UUID, db: AsyncSession = Depends(get_db)) -> dict:
    """Return the free locked preview for a completed report."""
    result = await get_scan_preview_data(scan_id, db)
    if "error" in result:
        status_code = 404 if "not found" in result["error"].lower() else 400
        raise HTTPException(status_code=status_code, detail=result["error"])
    return result
