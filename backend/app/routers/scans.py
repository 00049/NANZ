from uuid import UUID
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

from app.db.session import get_db
from app.schemas.scan import ScanCreateRequest, ScanResponse, ScanStatusResponse, ScanPreviewResponse
from app.schemas.common import WrappedResponse, success_response, error_response
from app.utils.url_validator import validate_scan_url
from app.config import settings
from app.main import limiter
from app.services.scan_service import create_new_scan, get_scan_status_data, get_scan_preview_data

router = APIRouter(tags=["Scans"])

# Global redis client for routers with fast failover logic
redis_client = Redis.from_url(settings.REDIS_URL, decode_responses=True, socket_connect_timeout=1.0, socket_timeout=1.0)

@router.post("", response_model=WrappedResponse[dict], status_code=202)
@limiter.limit("100/minute")
async def create_scan(request: Request, body: ScanCreateRequest, db: AsyncSession = Depends(get_db)):
    url = body.url.strip()
    if not url:
        return JSONResponse(status_code=400, content=error_response("URL cannot be empty"))
        
    is_valid, resolved_ip_or_error = validate_scan_url(url)
    if not is_valid:
        return JSONResponse(status_code=400, content=error_response(resolved_ip_or_error))
        
    client_ip = request.client.host if request.client else None
    
    result = await create_new_scan(url, resolved_ip_or_error, client_ip, db, redis_client)
    
    if "error" in result:
        return JSONResponse(status_code=400, content=error_response(result["error"]))
        
    return success_response(result)


@router.get("/{scan_id}", response_model=WrappedResponse[dict])
@limiter.limit("60/minute")
async def get_scan_status(request: Request, scan_id: UUID, db: AsyncSession = Depends(get_db)):
    result = await get_scan_status_data(scan_id, db, redis_client)
    if "error" in result:
        status_code = 404 if "not found" in result["error"].lower() else 400
        return JSONResponse(status_code=status_code, content=error_response(result["error"]))
    return success_response(result)

@router.get("/{scan_id}/preview", response_model=WrappedResponse[dict])
async def get_scan_preview(scan_id: UUID, db: AsyncSession = Depends(get_db)):
    result = await get_scan_preview_data(scan_id, db)
    if "error" in result:
        status_code = 404 if "not found" in result["error"].lower() and "ready" not in result["error"].lower() else 400
        return JSONResponse(status_code=status_code, content=error_response(result["error"]))
    return success_response(result)
