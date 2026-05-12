import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer

from app.schemas.fix import FixRequest, FixResponse
from app.services.fix_generator import FixGeneratorService

router = APIRouter(tags=["Fixes"])
logger = logging.getLogger(__name__)

_service = FixGeneratorService()

# Optional auth — fix generation works with or without a token
_optional_oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


@router.post("/findings/fix", response_model=FixResponse)
async def generate_fix(
    body: FixRequest,
    token: Optional[str] = Depends(_optional_oauth2),
) -> FixResponse:
    """Generate an AI-powered remediation guide for a single finding."""
    try:
        return await _service.generate_fix(body)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "Unhandled error generating fix for finding %s: %s",
            body.finding_id,
            exc,
            exc_info=True,
        )
        raise HTTPException(status_code=500, detail="Failed to generate fix guide.")


@router.post("/findings/fix/stream")
async def stream_fix(
    body: FixRequest,
    token: Optional[str] = Depends(_optional_oauth2),
) -> StreamingResponse:
    """Stream an AI-powered remediation guide token-by-token via SSE."""
    try:
        return StreamingResponse(
            _service.stream_fix(body),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "Unhandled error streaming fix for finding %s: %s",
            body.finding_id,
            exc,
            exc_info=True,
        )
        raise HTTPException(status_code=500, detail="Failed to stream fix guide.")
