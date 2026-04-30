from fastapi import APIRouter, HTTPException, Depends
from app.schemas.scan import ScanCreateRequest
from app.utils.url_validator import validate_scan_url
from app.services.scanner.email_security_check import run as run_email_check
from app.main import limiter
from fastapi import Request

router = APIRouter(tags=["Tools"])

@router.post("/email-security")
@limiter.limit("10/minute")
async def check_email_security(request: Request, body: ScanCreateRequest) -> dict:
    """Run a free standalone email security check for a domain."""
    url = body.url.strip()
    if not url:
        raise HTTPException(status_code=422, detail="URL cannot be empty")

    is_valid, resolved_ip_or_error = validate_scan_url(url)
    if not is_valid:
        status_code = 422 if "http://" in resolved_ip_or_error or "https://" in resolved_ip_or_error else 400
        raise HTTPException(status_code=status_code, detail=resolved_ip_or_error)

    # validate_scan_url returns domain in case we pass a domain, or we extract the domain
    # To be safe, extract domain
    from urllib.parse import urlparse
    if not url.startswith("http"):
        url = "http://" + url
    parsed = urlparse(url)
    domain = parsed.hostname or url

    try:
        result = await run_email_check(domain)
        return {"domain": domain, "result": result.__dict__}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
