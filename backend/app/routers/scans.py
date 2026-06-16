from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.report_guard import verify_report_access
from app.core.security import get_current_user
from app.db.session import get_db
from app.main import limiter
from app.models.user import User
from app.schemas.scan import ScanCreateRequest
from app.services.scan_service import (
    create_new_scan,
    get_scan_preview_data,
    get_scan_status_data,
)
from app.utils.url_validator import validate_scan_url

router = APIRouter(tags=["Scans"])

redis_client = Redis.from_url(
    settings.REDIS_URL,
    decode_responses=True,
    socket_connect_timeout=1.0,
    socket_timeout=1.0,
)


@router.get("")
async def list_scans(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return a paginated list of scans belonging to the authenticated user."""
    from sqlalchemy import func, select

    from app.models.report import Report
    from app.models.scan import Scan

    total_result = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.user_id == current_user.id)
    )
    total = total_result.scalar()

    result = await db.execute(
        select(Scan, Report)
        .outerjoin(Report, Scan.id == Report.scan_id)
        .where(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    rows = result.all()

    scans_out = []
    for scan, report in rows:
        scan_data = {
            "id": str(scan.id),
            "domain": scan.domain,
            "url": scan.url,
            "status": scan.status,
            "scan_type": scan.scan_type,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "completed_at": (
                scan.completed_at.isoformat() if scan.completed_at else None
            ),
            "scan_duration_ms": scan.scan_duration_ms,
        }
        if report:
            scan_data["overall_score"] = report.overall_score
            scan_data["overall_severity"] = report.overall_severity
            scan_data["critical_count"] = report.critical_count
            scan_data["high_count"] = report.high_count
            scan_data["medium_count"] = report.medium_count
            scan_data["low_count"] = report.low_count
            scan_data["info_count"] = report.info_count
            scan_data["total_findings"] = report.total_findings
            scan_data["is_paid"] = report.is_paid
        scans_out.append(scan_data)

    return {"total": total, "scans": scans_out}


@router.post("", status_code=202)
@limiter.limit(f"{settings.MAX_SCANS_PER_IP_PER_HOUR}/hour")
async def create_scan(
    request: Request,
    background_tasks: BackgroundTasks,
    body: ScanCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(lambda: None),
) -> dict:
    """Create a scan request and dispatch the passive scanner task."""

    # Try to get user from token if provided
    user_id = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        try:
            from app.db.session import get_db as _get_db

            async for _db_session in _get_db():
                from jose import jwt

                from app.core.security import ALGORITHM, SECRET_KEY

                token = auth_header.split(" ", 1)[1]
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                user_id = payload.get("sub")
                break
        except Exception:
            pass

    url = body.url.strip()
    if not url:
        raise HTTPException(status_code=422, detail="URL cannot be empty")

    is_valid, resolved_ip_or_error = validate_scan_url(url)
    if not is_valid:
        status_code = (
            422
            if "http://" in resolved_ip_or_error or "https://" in resolved_ip_or_error
            else 400
        )
        raise HTTPException(status_code=status_code, detail=resolved_ip_or_error)

    client_ip = request.client.host if request.client else None
    result = await create_new_scan(
        url,
        resolved_ip_or_error,
        client_ip,
        db,
        redis_client,
        user_id=user_id,
        background_tasks=background_tasks,
    )
    if "error" in result:
        status_code = 503 if "Database" in result["error"] else 400
        raise HTTPException(status_code=status_code, detail=result["error"])
    return result


@router.get("/{scan_id}")
@limiter.limit("60/minute")
async def get_scan_status(
    request: Request, scan_id: UUID, db: AsyncSession = Depends(get_db)
) -> dict:
    """Return current scan status and any available preview details."""
    result = await get_scan_status_data(scan_id, db, redis_client)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/{scan_id}/preview")
async def get_scan_preview(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    scan=Depends(verify_report_access),
) -> dict:
    """Return the free locked preview for a completed report. Protected by report_guard."""
    result = await get_scan_preview_data(scan_id, db)
    if "error" in result:
        status_code = 404 if "not found" in result["error"].lower() else 400
        raise HTTPException(status_code=status_code, detail=result["error"])
    return result


@router.post("/{scan_id}/feedback")
@limiter.limit("10/minute")
async def submit_finding_feedback(
    request: Request, scan_id: UUID, body: dict, db: AsyncSession = Depends(get_db)
) -> dict:
    """Submit feedback on a specific finding (false_positive / confirmed / fixed)."""
    from sqlalchemy import select
    from sqlalchemy import text as sa_text

    from app.models.scan import Scan

    finding_id = body.get("finding_id", "")
    check_type = body.get("check_type", "")
    feedback_type = body.get("feedback_type", "")

    if feedback_type not in ("false_positive", "confirmed", "fixed"):
        raise HTTPException(
            status_code=422,
            detail="feedback_type must be: false_positive, confirmed, or fixed",
        )
    if not finding_id or not check_type:
        raise HTTPException(
            status_code=422, detail="finding_id and check_type are required"
        )

    # Verify scan exists
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Insert feedback
    await db.execute(
        sa_text(
            "INSERT INTO scan_feedback (scan_id, finding_id, check_type, feedback_type) "
            "VALUES (:scan_id, :finding_id, :check_type, :feedback_type)"
        ),
        {
            "scan_id": str(scan_id),
            "finding_id": finding_id,
            "check_type": check_type,
            "feedback_type": feedback_type,
        },
    )
    await db.commit()
    return {
        "status": "ok",
        "message": f"Feedback '{feedback_type}' recorded for {check_type}",
    }


@router.get("/compare")
async def compare_scans(
    scan_a: UUID, scan_b: UUID, db: AsyncSession = Depends(get_db)
) -> dict:
    """Compare two scans of the same domain and return differences."""
    from sqlalchemy import select

    from app.models.report import Report
    from app.models.scan import Scan

    s1 = await db.execute(select(Scan).where(Scan.id == scan_a))
    s2 = await db.execute(select(Scan).where(Scan.id == scan_b))
    scan1 = s1.scalars().first()
    scan2 = s2.scalars().first()

    if not scan1 or not scan2:
        raise HTTPException(status_code=404, detail="One or both scans not found")

    if scan1.domain != scan2.domain:
        raise HTTPException(
            status_code=400, detail="Cannot compare scans from different domains"
        )

    if scan1.status != "completed" or scan2.status != "completed":
        raise HTTPException(
            status_code=400, detail="Both scans must be completed to compare"
        )

    r1 = await db.execute(select(Report).where(Report.scan_id == scan_a))
    r2 = await db.execute(select(Report).where(Report.scan_id == scan_b))
    report1 = r1.scalars().first()
    report2 = r2.scalars().first()

    if not report1 or not report2:
        raise HTTPException(status_code=404, detail="One or both reports not found")

    # Diff logic
    findings_a = {f["id"]: f for f in report1.findings}
    findings_b = {f["id"]: f for f in report2.findings}

    resolved = [f for f_id, f in findings_a.items() if f_id not in findings_b]
    new_issues = [f for f_id, f in findings_b.items() if f_id not in findings_a]
    persisting = [f for f_id, f in findings_b.items() if f_id in findings_a]

    return {
        "domain": scan1.domain,
        "scan_a": {
            "scan_id": str(scan_a),
            "date": scan1.created_at.isoformat(),
            "score": report1.overall_score,
            "severity": report1.overall_severity,
            "total_findings": report1.total_findings,
        },
        "scan_b": {
            "scan_id": str(scan_b),
            "date": scan2.created_at.isoformat(),
            "score": report2.overall_score,
            "severity": report2.overall_severity,
            "total_findings": report2.total_findings,
        },
        "comparison": {
            "score_change": report2.overall_score - report1.overall_score,
            "improved": report2.overall_score > report1.overall_score,
            "resolved_count": len(resolved),
            "new_count": len(new_issues),
            "persisting_count": len(persisting),
            "resolved_findings": resolved,
            "new_findings": new_issues,
            "persisting_findings": persisting,
        },
    }
