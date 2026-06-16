from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import get_current_user
from app.crud.crud_risk_exception import (
    create_exception,
    get_active_exceptions_for_domain,
    get_exception,
    remove_exception,
)
from app.db.session import get_db
from app.models.report import Report
from app.models.scan import Scan
from app.models.user import User
from app.schemas.risk_exception import RiskExceptionCreate, RiskExceptionResponse
from app.services.scanner.orchestrator import _calculate_weighted_score

router = APIRouter(prefix="/exceptions", tags=["Exceptions"])


@router.get("/scans/{scan_id}", response_model=list[RiskExceptionResponse])
def list_exceptions(
    scan_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalars().first()
    if not scan or not scan.domain_id:
        raise HTTPException(status_code=404, detail="Scan or domain not found")
    return get_active_exceptions_for_domain(db, scan.domain_id)


@router.post("/scans/{scan_id}", response_model=RiskExceptionResponse)
def add_exception(
    scan_id: UUID,
    exception_in: RiskExceptionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalars().first()
    if not scan or not scan.domain_id:
        raise HTTPException(status_code=404, detail="Scan or domain not found")
    domain_id = scan.domain_id

    # 1. Create or update the exception in the DB
    exception = create_exception(db, domain_id, current_user.id, exception_in)

    # 2. Retro-actively apply to the most recent Report for this domain to immediately update score
    latest_report = (
        db.execute(
            select(Report)
            .join(Report.scan)
            .where(Report.scan.has(domain_id=domain_id))
            .order_by(Report.generated_at.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )

    if latest_report:
        # Fetch ALL active exceptions for the domain to pass to the scoring function
        active_exceptions = get_active_exceptions_for_domain(db, domain_id)
        exceptions_map = {exc.finding_key: exc for exc in active_exceptions}

        # risk_items is the classified list
        classified = list(latest_report.risk_items) if latest_report.risk_items else []

        # Reconstruct raw_findings from checks_run
        raw_findings = latest_report.checks_run if latest_report.checks_run else {}
        waf_data = raw_findings.get("waf", {}).get("data")

        # Recalculate
        overall_score, score_breakdown = _calculate_weighted_score(
            classified, raw_findings, waf_data, exceptions_map
        )

        # Update the report
        latest_report.risk_items = (
            classified  # Risk items were mutated in-place by _calculate_weighted_score
        )
        latest_report.overall_score = overall_score

        db.add(latest_report)
        db.commit()

    return exception


@router.delete("/{exception_id}", status_code=204)
def delete_exception(
    exception_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    exception = get_exception(db, exception_id)
    if not exception:
        raise HTTPException(status_code=404, detail="Exception not found")

    domain_id = exception.domain_id
    remove_exception(db, exception, current_user.id)

    # Recalculate score for latest report after removing exception
    latest_report = (
        db.execute(
            select(Report)
            .join(Report.scan)
            .where(Report.scan.has(domain_id=domain_id))
            .order_by(Report.generated_at.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )

    if latest_report:
        active_exceptions = get_active_exceptions_for_domain(db, domain_id)
        exceptions_map = {exc.finding_key: exc for exc in active_exceptions}

        classified = list(latest_report.risk_items) if latest_report.risk_items else []

        # Remove exception metadata from previously accepted findings that match this key
        for finding in classified:
            if finding.get("key") == exception.finding_key:
                finding.pop("exception_status", None)
                finding.pop("exception_justification", None)
                finding.pop("exception_owner", None)
                finding.pop("exception_expires_at", None)

        raw_findings = latest_report.checks_run if latest_report.checks_run else {}
        waf_data = raw_findings.get("waf", {}).get("data")

        overall_score, score_breakdown = _calculate_weighted_score(
            classified, raw_findings, waf_data, exceptions_map
        )

        latest_report.risk_items = classified
        latest_report.overall_score = overall_score

        db.add(latest_report)
        db.commit()
