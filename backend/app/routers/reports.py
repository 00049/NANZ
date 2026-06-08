from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Security, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.models import Report, Scan
from app.schemas.report import ReportResponse, ReportEmailRequest, FreePreviewResponse, RiskItem
from app.utils.auth import verify_report_token

try:
    from app.services.email_service import send_report_email
except ImportError:
    send_report_email = None

router = APIRouter(tags=["Reports"])
security = HTTPBearer()


async def get_current_token_payload(credentials: HTTPAuthorizationCredentials = Security(security)) -> dict:
    """Decode and validate a report access bearer token."""
    payload = verify_report_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid token")
    return payload


# ── Main report ─────────────────────────────────────────────────────────────

from fastapi.responses import JSONResponse
from app.core.report_guard import verify_report_access
from app.core.security import get_current_user_optional
from app.models.user import User
from typing import Optional

@router.get("/{scan_id}", response_model=ReportResponse)
async def get_report(
    scan_id: UUID, 
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Return the full paid report for a scan or 402 if unpaid."""
    scan = await verify_report_access(scan_id, request, db, current_user)
    
    result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    report = result.scalars().first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Check payments table directly as source of truth
    from app.models.payment import Payment
    payment_result = await db.execute(
        select(Payment).where(Payment.scan_id == scan_id, Payment.status == "paid")
    )
    has_paid_payment = payment_result.scalars().first() is not None
    
    # Sync is_paid flag if out of sync
    if has_paid_payment and not report.is_paid:
        report.is_paid = True
        await db.commit()
        
    is_paid_scan = report.is_paid or scan.scan_type == "paid" or has_paid_payment
    user_has_paid_plan = current_user and getattr(current_user, 'plan', None) == 'paid'
    
    if scan.scan_type == "free" and not is_paid_scan and not user_has_paid_plan:
        # Generate Free tier response
        def sev_weight(item):
            sev = item.get("severity", "").upper()
            return {"CRITICAL": 4, "RED": 3, "HIGH": 3, "AMBER": 2, "MEDIUM": 2, "GREEN": 1, "LOW": 1}.get(sev, 0)
        
        all_items = report.risk_items or []
        top_3 = sorted(all_items, key=sev_weight, reverse=True)[:3]
        
        return JSONResponse(status_code=402, content={
            "error": "payment_required",
            "scan_id": str(scan_id),
            "amount": 49900,
            "currency": "INR",
            "score": report.overall_score,
            "grade": getattr(report, "overall_severity", ""),
            "dpdp_score": report.dpdp_compliance_score,
            "ale_estimate": report.ale_reduction_total,
            "total_findings": report.total_findings,
            "top_3_findings": [],
            "modules_run": report.checks_run.get("checks", []) if report.checks_run else []
        })

    return report

# ── SBOM Download ────────────────────────────────────────────────────────────

@router.get("/{scan_id}/sbom")
async def get_sbom(scan_id: UUID, format: str = "cyclonedx", db: AsyncSession = Depends(get_db)):
    """
    Generate an SBOM in CycloneDX or SPDX format from the scan's domain_reports.
    """
    from app.services.sbom_generator import generate_sbom, SBOMFormat
    
    result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    report = result.scalars().first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
        
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalars().first()
    domain = scan.domain if scan else "unknown"
    
    scan_results = report.domain_reports or {}
    
    try:
        fmt = SBOMFormat.SPDX if format.lower() == "spdx" else SBOMFormat.CYCLONEDX
        sbom = generate_sbom(scan_results, domain, str(scan_id), fmt)
        return sbom
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate SBOM: {e}")

# ── Email ────────────────────────────────────────────────────────────────────

@router.post("/{scan_id}/email")
async def email_report(scan_id: UUID, body: ReportEmailRequest, db: AsyncSession = Depends(get_db)) -> dict:
    """Send a paid report by email (Premium bypassed for dev)."""
    result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    report = result.scalars().first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalars().first()
    domain = scan.domain if scan else "nanz-site"

    if send_report_email:
        report_data = {
            "overall_severity": report.overall_severity,
            "risk_items": report.risk_items,
        }
        success = await send_report_email(body.email, report_data, domain)
        if success:
            return {"message": f"Report sent to {body.email}"}
        raise HTTPException(status_code=500, detail="Failed to send email")
    raise HTTPException(status_code=500, detail="Email service unavailable")


# ── Remediation Roadmap (Module 10) ──────────────────────────────────────────

@router.get("/{scan_id}/roadmap")
async def get_roadmap(scan_id: UUID, db: AsyncSession = Depends(get_db)) -> dict:
    """
    Generate a prioritized remediation roadmap.
    Includes stack-specific code fixes, risk_score_reduction_delta, and regulatory_impact.
    """
    from app.services.remediation import generate_roadmap, detect_backend_framework

    result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    report = result.scalars().first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Detect backend framework from domain_reports
    domain_reports = report.domain_reports or {}
    framework = detect_backend_framework(domain_reports)

    return generate_roadmap(report.risk_items or [], framework=framework)


# ── Compliance Report (Module 9) ─────────────────────────────────────────────

@router.get("/{scan_id}/compliance")
async def get_compliance_report(scan_id: UUID, db: AsyncSession = Depends(get_db)) -> dict:
    """
    Return the per-framework compliance readiness report.
    Covers DPDP, GDPR, PCI DSS v4.0, SOC 2 Type II, and DORA.
    If not yet stored (older scan), generates it on-the-fly.
    """
    from app.services.compliance_mapper import map_to_frameworks

    result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    report = result.scalars().first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Return cached compliance report if already stored
    if report.compliance_report:
        return report.compliance_report

    # Generate on-the-fly for older scans
    try:
        compliance = map_to_frameworks(report.risk_items or [])
        return compliance.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Compliance generation failed: {e}")


# ── Brand Threats (Module 5) ──────────────────────────────────────────────────

@router.get("/{scan_id}/brand-threats")
async def get_brand_threats(scan_id: UUID, db: AsyncSession = Depends(get_db)) -> dict:
    """
    Return brand protection findings: CT log alerts, typosquatting, and homoglyph domains.
    """
    result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    report = result.scalars().first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if not report.brand_threats:
        # Re-run on-demand if not stored
        try:
            scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = scan_result.scalars().first()
            if scan:
                from app.services.scanner.brand_monitor import check_brand_threats
                import asyncio
                brand_result = await asyncio.wait_for(
                    check_brand_threats(scan.domain), timeout=30.0
                )
                return brand_result
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Brand threat check failed: {e}")
        return {"threats": [], "message": "No brand threat data available for this scan."}

    return report.brand_threats


# ── BOLA/IDOR Findings (Module 1) ─────────────────────────────────────────────

@router.get("/{scan_id}/bola")
async def get_bola_findings(scan_id: UUID, db: AsyncSession = Depends(get_db)) -> dict:
    """Return BOLA/IDOR findings for authenticated scans."""
    result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    report = result.scalars().first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return {
        "findings": report.bola_findings or [],
        "message": "BOLA/IDOR scanning requires providing two sets of target credentials."
        if not report.bola_findings else None
    }


# ── Enterprise Security Data ───────────────────────────────────────────────────

@router.get("/{scan_id}/enterprise")
async def get_enterprise_data(scan_id: UUID, db: AsyncSession = Depends(get_db)) -> dict:
    """
    Return enterprise module results (IAST, OAST, API, GraphQL, Business Logic,
    Container, Dependency, LLM) for a scan.

    If the scan was run before enterprise modules were added, runs a lightweight
    re-scan of the enterprise modules live.
    """
    result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    report = result.scalars().first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    domain_reports = report.domain_reports or {}

    # Return stored enterprise data if present
    if domain_reports.get("enterprise"):
        return {
            "enterprise": domain_reports["enterprise"],
            "aspm": domain_reports.get("aspm"),
        }

    # Otherwise, run enterprise modules live against the scan domain
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    domain = scan.domain
    url = f"https://{domain}"

    import asyncio
    from app.services.scanner import (
        iast_behavioral, oast_check, api_security_check,
        graphql_check, business_logic_check, container_security_check,
        dependency_check, llm_security_check,
    )
    from app.services.oast.oast_client import OASTClient, OASTUnavailableError
    from app.services.aspm_engine import compute_aspm_report
    from app.services.classifier import classify_findings

    # Start OAST session
    oast_client = None
    try:
        oast_client = OASTClient()
        await oast_client.start_session()
    except (OASTUnavailableError, Exception):
        oast_client = None

    async def safe_run(coro, fallback: dict) -> dict:
        try:
            result_obj = await asyncio.wait_for(coro, timeout=90.0)
            if hasattr(result_obj, "__dict__"):
                return result_obj.__dict__
            return result_obj
        except Exception as exc:
            return {**fallback, "error": str(exc)[:200]}

    ent_iast, ent_oast, ent_api, ent_graphql, ent_bl, ent_container, ent_dep, ent_llm = \
        await asyncio.gather(
            safe_run(iast_behavioral.run(url, domain), {"error_verbosity_score": 0}),
            safe_run(oast_check.run(url, domain, oast_client), {"ssrf_confirmed": False}),
            safe_run(api_security_check.run(url, domain), {"endpoints_discovered": []}),
            safe_run(graphql_check.run(url, domain), {"graphql_detected": False}),
            safe_run(business_logic_check.run(url, domain), {"probes_sent": 0}),
            safe_run(container_security_check.run(url, domain), {"findings": []}),
            safe_run(dependency_check.run(url, domain), {"detected_libraries": []}),
            safe_run(llm_security_check.run(url, domain), {"llm_surface_detected": False}),
        )

    if oast_client:
        try:
            await oast_client.stop_session()
        except Exception:
            pass

    # JSON-safe helper
    import json

    def _safe(obj):
        try:
            return json.loads(json.dumps(obj, default=str))
        except Exception:
            return {}

    enterprise_results = {
        "iast": _safe(ent_iast),
        "oast": _safe(ent_oast),
        "api_security": _safe(ent_api),
        "graphql": _safe(ent_graphql),
        "business_logic": _safe(ent_bl),
        "container": _safe(ent_container),
        "dependency": _safe(ent_dep),
        "llm_security": _safe(ent_llm),
    }

    # Compute ASPM
    classified = report.risk_items or []
    try:
        aspm_report = compute_aspm_report(
            classified_findings=classified,
            raw_findings={},
            enterprise_results=enterprise_results,
            base_score=report.overall_score or 50,
        )
        aspm_data = _safe(aspm_report.__dict__)
    except Exception as exc:
        aspm_data = {"error": str(exc)}

    # Persist back into domain_reports so future calls are instant
    try:
        updated_domain_reports = dict(domain_reports)
        updated_domain_reports["enterprise"] = enterprise_results
        updated_domain_reports["aspm"] = aspm_data
        report.domain_reports = updated_domain_reports

        # Also persist dedicated fields
        report.bola_findings = enterprise_results.get("api_security")
        report.api_findings = enterprise_results.get("api_security")
        report.llm_findings = enterprise_results.get("llm_security")
        report.oast_interactions = enterprise_results.get("oast")

        await db.commit()
    except Exception as exc:
        # Non-fatal — still return the data
        pass

    return {
        "enterprise": enterprise_results,
        "aspm": aspm_data,
    }


# ── ASPM Posture Score ─────────────────────────────────────────────────────────

@router.get("/{scan_id}/aspm")
async def get_aspm_score(scan_id: UUID, db: AsyncSession = Depends(get_db)) -> dict:
    """Return the ASPM posture score and OWASP coverage map for a scan."""
    result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    report = result.scalars().first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    domain_reports = report.domain_reports or {}
    if domain_reports.get("aspm"):
        return domain_reports["aspm"]

    # Compute on the fly from existing findings
    from app.services.aspm_engine import compute_aspm_report
    import json

    def _safe(obj):
        try:
            return json.loads(json.dumps(obj, default=str))
        except Exception:
            return {}

    classified = report.risk_items or []
    enterprise_results = domain_reports.get("enterprise", {})

    try:
        aspm_report = compute_aspm_report(
            classified_findings=classified,
            raw_findings={},
            enterprise_results=enterprise_results,
            base_score=report.overall_score or 50,
        )
        return _safe(aspm_report.__dict__)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"ASPM computation failed: {exc}")

