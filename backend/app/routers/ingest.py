"""
Ingest Router — BYOS (Bring-Your-Own-Scanner) API endpoints.

Accepts third-party scanner results and merges them into existing
ShieldCheck scan reports, then recomputes the ASPM risk score.

Endpoints:
  POST /api/ingest/sarif          — SARIF 2.1.0 (Semgrep, CodeQL, ESLint)
  POST /api/ingest/snyk           — Snyk JSON
  POST /api/ingest/trivy          — Trivy JSON
  POST /api/ingest/semgrep        — Semgrep JSON
  POST /api/ingest/generic        — Generic finding array

All endpoints require:
  - scan_id (UUID) as a query param or request body field
  - Source scanner name for provenance tracking

Rate limiting: 30 requests/hour per API key (enforced via middleware).
"""

import json
import logging
from typing import Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from fastapi import Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.report import Report
from app.services.ingestion.normalizer import normalize_findings, Format
from app.services.ingestion.deduplicator import deduplicate_findings, compute_deduplication_stats

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ingest", tags=["ingest"])


# ── Request / Response Models ─────────────────────────────────────────────────

class IngestResponse(BaseModel):
    status: str
    scan_id: str
    new_findings: int
    merged_duplicates: int
    total_findings: int
    ingestion_sources: list[str]
    deduplication_rate: float
    message: str


class GenericFindingItem(BaseModel):
    key: str
    severity: str = "AMBER"
    detail: str
    title: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    affected_file: Optional[str] = None
    fix_action: Optional[str] = None
    references: list[str] = Field(default_factory=list)


class GenericIngestRequest(BaseModel):
    scan_id: str
    source: str = "generic"
    findings: list[GenericFindingItem]


# ── Helper: Load & Update Report ─────────────────────────────────────────────

async def _get_report(db: AsyncSession, scan_id: str) -> Report:
    """Fetch a report by scan_id or raise 404."""
    from sqlalchemy import select
    try:
        uid = UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid scan_id UUID format")

    result = await db.execute(select(Report).where(Report.scan_id == uid))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Scan {scan_id} not found. Run a ShieldCheck scan first."
        )
    return report


def _extract_existing_findings(report: Report) -> list[dict]:
    """Extract the full list of existing classified findings from a report."""
    existing: list[dict] = []

    # From risk_items in report
    raw_findings_json = getattr(report, "raw_findings", None) or {}
    if isinstance(raw_findings_json, str):
        try:
            raw_findings_json = json.loads(raw_findings_json)
        except Exception:
            raw_findings_json = {}

    # Try ingested_findings store first
    ingested_store = getattr(report, "ingested_findings", None) or []
    if isinstance(ingested_store, str):
        try:
            ingested_store = json.loads(ingested_store)
        except Exception:
            ingested_store = []
    existing.extend(ingested_store)

    return existing


async def _save_ingested_findings(
    db: AsyncSession,
    report: Report,
    merged_result: dict,
    source: str,
) -> None:
    """Persist merged ingested findings and update metadata on the report."""
    stats = compute_deduplication_stats(merged_result)

    # Update ingested_findings JSONB column
    report.ingested_findings = merged_result.get("new_findings", [])

    # Update ingestion_sources JSONB column
    existing_sources = getattr(report, "ingestion_sources", None) or []
    if isinstance(existing_sources, str):
        try:
            existing_sources = json.loads(existing_sources)
        except Exception:
            existing_sources = []
    if source not in existing_sources:
        existing_sources.append(source)
    report.ingestion_sources = existing_sources

    # Update deduplication_savings column
    current_savings = getattr(report, "deduplication_savings", 0) or 0
    report.deduplication_savings = current_savings + stats["ingested_merged"]

    await db.commit()


# ── SARIF Endpoint ────────────────────────────────────────────────────────────

@router.post("/sarif", response_model=IngestResponse)
async def ingest_sarif(
    scan_id: str = Query(..., description="Target scan UUID from ShieldCheck"),
    source: str = Query("sarif", description="Scanner name for provenance (e.g. semgrep, codeql)"),
    file: Optional[UploadFile] = File(None),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Ingest SARIF 2.1.0 results into an existing ShieldCheck scan.

    Accepts SARIF from: Semgrep, CodeQL, ESLint, Snyk Code, GitHub Advanced Security.
    """
    # Parse body
    if file:
        content = await file.read()
        try:
            raw_data = json.loads(content)
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=422, detail=f"Invalid JSON in SARIF file: {e}")
    elif request:
        try:
            raw_data = await request.json()
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Invalid JSON body: {e}")
    else:
        raise HTTPException(status_code=422, detail="No SARIF data provided")

    # Validate SARIF version
    version = raw_data.get("version", "")
    if not version.startswith("2.1"):
        logger.warning(f"Non-standard SARIF version received: {version}")

    return await _process_ingestion(db, scan_id, raw_data, Format.SARIF, source)


# ── Snyk Endpoint ─────────────────────────────────────────────────────────────

@router.post("/snyk", response_model=IngestResponse)
async def ingest_snyk(
    scan_id: str = Query(..., description="Target scan UUID from ShieldCheck"),
    source: str = Query("snyk", description="Scanner source label"),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Ingest Snyk JSON results (snyk test --json or snyk container test --json).
    """
    try:
        raw_data = await request.json()
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid JSON body: {e}")

    return await _process_ingestion(db, scan_id, raw_data, Format.SNYK, source)


# ── Trivy Endpoint ────────────────────────────────────────────────────────────

@router.post("/trivy", response_model=IngestResponse)
async def ingest_trivy(
    scan_id: str = Query(..., description="Target scan UUID from ShieldCheck"),
    source: str = Query("trivy", description="Scanner source label"),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Ingest Trivy JSON results (trivy image/fs/repo --format json).
    """
    try:
        raw_data = await request.json()
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid JSON body: {e}")

    return await _process_ingestion(db, scan_id, raw_data, Format.TRIVY, source)


# ── Semgrep Endpoint ──────────────────────────────────────────────────────────

@router.post("/semgrep", response_model=IngestResponse)
async def ingest_semgrep(
    scan_id: str = Query(..., description="Target scan UUID from ShieldCheck"),
    source: str = Query("semgrep", description="Scanner source label"),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Ingest Semgrep JSON results (semgrep --json).
    """
    try:
        raw_data = await request.json()
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid JSON body: {e}")

    return await _process_ingestion(db, scan_id, raw_data, Format.SEMGREP, source)


# ── Generic Endpoint ──────────────────────────────────────────────────────────

@router.post("/generic", response_model=IngestResponse)
async def ingest_generic(
    body: GenericIngestRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Ingest findings in ShieldCheck generic format.

    Accepts any list of findings with: key, severity, detail.
    Useful for custom scanner integrations or manual finding imports.
    """
    raw_data = {
        "findings": [f.model_dump() for f in body.findings]
    }
    return await _process_ingestion(db, body.scan_id, raw_data, Format.GENERIC, body.source)


# ── Ingest Status Endpoint ────────────────────────────────────────────────────

@router.get("/{scan_id}/status")
async def get_ingestion_status(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get the ingestion status for a scan — shows all sources and deduplication stats."""
    report = await _get_report(db, scan_id)

    sources = getattr(report, "ingestion_sources", None) or []
    ingested = getattr(report, "ingested_findings", None) or []
    savings = getattr(report, "deduplication_savings", 0) or 0

    if isinstance(ingested, str):
        try:
            ingested = json.loads(ingested)
        except Exception:
            ingested = []

    return {
        "scan_id": scan_id,
        "ingestion_sources": sources,
        "ingested_findings_count": len(ingested),
        "deduplication_savings": savings,
        "has_ingested_data": len(ingested) > 0,
    }


# ── Core Processing Logic ─────────────────────────────────────────────────────

async def _process_ingestion(
    db: AsyncSession,
    scan_id: str,
    raw_data: Any,
    format: Format,
    source: str,
) -> IngestResponse:
    """
    Core ingestion processing:
    1. Load existing report
    2. Normalize ingested findings to ShieldCheck format
    3. Deduplicate against existing findings
    4. Persist merged findings and update report metadata
    5. Return summary stats
    """
    report = await _get_report(db, scan_id)

    # Normalize
    try:
        ingested = normalize_findings(raw_data, format, source=source)
    except Exception as e:
        logger.error(f"Normalization failed for {source}: {e}", exc_info=True)
        raise HTTPException(
            status_code=422,
            detail=f"Failed to parse {format.value} results: {str(e)[:200]}"
        )

    if not ingested:
        raise HTTPException(
            status_code=422,
            detail=f"No findings could be parsed from {source} output. Verify the format."
        )

    # Deduplicate
    existing = _extract_existing_findings(report)
    try:
        merged_result = deduplicate_findings(existing, ingested)
    except Exception as e:
        logger.error(f"Deduplication failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Deduplication failed")

    # Persist
    await _save_ingested_findings(db, report, merged_result, source)

    stats = compute_deduplication_stats(merged_result)

    logger.info(
        f"Ingested {len(ingested)} findings from {source} into scan {scan_id}: "
        f"{stats['ingested_new']} new, {stats['ingested_merged']} merged"
    )

    return IngestResponse(
        status="success",
        scan_id=scan_id,
        new_findings=stats["ingested_new"],
        merged_duplicates=stats["ingested_merged"],
        total_findings=stats["total_after_dedup"],
        ingestion_sources=stats["ingestion_sources"],
        deduplication_rate=stats["deduplication_rate"],
        message=(
            f"Successfully ingested {len(ingested)} findings from {source}. "
            f"{stats['ingested_new']} new findings added, "
            f"{stats['ingested_merged']} merged with existing results."
        ),
    )
