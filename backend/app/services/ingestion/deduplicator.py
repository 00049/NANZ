"""
Finding Deduplicator — Merges ingested findings with existing scan results.

Deduplication strategy (applied in order):
  1. CVE ID match          — same CVE + same package/component
  2. Key + endpoint match  — same check_type + same affected_file/url
  3. Title fingerprint     — normalized title similarity (fuzzy)

When duplicates are found:
  - The finding with the highest severity wins
  - `confirmed_by` field merges all source scanners
  - `duplicate_count` tracks how many times this finding was seen

Usage:
    from app.services.ingestion.deduplicator import deduplicate_findings
    result = deduplicate_findings(existing_findings, ingested_findings)
"""

import hashlib
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {"CRITICAL": 5, "RED": 4, "AMBER": 3, "GREEN": 2, "INFO": 1}


def _normalize_title(title: str) -> str:
    """Normalize a finding title for fuzzy matching."""
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]", "", title.lower())).strip()


def _finding_fingerprint(finding: dict) -> str:
    """
    Generate a deterministic fingerprint for deduplication.

    Priority: CVE ID > key+file > title fingerprint
    """
    cve_id = finding.get("cve_id")
    affected_file = finding.get("affected_file") or finding.get("url") or ""
    key = finding.get("key") or finding.get("check_type") or ""
    title = finding.get("title") or finding.get("detail") or ""

    if cve_id:
        # CVE + package/file context
        component = finding.get("affected_file") or finding.get("source_scanner") or ""
        return f"cve:{cve_id}:{component[:30]}"

    if key and affected_file:
        return f"key:{key}:{affected_file[:60]}"

    if key:
        return f"key:{key}"

    # Fallback: title fingerprint
    return f"title:{hashlib.md5(_normalize_title(title).encode()).hexdigest()[:16]}"


def _merge_findings(primary: dict, duplicate: dict) -> dict:
    """
    Merge a duplicate finding into the primary one.

    Rules:
    - Highest severity wins
    - confirmed_by list is merged
    - references lists are merged
    - raw_finding from each is preserved
    """
    merged = dict(primary)

    # Severity: take worst
    primary_rank = _SEVERITY_RANK.get(primary.get("severity", "INFO"), 1)
    dup_rank = _SEVERITY_RANK.get(duplicate.get("severity", "INFO"), 1)
    if dup_rank > primary_rank:
        merged["severity"] = duplicate["severity"]

    # confirmed_by: merge source scanners
    primary_sources = primary.get("confirmed_by", [primary.get("source_scanner", primary.get("module", "shieldcheck"))])
    dup_source = duplicate.get("source_scanner") or duplicate.get("module") or "shieldcheck"
    if isinstance(primary_sources, str):
        primary_sources = [primary_sources]
    confirmed_by = list(set(primary_sources + [dup_source]))
    merged["confirmed_by"] = confirmed_by

    # references: merge unique
    primary_refs = primary.get("references", [])
    dup_refs = duplicate.get("references", [])
    merged["references"] = list(set(primary_refs + dup_refs))[:10]

    # Increment duplicate counter
    merged["duplicate_count"] = primary.get("duplicate_count", 1) + 1

    # Prefer the more detailed description
    if len(str(duplicate.get("technical_detail", ""))) > len(str(primary.get("technical_detail", ""))):
        merged["technical_detail"] = duplicate.get("technical_detail")

    if len(str(duplicate.get("fix_action", ""))) > len(str(primary.get("fix_action", ""))):
        merged["fix_action"] = duplicate.get("fix_action")

    return merged


def deduplicate_findings(
    existing_findings: list[dict],
    ingested_findings: list[dict],
) -> dict:
    """
    Merge ingested findings into existing findings with deduplication.

    Args:
        existing_findings: Findings from ShieldCheck's own scanner modules
        ingested_findings: Normalized findings from third-party scanners

    Returns:
        {
            "merged_findings": list[dict],      # Full merged set
            "new_findings": list[dict],         # Only newly added findings
            "duplicates_found": int,
            "deduplication_savings": int,       # Findings merged/suppressed
            "merge_summary": dict,              # Per-source summary
        }
    """
    # Build fingerprint index for existing findings
    fingerprint_index: dict[str, dict] = {}
    for f in existing_findings:
        fp = _finding_fingerprint(f)
        fingerprint_index[fp] = dict(f)

    new_findings: list[dict] = []
    duplicates_found = 0
    deduplication_savings = 0
    merge_summary: dict[str, dict] = {}

    for ingested in ingested_findings:
        source = ingested.get("source_scanner") or ingested.get("module") or "external"
        if source not in merge_summary:
            merge_summary[source] = {"total": 0, "new": 0, "merged": 0}
        merge_summary[source]["total"] += 1

        fp = _finding_fingerprint(ingested)

        if fp in fingerprint_index:
            # Duplicate — merge
            fingerprint_index[fp] = _merge_findings(fingerprint_index[fp], ingested)
            duplicates_found += 1
            deduplication_savings += 1
            merge_summary[source]["merged"] += 1
            logger.debug(f"Deduped: {fp} (source: {source})")
        else:
            # New finding — mark with initial metadata
            new_f = dict(ingested)
            new_f.setdefault("confirmed_by", [source])
            new_f.setdefault("duplicate_count", 1)
            fingerprint_index[fp] = new_f
            new_findings.append(new_f)
            merge_summary[source]["new"] += 1

    # Reconstruct merged findings: existing (possibly updated) + new
    existing_fps = {_finding_fingerprint(f) for f in existing_findings}
    merged_findings = []

    # Existing findings (with merged data)
    for f in existing_findings:
        fp = _finding_fingerprint(f)
        merged_findings.append(fingerprint_index.get(fp, f))

    # Truly new findings
    merged_findings.extend(new_findings)

    logger.info(
        f"Deduplication complete: {len(existing_findings)} existing + "
        f"{len(ingested_findings)} ingested → "
        f"{len(merged_findings)} total ({duplicates_found} duplicates merged)"
    )

    return {
        "merged_findings": merged_findings,
        "new_findings": new_findings,
        "duplicates_found": duplicates_found,
        "deduplication_savings": deduplication_savings,
        "merge_summary": merge_summary,
    }


def compute_deduplication_stats(merged_result: dict) -> dict:
    """
    Generate human-readable stats from a deduplicate_findings result.

    Returns stats suitable for the ASPM report.
    """
    new = len(merged_result.get("new_findings", []))
    savings = merged_result.get("deduplication_savings", 0)
    total = len(merged_result.get("merged_findings", []))
    sources = list(merged_result.get("merge_summary", {}).keys())

    return {
        "ingested_new": new,
        "ingested_merged": savings,
        "total_after_dedup": total,
        "ingestion_sources": sources,
        "deduplication_rate": (
            round(savings / (new + savings) * 100, 1) if (new + savings) > 0 else 0.0
        ),
    }
