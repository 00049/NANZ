"""
Scanner Result Normalizer — Bring-Your-Own-Scanner (BYOS) Ingestion Layer.

Translates third-party scanner output formats into ShieldCheck's internal
normalized finding format (compatible with RiskItem schema).

Supported formats:
  - SARIF 2.1.0 (Semgrep, CodeQL, ESLint, Snyk Code)
  - Snyk JSON (snyk test --json)
  - Trivy JSON (trivy image --format json / trivy fs --format json)
  - Semgrep JSON (semgrep --json)
  - Generic ShieldCheck finding array

Usage:
    from app.services.ingestion.normalizer import normalize_findings, Format

    normalized = normalize_findings(raw_data, Format.SARIF, source="semgrep")
"""

import logging
import re
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)

# ── Severity Mapping Tables ───────────────────────────────────────────────────

_SARIF_LEVEL_TO_SEVERITY: dict[str, str] = {
    "error": "RED",
    "warning": "AMBER",
    "note": "GREEN",
    "none": "INFO",
}

_CVSS_TO_SEVERITY: dict[str, str] = {
    # CVSS 3.x score ranges
}

_SNYK_SEVERITY: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "RED",
    "medium": "AMBER",
    "low": "GREEN",
}

_TRIVY_SEVERITY: dict[str, str] = {
    "CRITICAL": "CRITICAL",
    "HIGH": "RED",
    "MEDIUM": "AMBER",
    "LOW": "GREEN",
    "UNKNOWN": "INFO",
}

_SEMGREP_SEVERITY: dict[str, str] = {
    "ERROR": "RED",
    "WARNING": "AMBER",
    "INFO": "GREEN",
}


def _cvss_to_severity(score: float | None) -> str:
    """Map a CVSS score to internal severity."""
    if score is None:
        return "AMBER"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "RED"
    if score >= 4.0:
        return "AMBER"
    if score >= 0.1:
        return "GREEN"
    return "INFO"


class Format(StrEnum):
    SARIF = "sarif"
    SNYK = "snyk"
    TRIVY = "trivy"
    SEMGREP = "semgrep"
    GENERIC = "generic"


# ── Normalized Finding Template ───────────────────────────────────────────────


def _base_finding(
    key: str,
    title: str,
    severity: str,
    description: str,
    cve_id: str | None = None,
    cvss_score: float | None = None,
    affected_file: str | None = None,
    affected_line: int | None = None,
    remediation: str | None = None,
    references: list[str] | None = None,
    source: str = "external",
    raw: dict | None = None,
) -> dict:
    """Build a normalized finding dict compatible with ShieldCheck RiskItem."""
    return {
        "key": key,
        "check": "external_scanner",
        "check_type": key,
        "module": source,
        "severity": severity,
        "detail": description or title,
        "title": title,
        "business_impact": f"A security issue was detected by {source}: {title}",
        "technical_detail": description or title,
        "fix_action": remediation
        or "Review the finding and apply the recommended fix.",
        "fix_difficulty": "Medium",
        "estimated_fix_time": "30 minutes",
        "references": references or [],
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "affected_file": affected_file,
        "affected_line": affected_line,
        "source_scanner": source,
        "ingested": True,
        "raw_finding": raw or {},
    }


# ── SARIF 2.1.0 Parser ────────────────────────────────────────────────────────


def _normalize_sarif(data: dict, source: str = "sarif") -> list[dict]:
    """
    Parse SARIF 2.1.0 results into normalized findings.

    Handles: Semgrep, CodeQL, ESLint, Snyk Code, and standard SARIF tools.
    """
    normalized: list[dict] = []
    runs = data.get("runs", [])

    for run in runs:
        tool_name = run.get("tool", {}).get("driver", {}).get("name", source)
        rules_by_id: dict[str, dict] = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rules_by_id[rule["id"]] = rule

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown_rule")
            level = result.get("level", "warning")
            severity = _SARIF_LEVEL_TO_SEVERITY.get(level, "AMBER")

            # Title from rule or message
            rule = rules_by_id.get(rule_id, {})
            title = (
                rule.get("name")
                or rule.get("shortDescription", {}).get("text")
                or rule_id
            )
            desc = (
                result.get("message", {}).get("text")
                or rule.get("fullDescription", {}).get("text")
                or rule.get("shortDescription", {}).get("text")
                or title
            )

            # Location
            location_list = result.get("locations", [])
            affected_file = None
            affected_line = None
            if location_list:
                phys = location_list[0].get("physicalLocation", {})
                affected_file = phys.get("artifactLocation", {}).get("uri")
                affected_line = phys.get("region", {}).get("startLine")

            # References
            refs = [
                r.get("uri", "")
                for r in rule.get("helpUri", [{"uri": ""}])
                if isinstance(r, dict)
            ]
            help_uri = rule.get("helpUri")
            if isinstance(help_uri, str):
                refs = [help_uri]

            # CVE extraction from rule tags
            cve_id = None
            tags = rule.get("properties", {}).get("tags", [])
            for tag in tags:
                if isinstance(tag, str) and tag.upper().startswith("CVE-"):
                    cve_id = tag.upper()
                    break

            key = f"sarif_{tool_name.lower().replace(' ', '_')}_{rule_id[:40]}"

            normalized.append(
                _base_finding(
                    key=key,
                    title=title,
                    severity=severity,
                    description=desc,
                    cve_id=cve_id,
                    affected_file=affected_file,
                    affected_line=affected_line,
                    references=refs,
                    source=tool_name,
                    raw=result,
                )
            )

    logger.info(f"SARIF: normalized {len(normalized)} findings from {source}")
    return normalized


# ── Snyk JSON Parser ──────────────────────────────────────────────────────────


def _normalize_snyk(data: dict, source: str = "snyk") -> list[dict]:
    """
    Parse Snyk JSON output (snyk test --json or snyk container test --json).
    Handles both single-project and multi-project results.
    """
    normalized: list[dict] = []

    # Multi-project result
    results_list = data if isinstance(data, list) else [data]

    for project_result in results_list:
        vulnerabilities = project_result.get("vulnerabilities", [])
        project_result.get("projectName", "unknown")

        for vuln in vulnerabilities:
            cve_ids = vuln.get("identifiers", {}).get("CVE", [])
            cve_id = cve_ids[0] if cve_ids else None

            cvss_score = vuln.get("cvssScore")
            if cvss_score is not None:
                try:
                    cvss_score = float(cvss_score)
                except (TypeError, ValueError):
                    cvss_score = None

            severity_raw = vuln.get("severity", "medium")
            severity = _SNYK_SEVERITY.get(severity_raw.lower(), "AMBER")

            title = vuln.get("title") or vuln.get("name") or "Unknown Vulnerability"
            desc = vuln.get("description") or title
            module_name = vuln.get("moduleName") or vuln.get("packageName") or ""
            fix = vuln.get("fixedIn", [])
            remediation = (
                f"Upgrade {module_name} to {fix[0]}"
                if fix
                else (
                    vuln.get("remediation")
                    or vuln.get("description")
                    or "Apply vendor patch"
                )
            )

            refs = [
                r.get("url", "")
                for r in vuln.get("references", [])
                if isinstance(r, dict)
            ]
            if cve_id:
                refs.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")

            key = f"snyk_{(cve_id or vuln.get('id', 'unknown')).lower().replace('-', '_')[:50]}"

            normalized.append(
                _base_finding(
                    key=key,
                    title=title,
                    severity=severity,
                    description=desc,
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    affected_file=module_name,
                    remediation=remediation,
                    references=[r for r in refs if r],
                    source=source,
                    raw=vuln,
                )
            )

    logger.info(f"Snyk: normalized {len(normalized)} findings")
    return normalized


# ── Trivy JSON Parser ─────────────────────────────────────────────────────────


def _normalize_trivy(data: dict, source: str = "trivy") -> list[dict]:
    """
    Parse Trivy JSON output (trivy image/fs/repo --format json).
    Handles Results array with Vulnerabilities and Misconfigurations.
    """
    normalized: list[dict] = []
    results = data.get("Results", [])

    for result in results:
        target = result.get("Target", "")

        # Vulnerabilities
        for vuln in result.get("Vulnerabilities", []) or []:
            cve_id = vuln.get("VulnerabilityID")
            title = vuln.get("Title") or vuln.get("PkgName") or cve_id or "Unknown"
            desc = vuln.get("Description") or title
            sev_raw = vuln.get("Severity", "UNKNOWN")
            severity = _TRIVY_SEVERITY.get(sev_raw.upper(), "AMBER")

            # CVSS
            cvss_score = None
            cvss_data = vuln.get("CVSS", {})
            for _, score_data in cvss_data.items():
                if "V3Score" in score_data:
                    try:
                        cvss_score = float(score_data["V3Score"])
                    except (TypeError, ValueError):
                        pass
                    break

            fixed_version = vuln.get("FixedVersion")
            pkg_name = vuln.get("PkgName", "")
            remediation = (
                f"Upgrade {pkg_name} to version {fixed_version}"
                if fixed_version
                else f"Update {pkg_name} to the latest version"
            )
            refs = vuln.get("References", [])[:5]

            key = f"trivy_vuln_{(cve_id or 'unknown').lower().replace('-', '_')[:50]}"
            normalized.append(
                _base_finding(
                    key=key,
                    title=title,
                    severity=severity,
                    description=desc,
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    affected_file=target or pkg_name,
                    remediation=remediation,
                    references=refs,
                    source=source,
                    raw=vuln,
                )
            )

        # Misconfigurations
        for misc in result.get("Misconfigurations", []) or []:
            sev_raw = misc.get("Severity", "UNKNOWN")
            severity = _TRIVY_SEVERITY.get(sev_raw.upper(), "AMBER")
            title = misc.get("Title") or misc.get("Type") or "Misconfiguration"
            desc = misc.get("Description") or misc.get("Message") or title
            refs = [misc.get("PrimaryURL")] if misc.get("PrimaryURL") else []
            key = (
                f"trivy_misc_{misc.get('ID', 'unknown').lower().replace('-', '_')[:50]}"
            )

            normalized.append(
                _base_finding(
                    key=key,
                    title=title,
                    severity=severity,
                    description=desc,
                    affected_file=target,
                    references=[r for r in refs if r],
                    remediation=misc.get("Resolution")
                    or "Apply recommended security configuration.",
                    source=source,
                    raw=misc,
                )
            )

    logger.info(f"Trivy: normalized {len(normalized)} findings")
    return normalized


# ── Semgrep JSON Parser ───────────────────────────────────────────────────────


def _normalize_semgrep(data: dict, source: str = "semgrep") -> list[dict]:
    """Parse Semgrep JSON output (semgrep --json)."""
    normalized: list[dict] = []
    results = data.get("results", [])

    for result in results:
        rule_id = result.get("check_id", "unknown")
        message = result.get("extra", {}).get("message", "")
        metadata = result.get("extra", {}).get("metadata", {})
        sev_raw = result.get("extra", {}).get("severity", "WARNING")
        severity = _SEMGREP_SEVERITY.get(sev_raw.upper(), "AMBER")

        title = (
            metadata.get("cwe", [rule_id])[0]
            if isinstance(metadata.get("cwe"), list)
            else rule_id
        )
        refs = metadata.get("references", [])
        if isinstance(refs, str):
            refs = [refs]

        cwe_list = metadata.get("cwe", [])
        cve_id = None
        if isinstance(cwe_list, list):
            for cwe in cwe_list:
                if isinstance(cwe, str) and "CVE-" in cwe:
                    match = re.search(r"CVE-\d{4}-\d+", cwe)
                    if match:
                        cve_id = match.group(0)
                        break

        path = result.get("path", "")
        start = result.get("start", {})
        line = start.get("line")
        key = f"semgrep_{rule_id[:60].lower().replace('/', '_').replace('.', '_')}"

        normalized.append(
            _base_finding(
                key=key,
                title=title,
                severity=severity,
                description=message,
                cve_id=cve_id,
                affected_file=path,
                affected_line=line,
                references=[r for r in refs if r],
                remediation=metadata.get("fix", metadata.get("message", "")),
                source=source,
                raw=result,
            )
        )

    logger.info(f"Semgrep: normalized {len(normalized)} findings")
    return normalized


# ── Generic Format Parser ─────────────────────────────────────────────────────


def _normalize_generic(data: Any, source: str = "generic") -> list[dict]:
    """
    Passthrough normalizer for the generic ShieldCheck finding array format.

    Expects a list of dicts with at minimum: key, severity, detail.
    """
    if isinstance(data, dict):
        data = data.get("findings", [data])
    if not isinstance(data, list):
        return []

    normalized = []
    for item in data:
        if not isinstance(item, dict):
            continue
        key = item.get("key") or item.get("check_type") or "generic_finding"
        severity = item.get("severity", "AMBER")
        detail = (
            item.get("detail")
            or item.get("description")
            or item.get("title")
            or "Security Finding"
        )
        title = item.get("title") or detail[:80]

        normalized.append(
            _base_finding(
                key=key,
                title=title,
                severity=severity,
                description=detail,
                cve_id=item.get("cve_id"),
                cvss_score=item.get("cvss_score"),
                affected_file=item.get("affected_file") or item.get("url"),
                affected_line=item.get("affected_line"),
                remediation=item.get("fix_action") or item.get("remediation"),
                references=item.get("references", []),
                source=source,
                raw=item,
            )
        )

    logger.info(f"Generic: normalized {len(normalized)} findings")
    return normalized


# ── Main Entrypoint ───────────────────────────────────────────────────────────


def normalize_findings(
    raw_data: Any,
    format: Format,
    source: str = "external",
) -> list[dict]:
    """
    Normalize third-party scanner output into ShieldCheck internal format.

    Args:
        raw_data: Parsed JSON from scanner (dict or list)
        format: One of Format.SARIF, Format.SNYK, Format.TRIVY, Format.SEMGREP, Format.GENERIC
        source: Source label (e.g. "semgrep", "snyk", "trivy", "codeql")

    Returns:
        List of normalized finding dicts compatible with ShieldCheck RiskItem schema
    """
    if format == Format.SARIF:
        return _normalize_sarif(raw_data, source)
    elif format == Format.SNYK:
        return _normalize_snyk(raw_data, source)
    elif format == Format.TRIVY:
        return _normalize_trivy(raw_data, source)
    elif format == Format.SEMGREP:
        return _normalize_semgrep(raw_data, source)
    else:
        return _normalize_generic(raw_data, source)
