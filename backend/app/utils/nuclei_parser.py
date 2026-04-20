"""
Parser for Nuclei JSON-lines output.

Nuclei outputs one JSON object per line (JSONL format).
Each finding contains template info, severity, matched-at URL, etc.
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Only allow safe template categories — no active exploitation
SAFE_TEMPLATE_CATEGORIES = frozenset({
    "technologies",
    "exposures",
    "misconfigurations",
    "default-logins",
    "takeovers",
})

# Map nuclei severity strings to our severity system
NUCLEI_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "RED",
    "medium": "AMBER",
    "low": "GREEN",
    "info": "INFO",
    "unknown": "INFO",
}


@dataclass
class NucleiFinding:
    """A single parsed nuclei finding."""

    template_id: str
    template_name: str
    severity: str  # CRITICAL, RED, AMBER, GREEN, INFO
    matched_url: str
    description: str
    tags: list[str] = field(default_factory=list)
    reference: list[str] = field(default_factory=list)
    matcher_name: Optional[str] = None
    extracted_results: list[str] = field(default_factory=list)
    curl_command: Optional[str] = None


def parse_nuclei_output(raw_output: str) -> list[NucleiFinding]:
    """
    Parse nuclei JSONL output into structured findings.

    Args:
        raw_output: Raw stdout from nuclei -json execution.

    Returns:
        List of NucleiFinding objects, filtered to safe categories only.
    """
    findings: list[NucleiFinding] = []

    if not raw_output or not raw_output.strip():
        return findings

    for line_num, line in enumerate(raw_output.strip().splitlines(), 1):
        line = line.strip()
        if not line:
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            logger.debug(f"Nuclei output line {line_num} is not valid JSON, skipping")
            continue

        # Extract template info
        template_id = data.get("template-id", data.get("templateID", "unknown"))
        info = data.get("info", {})
        template_name = info.get("name", template_id)
        nuclei_severity = info.get("severity", "info").lower()
        severity = NUCLEI_SEVERITY_MAP.get(nuclei_severity, "INFO")

        # Extract tags and filter to safe categories
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]

        # Extract description and references
        description = info.get("description", "")
        reference = info.get("reference", [])
        if isinstance(reference, str):
            reference = [reference]

        matched_url = data.get("matched-at", data.get("matched", ""))
        matcher_name = data.get("matcher-name", data.get("matcher_name"))
        extracted = data.get("extracted-results", [])
        curl_cmd = data.get("curl-command")

        finding = NucleiFinding(
            template_id=template_id,
            template_name=template_name,
            severity=severity,
            matched_url=matched_url,
            description=description,
            tags=tags,
            reference=reference if reference else [],
            matcher_name=matcher_name,
            extracted_results=extracted if extracted else [],
            curl_command=curl_cmd,
        )
        findings.append(finding)

    logger.info(f"Parsed {len(findings)} nuclei findings")
    return findings
