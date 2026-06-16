"""
CVE Intelligence Module — v2 with EPSS + CISA KEV Enrichment.

Maps detected technologies to specific CVEs using the NVD API
and elevates severity scores dynamically.

New in v2:
  - EPSS score + percentile from FIRST.org (see threat_intel/epss_client)
  - CISA KEV membership check (see threat_intel/kev_client)
  - actively_exploited flag for contextual severity override
"""

import asyncio
import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

# Base URL for NVD API v2.0
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class CVEFinding:
    cve_id: str
    description: str
    base_severity: str
    base_score: float
    vector_string: str
    # EPSS + KEV enrichment fields (added v2)
    epss_score: float | None = None
    epss_percentile: int | None = None
    in_cisa_kev: bool = False
    actively_exploited: bool = False  # True if in KEV OR epss > 0.5
    kev_entry: dict | None = None  # Full KEV metadata if available


@dataclass
class CVEResult:
    tech_name: str
    tech_version: str
    cves: list[CVEFinding] = field(default_factory=list)
    highest_severity: str = "INFO"
    error: str | None = None
    kev_count: int = 0  # How many CVEs are in CISA KEV
    epss_enriched: bool = False  # Whether EPSS data was fetched


async def _query_nvd(client: httpx.AsyncClient, keyword: str) -> list[CVEFinding]:
    """Query NVD API for CVEs matching the keyword (tech + version)."""
    # Note: NVD API without an API key is heavily rate-limited (5 requests / 30 seconds).
    # We use keywordSearch to find matches.
    cves = []
    try:
        params = {"keywordSearch": keyword, "resultsPerPage": 5}
        res = await client.get(NVD_API_URL, params=params)
        if res.status_code == 200:
            data = res.json()
            vulnerabilities = data.get("vulnerabilities", [])
            for item in vulnerabilities:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id")

                # Extract description
                descriptions = cve_data.get("descriptions", [])
                desc = next(
                    (d.get("value") for d in descriptions if d.get("lang") == "en"),
                    "No description",
                )

                # Extract metrics
                metrics = cve_data.get("metrics", {})
                cvss_data = metrics.get(
                    "cvssMetricV31", metrics.get("cvssMetricV30", [])
                )

                base_severity = "UNKNOWN"
                base_score = 0.0
                vector_string = ""

                if cvss_data and len(cvss_data) > 0:
                    primary_cvss = cvss_data[0].get("cvssData", {})
                    base_severity = primary_cvss.get("baseSeverity", "UNKNOWN")
                    base_score = primary_cvss.get("baseScore", 0.0)
                    vector_string = primary_cvss.get("vectorString", "")

                cves.append(
                    CVEFinding(
                        cve_id=cve_id,
                        description=desc,
                        base_severity=base_severity,
                        base_score=base_score,
                        vector_string=vector_string,
                    )
                )
    except Exception as e:
        logger.warning(f"Failed to query NVD for {keyword}: {e}")

    return cves


async def _enrich_cves_with_threat_intel(cves: list[CVEFinding]) -> None:
    """
    Enrich CVEFinding objects in-place with EPSS scores and CISA KEV membership.
    Degrades gracefully if threat intel services are unavailable.
    """
    if not cves:
        return

    cve_ids = [c.cve_id for c in cves if c.cve_id]
    if not cve_ids:
        return

    try:
        from app.services.threat_intel.epss_client import get_epss_batch
        from app.services.threat_intel.kev_client import get_kev_batch, get_kev_entry

        # Parallel fetch: EPSS + KEV
        epss_task = get_epss_batch(cve_ids)
        kev_task = get_kev_batch(cve_ids)
        epss_results, kev_results = await asyncio.gather(
            epss_task, kev_task, return_exceptions=True
        )

        if isinstance(epss_results, Exception):
            logger.warning(f"EPSS batch fetch error: {epss_results}")
            epss_results = {}
        if isinstance(kev_results, Exception):
            logger.warning(f"KEV batch fetch error: {kev_results}")
            kev_results = {}

        for cve_finding in cves:
            cid = cve_finding.cve_id
            if not cid:
                continue

            # Attach EPSS data
            epss_data = epss_results.get(cid, {})
            cve_finding.epss_score = epss_data.get("epss_score")
            cve_finding.epss_percentile = epss_data.get("epss_percentile")

            # Attach KEV data
            in_kev = kev_results.get(cid, False)
            cve_finding.in_cisa_kev = in_kev

            if in_kev:
                try:
                    cve_finding.kev_entry = await get_kev_entry(cid)
                except Exception:
                    pass

            # Determine actively_exploited flag
            epss = cve_finding.epss_score or 0.0
            cve_finding.actively_exploited = in_kev or epss >= 0.5

    except ImportError:
        logger.debug(
            "Threat intel clients not available — skipping EPSS/KEV enrichment"
        )
    except Exception as e:
        logger.warning(f"Threat intel enrichment failed: {e}")


async def map_cves(technologies: list[dict[str, str]]) -> dict[str, CVEResult]:
    """
    Map a list of technologies to known CVEs.
    CVE findings are enriched with EPSS scores and CISA KEV membership.
    """
    results = {}

    # We only want to query technologies with a specific version to avoid noise.
    techs_to_query = [t for t in technologies if t.get("version")]

    if not techs_to_query:
        return results

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        # To respect rate limits without a key, we limit concurrent queries
        sem = asyncio.Semaphore(2)

        async def _bounded_query(tech: dict[str, str]):
            async with sem:
                name = tech["name"].lower()
                version = tech["version"]
                keyword = f"{name} {version}"

                cves = await _query_nvd(client, keyword)

                # ── EPSS + KEV Enrichment (v2) ──────────────────────────────────
                await _enrich_cves_with_threat_intel(cves)

                highest_sev = "INFO"
                max_score = 0.0
                kev_count = 0
                epss_enriched = False

                for c in cves:
                    if c.base_score > max_score:
                        max_score = c.base_score
                        highest_sev = c.base_severity
                    if c.in_cisa_kev:
                        kev_count += 1
                    if c.epss_score is not None:
                        epss_enriched = True

                    # KEV membership always elevates to CRITICAL
                    if c.in_cisa_kev:
                        highest_sev = "CRITICAL"
                    # High EPSS (>0.5) elevates to at least RED
                    elif (
                        c.epss_score
                        and c.epss_score > 0.5
                        and highest_sev not in ("CRITICAL",)
                    ):
                        highest_sev = "HIGH"

                # Map NVD severity to our severity
                mapped_sev = "INFO"
                if highest_sev in ("CRITICAL",):
                    mapped_sev = "CRITICAL"
                elif highest_sev in ("HIGH",):
                    mapped_sev = "RED"
                elif highest_sev == "MEDIUM":
                    mapped_sev = "AMBER"

                results[keyword] = CVEResult(
                    tech_name=name,
                    tech_version=version,
                    cves=cves,
                    highest_severity=mapped_sev,
                    kev_count=kev_count,
                    epss_enriched=epss_enriched,
                )

                # Sleep briefly to avoid hitting NVD rate limit
                await asyncio.sleep(2.0)

        tasks = [
            _bounded_query(t) for t in techs_to_query[:5]
        ]  # Max 5 techs to avoid huge delays
        await asyncio.gather(*tasks, return_exceptions=True)

    return results
