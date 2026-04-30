"""
CVE Intelligence Module.

Maps detected technologies to specific CVEs using the NVD API
and elevates severity scores dynamically.
"""

import httpx
import logging
import asyncio
from typing import Dict, List, Optional
from dataclasses import dataclass, field

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

@dataclass
class CVEResult:
    tech_name: str
    tech_version: str
    cves: List[CVEFinding] = field(default_factory=list)
    highest_severity: str = "INFO"
    error: Optional[str] = None


async def _query_nvd(client: httpx.AsyncClient, keyword: str) -> List[CVEFinding]:
    """Query NVD API for CVEs matching the keyword (tech + version)."""
    # Note: NVD API without an API key is heavily rate-limited (5 requests / 30 seconds).
    # We use keywordSearch to find matches.
    cves = []
    try:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 5
        }
        res = await client.get(NVD_API_URL, params=params)
        if res.status_code == 200:
            data = res.json()
            vulnerabilities = data.get("vulnerabilities", [])
            for item in vulnerabilities:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id")
                
                # Extract description
                descriptions = cve_data.get("descriptions", [])
                desc = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "No description")
                
                # Extract metrics
                metrics = cve_data.get("metrics", {})
                cvss_data = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                
                base_severity = "UNKNOWN"
                base_score = 0.0
                vector_string = ""
                
                if cvss_data and len(cvss_data) > 0:
                    primary_cvss = cvss_data[0].get("cvssData", {})
                    base_severity = primary_cvss.get("baseSeverity", "UNKNOWN")
                    base_score = primary_cvss.get("baseScore", 0.0)
                    vector_string = primary_cvss.get("vectorString", "")
                    
                cves.append(CVEFinding(
                    cve_id=cve_id,
                    description=desc,
                    base_severity=base_severity,
                    base_score=base_score,
                    vector_string=vector_string
                ))
    except Exception as e:
        logger.warning(f"Failed to query NVD for {keyword}: {e}")
        
    return cves


async def map_cves(technologies: List[Dict[str, str]]) -> Dict[str, CVEResult]:
    """Map a list of technologies to known CVEs."""
    results = {}
    
    # We only want to query technologies with a specific version to avoid noise.
    techs_to_query = [t for t in technologies if t.get("version")]
    
    if not techs_to_query:
        return results

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        # To respect rate limits without a key, we limit concurrent queries
        sem = asyncio.Semaphore(2)
        
        async def _bounded_query(tech: Dict[str, str]):
            async with sem:
                name = tech["name"].lower()
                version = tech["version"]
                keyword = f"{name} {version}"
                
                cves = await _query_nvd(client, keyword)
                
                highest_sev = "INFO"
                max_score = 0.0
                for c in cves:
                    if c.base_score > max_score:
                        max_score = c.base_score
                        highest_sev = c.base_severity
                        
                # Map NVD severity to our severity
                mapped_sev = "INFO"
                if highest_sev == "CRITICAL":
                    mapped_sev = "CRITICAL"
                elif highest_sev == "HIGH":
                    mapped_sev = "RED"
                elif highest_sev == "MEDIUM":
                    mapped_sev = "AMBER"
                    
                results[keyword] = CVEResult(
                    tech_name=name,
                    tech_version=version,
                    cves=cves,
                    highest_severity=mapped_sev
                )
                
                # Sleep briefly to avoid hitting rate limit
                await asyncio.sleep(2.0)
                
        tasks = [_bounded_query(t) for t in techs_to_query[:5]] # Max 5 techs to avoid huge delays
        await asyncio.gather(*tasks, return_exceptions=True)
        
    return results
