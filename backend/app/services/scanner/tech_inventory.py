"""
Technology Inventory Check.

Consolidates technologies, matches against an End-of-Life (EOL) matrix, 
and lists analytics trackers.
"""

import httpx
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import re

logger = logging.getLogger(__name__)

EOL_MATRIX = {
    "php": {"7.4": "EOL", "8.0": "EOL", "8.1": "Supported", "8.2": "Supported", "8.3": "Supported"},
    "python": {"2.7": "EOL", "3.6": "EOL", "3.7": "EOL", "3.8": "Supported", "3.9": "Supported", "3.10": "Supported", "3.11": "Supported", "3.12": "Supported"},
    "jquery": {"1.": "EOL", "2.": "EOL", "3.": "Supported"},
    "react": {"15.": "EOL", "16.": "Supported", "17.": "Supported", "18.": "Supported"},
    "angular": {"1.": "EOL", "v2": "EOL"},
    "vue": {"1.": "EOL", "2.": "EOL", "3.": "Supported"},
    "bootstrap": {"2.": "EOL", "3.": "EOL", "4.": "Supported", "5.": "Supported"},
    "wordpress": {"4.": "EOL", "5.": "EOL", "6.": "Supported"}
}

ANALYTICS_TRACKERS = {
    "Google Analytics": r"google-analytics\.com/analytics\.js|googletagmanager\.com/gtag/js",
    "Facebook Pixel": r"connect\.facebook\.net/.*/fbevents\.js",
    "Hotjar": r"static\.hotjar\.com/c/hotjar-",
    "Mixpanel": r"cdn\.mxpnl\.com/libs/mixpanel",
    "Segment": r"cdn\.segment\.com/analytics\.js",
    "Matomo": r"matomo\.js|piwik\.js",
    "HubSpot": r"js\.hs-scripts\.com/",
    "Plausible": r"plausible\.io/js/script\.js",
    "Fathom": r"cdn\.usefathom\.com/script\.js",
    "PostHog": r"us\.i\.posthog\.com/static/array\.js"
}

@dataclass
class TechInventoryResult:
    technologies: list[dict] = field(default_factory=list)
    trackers: list[str] = field(default_factory=list)
    eol_technologies: list[dict] = field(default_factory=list)
    total_tech_found: int = 0
    error: Optional[str] = None


async def _extract_tech_from_headers(headers: httpx.Headers, result: TechInventoryResult):
    server = headers.get("server", "").lower()
    if server:
        version = ""
        if "/" in server:
            parts = server.split("/", 1)
            name = parts[0]
            version = parts[1].split()[0]
        else:
            name = server
            
        result.technologies.append({
            "name": name.capitalize(),
            "type": "Web Server",
            "version": version
        })
        
    x_powered_by = headers.get("x-powered-by", "").lower()
    if x_powered_by:
        version = ""
        name = x_powered_by
        if "php" in x_powered_by:
            name = "PHP"
            parts = x_powered_by.split("/")
            if len(parts) > 1:
                version = parts[1]
        elif "express" in x_powered_by:
            name = "Express.js"
        elif "next.js" in x_powered_by:
            name = "Next.js"
            
        result.technologies.append({
            "name": name,
            "type": "Backend Framework/Language",
            "version": version
        })


async def _analyze_html(html: str, result: TechInventoryResult):
    soup = BeautifulSoup(html, "html.parser")
    
    # Check meta tags for generators
    for meta in soup.find_all("meta", attrs={"name": "generator"}):
        content = meta.get("content", "").lower()
        if content:
            version = ""
            name = content
            if "wordpress" in content:
                name = "WordPress"
                match = re.search(r"wordpress (\d+\.\d+(\.\d+)?)", content)
                if match:
                    version = match.group(1)
            elif "drupal" in content:
                name = "Drupal"
                match = re.search(r"drupal (\d+)", content)
                if match:
                    version = match.group(1)
            elif "joomla" in content:
                name = "Joomla"
                
            result.technologies.append({
                "name": name,
                "type": "CMS",
                "version": version
            })

    # Check for trackers in script src
    scripts = [s.get("src", "") for s in soup.find_all("script") if s.get("src")]
    for tracker_name, regex in ANALYTICS_TRACKERS.items():
        pattern = re.compile(regex)
        for script in scripts:
            if pattern.search(script):
                result.trackers.append(tracker_name)
                break
                
    # Detect frontend libraries
    for script in scripts:
        if "jquery" in script.lower():
            match = re.search(r"jquery[-.]?(\d+\.\d+\.\d+)", script.lower())
            version = match.group(1) if match else ""
            result.technologies.append({"name": "jQuery", "type": "JavaScript Library", "version": version})
        elif "bootstrap" in script.lower():
            match = re.search(r"bootstrap(?:[-.]min)?(?:[-.]js)?@(\d+\.\d+\.\d+)", script.lower())
            if not match:
                match = re.search(r"bootstrap/(\d+\.\d+\.\d+)", script.lower())
            version = match.group(1) if match else ""
            result.technologies.append({"name": "Bootstrap", "type": "UI Framework", "version": version})
        elif "react" in script.lower():
            result.technologies.append({"name": "React", "type": "JavaScript Framework", "version": ""})
        elif "vue" in script.lower():
            result.technologies.append({"name": "Vue.js", "type": "JavaScript Framework", "version": ""})


def _check_eol(result: TechInventoryResult):
    for tech in result.technologies:
        name_key = tech["name"].lower()
        version = tech.get("version", "")
        
        if not version or name_key not in EOL_MATRIX:
            continue
            
        matrix = EOL_MATRIX[name_key]
        for v_prefix, status in matrix.items():
            if version.startswith(v_prefix):
                if status == "EOL":
                    result.eol_technologies.append({
                        "name": tech["name"],
                        "version": version,
                        "status": status,
                        "risk": f"{tech['name']} {version} is End of Life and no longer receives security updates."
                    })
                break


async def run(domain: str) -> TechInventoryResult:
    """Run technology inventory analysis."""
    result = TechInventoryResult()
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            res = await client.get(f"https://{domain}")
            
            await _extract_tech_from_headers(res.headers, result)
            await _analyze_html(res.text, result)
            
            # Deduplicate
            seen = set()
            unique_tech = []
            for t in result.technologies:
                key = f"{t['name']}-{t['version']}"
                if key not in seen:
                    seen.add(key)
                    unique_tech.append(t)
            result.technologies = unique_tech
            result.trackers = list(set(result.trackers))
            
            _check_eol(result)
            
            result.total_tech_found = len(result.technologies)
            
    except Exception as e:
        logger.error(f"Tech inventory failed for {domain}: {e}", exc_info=True)
        result.error = "Tech inventory check failed"
        
    return result
