"""
Crawl Intelligence Check.

Parses robots.txt for sensitive paths and scans sitemap.xml for structural IDORs
or sensitive administrative endpoints.
"""

import httpx
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

SENSITIVE_KEYWORDS = [
    "admin", "login", "secret", "api", "dashboard", "portal",
    "backup", "config", "staging", "dev", "test"
]

@dataclass
class CrawlResult:
    robots_found: bool = False
    robots_disallowed_paths: list[str] = field(default_factory=list)
    robots_sensitive_exposed: list[str] = field(default_factory=list)
    sitemap_found: bool = False
    sitemap_sensitive_urls: list[str] = field(default_factory=list)
    total_urls_found: int = 0
    error: Optional[str] = None


async def _parse_robots(client: httpx.AsyncClient, domain: str, result: CrawlResult) -> None:
    url = f"https://{domain}/robots.txt"
    try:
        res = await client.get(url)
        if res.status_code == 200:
            result.robots_found = True
            lines = res.text.splitlines()
            for line in lines:
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        result.robots_disallowed_paths.append(path)
                        for keyword in SENSITIVE_KEYWORDS:
                            if keyword in path.lower():
                                result.robots_sensitive_exposed.append(path)
                                break
    except Exception as e:
        logger.debug(f"robots.txt fetch failed for {domain}: {e}")


async def _parse_sitemap(client: httpx.AsyncClient, domain: str, result: CrawlResult) -> None:
    url = f"https://{domain}/sitemap.xml"
    try:
        res = await client.get(url)
        if res.status_code == 200:
            result.sitemap_found = True
            try:
                root = ET.fromstring(res.content)
                # sitemap namespace is usually http://www.sitemaps.org/schemas/sitemap/0.9
                urls = []
                for loc in root.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc"):
                    if loc.text:
                        urls.append(loc.text)
                # Fallback without namespace
                if not urls:
                    for loc in root.findall(".//loc"):
                        if loc.text:
                            urls.append(loc.text)
                
                result.total_urls_found = len(urls)
                for u in urls:
                    for keyword in SENSITIVE_KEYWORDS:
                        if keyword in u.lower():
                            result.sitemap_sensitive_urls.append(u)
                            break
                            
                # Limit size
                result.sitemap_sensitive_urls = result.sitemap_sensitive_urls[:20]
            except ET.ParseError:
                logger.debug(f"Failed to parse sitemap XML for {domain}")
    except Exception as e:
        logger.debug(f"sitemap.xml fetch failed for {domain}: {e}")


async def run(domain: str) -> CrawlResult:
    """Run crawl intelligence analysis."""
    result = CrawlResult()
    try:
        async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=True) as client:
            await _parse_robots(client, domain, result)
            await _parse_sitemap(client, domain, result)
            
            # Deduplicate sensitive exposed
            result.robots_sensitive_exposed = list(set(result.robots_sensitive_exposed))
    except Exception as e:
        logger.error(f"Crawl intelligence failed for {domain}: {e}", exc_info=True)
        result.error = "Crawl intelligence check partially failed"
    return result
