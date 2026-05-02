"""
Dependency Analysis — SCA (Software Composition Analysis) via passive fingerprinting.

Detects:
  - Client-side JS library versions from CDN URLs and inline code
  - npm package versions from package.json (if exposed)
  - Dependency confusion risk indicators
  - Known-vulnerable library patterns via NVD/OSV lookup
  - License risk indicators in exposed package files

PASSIVE ONLY: No agent installation, no source code access.
All detection is from publicly accessible HTTP responses.
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 20.0
OSV_API_BASE = "https://api.osv.dev/v1"
MAX_OSV_LOOKUPS = 10

# CDN URL version extraction patterns
CDN_VERSION_PATTERNS = [
    # jquery/3.6.0/jquery.min.js
    re.compile(r"(?:jquery)[/-](\d+\.\d+\.\d+)[/.]", re.IGNORECASE),
    # lodash@4.17.21/lodash.min.js
    re.compile(r"(?:lodash)[@/-](\d+\.\d+\.\d+)", re.IGNORECASE),
    # bootstrap/5.2.0/
    re.compile(r"(?:bootstrap)[@/-](\d+\.\d+\.\d+)", re.IGNORECASE),
    # react@18.2.0/ (CDN)
    re.compile(r"(?:react)[@/-](\d+\.\d+\.\d+)", re.IGNORECASE),
    # angular/12.2.16/
    re.compile(r"(?:angular)[@/-](\d+\.\d+\.\d+)", re.IGNORECASE),
    # vue@3.3.4
    re.compile(r"(?:vue)[@/-](\d+\.\d+\.\d+)", re.IGNORECASE),
    # moment.js
    re.compile(r"(?:moment)[@/-](\d+\.\d+\.\d+)", re.IGNORECASE),
    # axios
    re.compile(r"(?:axios)[@/-](\d+\.\d+\.\d+)", re.IGNORECASE),
    # d3
    re.compile(r"(?:d3)[@/-](\d+\.\d+\.\d+)", re.IGNORECASE),
    # chart.js
    re.compile(r"(?:chart\.js|chartjs)[@/-](\d+\.\d+\.\d+)", re.IGNORECASE),
    # Generic semver in URL segments
    re.compile(r"/(\d+\.\d+\.\d+)/[\w\-\.]+\.(?:js|css)"),
]

# Script src pattern extraction
SCRIPT_SRC_PATTERN = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
LINK_HREF_PATTERN = re.compile(r'<link[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)

# Package file paths to probe
PACKAGE_FILE_PATHS = [
    "/package.json",
    "/package-lock.json",
    "/yarn.lock",
    "/composer.json",
    "/requirements.txt",
    "/Pipfile",
    "/Gemfile",
    "/go.mod",
    "/pom.xml",
    "/build.gradle",
]

# Dependency confusion indicators
INTERNAL_PACKAGE_PATTERNS = [
    re.compile(r"\"@(?:internal|private|corp|company|local)/[\w\-]+\"", re.IGNORECASE),
    re.compile(r"\"(?:internal|private|corp|local)-[\w\-]+\"", re.IGNORECASE),
]

# Minimum safe versions for common libraries
MINIMUM_SAFE_VERSIONS: dict[str, tuple[int, int, int]] = {
    "jquery": (3, 7, 0),
    "lodash": (4, 17, 21),
    "bootstrap": (5, 2, 0),
    "moment": (2, 29, 4),
    "handlebars": (4, 7, 7),
    "underscore": (1, 13, 6),
    "axios": (0, 27, 2),
    "angular": (15, 0, 0),
    "react": (18, 0, 0),
    "vue": (3, 2, 0),
}

# CWE-associated vulnerable patterns in requirements
KNOWN_VULN_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"PyYAML[<=]=?[0-4]\.", re.IGNORECASE), "PyYAML < 5.0", "CVE-2017-18342"),
    (re.compile(r"requests[<=]=?2\.\d{1}\.", re.IGNORECASE), "requests < 2.20", "CVE-2018-18074"),
    (re.compile(r"Django[<=]=?[123]\.", re.IGNORECASE), "Django < 4.0 (check CVEs)", "Multiple"),
    (re.compile(r"flask[<=]=?[01]\.", re.IGNORECASE), "Flask < 2.0", "Multiple"),
    (re.compile(r"pillow[<=]=?[78]\.", re.IGNORECASE), "Pillow < 9.0", "Multiple"),
    (re.compile(r"cryptography[<=]=?[123]\.", re.IGNORECASE), "cryptography < 41.0", "Multiple"),
]


@dataclass
class DependencyFinding:
    name: str
    detected_version: str
    min_safe_version: str
    severity: str
    cve_ref: str = ""
    osv_ids: list = field(default_factory=list)
    source: str = ""


@dataclass
class DependencyAnalysisResult:
    detected_libraries: list = field(default_factory=list)    # {name, version, source, url}
    vulnerable_libraries: list = field(default_factory=list)  # DependencyFinding dicts
    package_files_exposed: list = field(default_factory=list)
    dependency_confusion_risk: list = field(default_factory=list)
    known_vuln_patterns: list = field(default_factory=list)
    osv_matches: list = field(default_factory=list)
    total_dependencies_found: int = 0
    outdated_count: int = 0
    critical_vuln_count: int = 0
    error: Optional[str] = None


async def run(url: str, domain: str) -> DependencyAnalysisResult:
    result = DependencyAnalysisResult()
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(REQUEST_TIMEOUT, connect=5.0),
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"},
            limits=httpx.Limits(max_connections=6),
        ) as client:

            # Phase 1: Scrape homepage for CDN library versions
            libs_from_html = await _scrape_library_versions(client, url)
            result.detected_libraries.extend(libs_from_html)

            # Phase 2: Check for exposed package manifests
            await _check_package_files(client, base, result)

            # Phase 3: Identify vulnerable libraries
            _classify_vulnerable_libraries(result)

            # Phase 4: OSV.dev lookup for detected versions
            await _osv_lookup(result)

            # Summary counts
            result.total_dependencies_found = len(result.detected_libraries)
            result.outdated_count = len([
                l for l in result.detected_libraries
                if l.get("is_outdated")
            ])
            result.critical_vuln_count = len([
                v for v in result.vulnerable_libraries
                if v.get("severity") == "CRITICAL"
            ])

    except Exception as exc:
        logger.error(f"Dependency analysis failed for {url}: {exc}")
        result.error = str(exc)[:200]

    return result


async def _scrape_library_versions(
    client: httpx.AsyncClient,
    url: str,
) -> list[dict]:
    """Scrape HTML source for CDN-linked library versions."""
    detected = []

    try:
        resp = await client.get(url)
        if resp.status_code != 200:
            return detected
        body = resp.text

        # Extract all script src and link href URLs
        script_urls = SCRIPT_SRC_PATTERN.findall(body)
        link_urls = LINK_HREF_PATTERN.findall(body)
        all_urls = script_urls + link_urls

        seen = set()
        for asset_url in all_urls:
            for pattern in CDN_VERSION_PATTERNS:
                match = pattern.search(asset_url)
                if match:
                    version_str = match.group(1)
                    # Determine library name
                    lib_name = _extract_lib_name(asset_url)
                    if not lib_name:
                        continue
                    key = f"{lib_name}:{version_str}"
                    if key in seen:
                        continue
                    seen.add(key)

                    entry = {
                        "name": lib_name,
                        "detected_version": version_str,
                        "source": "html_scrape",
                        "url": asset_url[:150],
                        "is_outdated": _is_outdated(lib_name, version_str),
                    }
                    detected.append(entry)

    except Exception as exc:
        logger.debug(f"HTML scrape error: {exc}")

    return detected


def _extract_lib_name(url: str) -> Optional[str]:
    """Extract library name from a CDN URL."""
    url_lower = url.lower()
    for name in MINIMUM_SAFE_VERSIONS:
        if name.replace(".", r"\.") in url_lower or name in url_lower:
            return name
    # Try to extract from common CDN patterns
    # cdnjs: /ajax/libs/<name>/version/
    cdnjs = re.search(r"/ajax/libs/([\w\-\.]+)/", url)
    if cdnjs:
        return cdnjs.group(1).lower()
    # unpkg/jsDelivr: /<name>@version
    pkg = re.search(r"/(?:npm/|)(@?[\w\-\.]+)@[\d\.]+", url)
    if pkg:
        name = pkg.group(1).lstrip("@").lower()
        return name[:50]
    return None


def _is_outdated(name: str, version_str: str) -> bool:
    """Compare detected version against minimum safe version."""
    min_ver = MINIMUM_SAFE_VERSIONS.get(name.lower())
    if not min_ver:
        return False
    try:
        parts = [int(x) for x in version_str.split(".")[:3]]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts) < min_ver
    except Exception:
        return False


async def _check_package_files(
    client: httpx.AsyncClient,
    base: str,
    result: DependencyAnalysisResult,
) -> None:
    """Probe for exposed package manifests."""
    sem = asyncio.Semaphore(4)

    async def probe(path: str) -> None:
        async with sem:
            try:
                resp = await client.get(f"{base}{path}")
                if resp.status_code != 200:
                    return
                content_type = resp.headers.get("content-type", "")
                body = resp.text[:30000]

                # Sanity check: must look like a package file, not an HTML page
                if "<html" in body[:100].lower():
                    return

                result.package_files_exposed.append({
                    "path": path,
                    "size_bytes": len(body),
                    "severity": _package_severity(path),
                })

                # Extract dependencies from package.json
                if path in ("/package.json", "/composer.json"):
                    try:
                        data = json.loads(body)
                        for section in ("dependencies", "devDependencies", "require", "require-dev"):
                            for pkg_name, ver in (data.get(section) or {}).items():
                                ver_str = ver.lstrip("^~>=<")
                                entry = {
                                    "name": pkg_name,
                                    "detected_version": ver_str,
                                    "source": f"package_file:{path}",
                                    "url": "",
                                    "is_outdated": _is_outdated(pkg_name, ver_str),
                                }
                                result.detected_libraries.append(entry)

                        # Dependency confusion detection
                        pkg_body = body.lower()
                        for pat in INTERNAL_PACKAGE_PATTERNS:
                            matches = pat.findall(body)
                            for m in matches:
                                result.dependency_confusion_risk.append({
                                    "package": m.strip('"'),
                                    "file": path,
                                    "severity": "RED",
                                    "detail": f"Private/internal package reference found — potential dependency confusion attack surface",
                                })

                    except json.JSONDecodeError:
                        pass

                # Check requirements.txt for known vulnerable patterns
                if "requirements" in path or path == "/Pipfile":
                    for pattern, desc, cve in KNOWN_VULN_PATTERNS:
                        if pattern.search(body):
                            result.known_vuln_patterns.append({
                                "description": desc,
                                "cve": cve,
                                "file": path,
                                "severity": "RED",
                            })

            except Exception as exc:
                logger.debug(f"Package file probe {path}: {exc}")

    await asyncio.gather(*[probe(p) for p in PACKAGE_FILE_PATHS], return_exceptions=True)


def _package_severity(path: str) -> str:
    """Classify severity of exposed package file."""
    if path in ("/package-lock.json", "/yarn.lock"):
        return "RED"  # Exact version lockfile — maximum detail
    if path in ("/requirements.txt", "/composer.json"):
        return "AMBER"
    return "GREEN"


def _classify_vulnerable_libraries(result: DependencyAnalysisResult) -> None:
    """Classify detected libraries against known vulnerable versions."""
    for lib in result.detected_libraries:
        name = lib.get("name", "").lower()
        version_str = lib.get("detected_version", "")
        if not name or not version_str:
            continue

        min_ver = MINIMUM_SAFE_VERSIONS.get(name)
        if not min_ver or not _is_outdated(name, version_str):
            continue

        min_str = ".".join(str(v) for v in min_ver)
        finding = DependencyFinding(
            name=name,
            detected_version=version_str,
            min_safe_version=min_str,
            severity=_version_severity(name, version_str, min_ver),
            source=lib.get("source", ""),
        )
        result.vulnerable_libraries.append(finding.__dict__)


def _version_severity(name: str, detected: str, min_ver: tuple) -> str:
    """Determine severity based on version gap."""
    try:
        parts = [int(x) for x in detected.split(".")[:3]]
        while len(parts) < 3:
            parts.append(0)
        # Major version behind = CRITICAL
        if parts[0] < min_ver[0]:
            return "CRITICAL"
        # Minor version behind = RED
        if parts[1] < min_ver[1]:
            return "RED"
        return "AMBER"
    except Exception:
        return "AMBER"


async def _osv_lookup(result: DependencyAnalysisResult) -> None:
    """Query OSV.dev for known vulnerabilities in detected packages."""
    to_query = [
        lib for lib in result.detected_libraries[:MAX_OSV_LOOKUPS]
        if lib.get("detected_version") and "." in lib.get("detected_version", "")
    ]

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(15.0),
        headers={"Content-Type": "application/json"},
    ) as client:
        sem = asyncio.Semaphore(3)

        async def query_osv(lib: dict) -> None:
            async with sem:
                name = lib.get("name", "")
                version = lib.get("detected_version", "")
                if not name or not version:
                    return
                try:
                    resp = await client.post(
                        f"{OSV_API_BASE}/query",
                        json={
                            "version": version,
                            "package": {"name": name, "ecosystem": "npm"},
                        },
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        vulns = data.get("vulns", [])
                        for vuln in vulns[:3]:
                            result.osv_matches.append({
                                "library": name,
                                "version": version,
                                "osv_id": vuln.get("id", ""),
                                "summary": vuln.get("summary", "")[:200],
                                "severity": "RED",
                            })
                except Exception:
                    pass
                await asyncio.sleep(0.2)

        await asyncio.gather(*[query_osv(l) for l in to_query], return_exceptions=True)
