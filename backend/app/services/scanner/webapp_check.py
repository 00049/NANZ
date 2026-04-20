"""
Domain 5: Web Application Security.

Integrates: Mozilla Observatory API, Nuclei (passive mode), WhatWeb,
and sensitive file exposure checks.

All checks are PASSIVE — no POST requests to target, no form submission,
no payload injection.
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

import httpx

from app.config import settings
from app.utils.subprocess_runner import run_safe_subprocess, is_tool_available
from app.utils.nuclei_parser import parse_nuclei_output

logger = logging.getLogger(__name__)

USER_AGENT = "ShieldCheck-Scanner/2.0 (+https://shieldcheck.in/bot)"

# Sensitive files to check (passive GET only)
SENSITIVE_FILES = [
    {"path": "/.git/config", "severity": "CRITICAL", "description": "Git repository config exposed — source code leak"},
    {"path": "/.env", "severity": "CRITICAL", "description": "Environment file exposed — credentials leak"},
    {"path": "/wp-config.php", "severity": "CRITICAL", "description": "WordPress config exposed — DB credentials leak"},
    {"path": "/backup.zip", "severity": "CRITICAL", "description": "Backup archive exposed"},
    {"path": "/backup.sql", "severity": "CRITICAL", "description": "Database dump exposed"},
    {"path": "/dump.sql", "severity": "CRITICAL", "description": "Database dump exposed"},
    {"path": "/.htaccess", "severity": "RED", "description": "Server config file exposed"},
    {"path": "/phpinfo.php", "severity": "RED", "description": "PHP info page exposed — leaks server details"},
    {"path": "/server-status", "severity": "RED", "description": "Apache server status exposed"},
    {"path": "/adminer.php", "severity": "RED", "description": "Database admin tool exposed"},
    {"path": "/phpmyadmin/", "severity": "RED", "description": "phpMyAdmin panel exposed"},
    {"path": "/robots.txt", "severity": "INFO", "description": "Robots.txt present"},
    {"path": "/sitemap.xml", "severity": "INFO", "description": "Sitemap present"},
    {"path": "/.well-known/security.txt", "severity": "INFO", "description": "Security contact file present"},
]


@dataclass
class MozillaObservatoryResult:
    """Result from Mozilla HTTP Observatory API."""

    grade: Optional[str] = None
    score: Optional[int] = None
    tests_passed: int = 0
    tests_failed: int = 0
    scan_id: Optional[int] = None
    test_results: list[dict] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class NucleiScanResult:
    """Result from Nuclei passive scan."""

    findings_count: int = 0
    findings: list[dict] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class TechFingerprint:
    """Technology detected via WhatWeb."""

    name: str
    version: Optional[str] = None
    category: Optional[str] = None


@dataclass
class ExposedFile:
    """A sensitive file found to be publicly accessible."""

    path: str
    severity: str
    description: str
    status_code: int
    content_snippet: Optional[str] = None


@dataclass
class WebAppResult:
    """Complete web application security scan result."""

    # Mozilla Observatory
    observatory: Optional[dict] = None

    # Nuclei findings
    nuclei_findings: list[dict] = field(default_factory=list)
    nuclei_count: int = 0

    # Technology fingerprinting
    technologies: list[dict] = field(default_factory=list)

    # Exposed sensitive files
    exposed_files: list[dict] = field(default_factory=list)
    critical_exposures: int = 0

    # Informational files
    has_robots_txt: bool = False
    robots_disallowed: list[str] = field(default_factory=list)
    has_sitemap: bool = False
    has_security_txt: bool = False

    # Error
    error: Optional[str] = None


async def _check_mozilla_observatory(domain: str) -> MozillaObservatoryResult:
    """Query Mozilla HTTP Observatory API for security grade."""
    result = MozillaObservatoryResult()

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            # Trigger analysis
            analyze_res = await client.post(
                f"https://http-observatory.security.mozilla.org/api/v1/analyze?host={domain}",
                data={"hidden": "true", "rescan": "false"},
            )

            if analyze_res.status_code != 200:
                result.error = f"Observatory API error: {analyze_res.status_code}"
                return result

            data = analyze_res.json()
            result.grade = data.get("grade")
            result.score = data.get("score")
            result.scan_id = data.get("scan_id")

            state = data.get("state", "")
            if state == "FINISHED":
                result.tests_passed = data.get("tests_passed", 0)
                result.tests_failed = data.get("tests_failed", 0)

                # Get detailed test results
                if result.scan_id:
                    test_res = await client.get(
                        f"https://http-observatory.security.mozilla.org/api/v1/getScanResults?scan={result.scan_id}"
                    )
                    if test_res.status_code == 200:
                        tests = test_res.json()
                        for test_name, test_data in tests.items():
                            result.test_results.append({
                                "name": test_name,
                                "pass": test_data.get("pass", False),
                                "score_modifier": test_data.get("score_modifier", 0),
                                "result": test_data.get("result", ""),
                            })
            elif state in ("PENDING", "STARTING", "RUNNING"):
                # Wait and retry once
                await asyncio.sleep(5)
                retry_res = await client.get(
                    f"https://http-observatory.security.mozilla.org/api/v1/analyze?host={domain}"
                )
                if retry_res.status_code == 200:
                    retry_data = retry_res.json()
                    result.grade = retry_data.get("grade")
                    result.score = retry_data.get("score")

    except Exception as e:
        logger.warning(f"Mozilla Observatory check failed for {domain}: {e}")
        result.error = str(e)

    return result


async def _run_nuclei_scan(url: str) -> NucleiScanResult:
    """Run Nuclei in passive mode with safe templates only."""
    result = NucleiScanResult()

    if not is_tool_available("nuclei"):
        result.error = "Nuclei not installed"
        return result

    try:
        # Build safe command — ONLY passive, safe template categories
        command = [
            "nuclei",
            "-u", url,
            "-t", "technologies/",
            "-t", "exposures/",
            "-t", "misconfigurations/",
            "-t", "takeovers/",
            "-severity", "info,low,medium,high",
            "-no-interactsh",
            "-json",
            "-timeout", "10",
            "-silent",
        ]

        proc_result = await run_safe_subprocess(
            command, timeout=45.0, tool_name="nuclei"
        )

        if proc_result.error:
            result.error = proc_result.error
            return result

        findings = parse_nuclei_output(proc_result.stdout)
        result.findings_count = len(findings)
        result.findings = [
            {
                "template_id": f.template_id,
                "name": f.template_name,
                "severity": f.severity,
                "matched_url": f.matched_url,
                "description": f.description[:200],
                "tags": f.tags[:5],
            }
            for f in findings
        ]

    except Exception as e:
        logger.warning(f"Nuclei scan failed for {url}: {e}")
        result.error = str(e)

    return result


async def _run_whatweb(url: str) -> list[TechFingerprint]:
    """Run WhatWeb for technology fingerprinting."""
    techs: list[TechFingerprint] = []

    if not is_tool_available("whatweb"):
        return techs

    try:
        proc_result = await run_safe_subprocess(
            ["whatweb", "--no-errors", "-a", "1", "--log-json=-", url],
            timeout=15.0,
            tool_name="whatweb",
        )

        if proc_result.error or not proc_result.stdout:
            return techs

        for line in proc_result.stdout.strip().splitlines():
            try:
                data = json.loads(line)
                plugins = data.get("plugins", {})
                for plugin_name, plugin_data in plugins.items():
                    if plugin_name in ("IP", "Country", "HTTPServer"):
                        continue
                    version = None
                    if isinstance(plugin_data, dict):
                        version_list = plugin_data.get("version", [])
                        if version_list:
                            version = version_list[0] if isinstance(version_list, list) else str(version_list)
                    techs.append(TechFingerprint(
                        name=plugin_name,
                        version=version,
                    ))
            except json.JSONDecodeError:
                continue

    except Exception as e:
        logger.warning(f"WhatWeb failed for {url}: {e}")

    return techs


async def _check_sensitive_files(url: str) -> tuple[list[ExposedFile], dict]:
    """Check for publicly accessible sensitive files via GET requests."""
    exposed: list[ExposedFile] = []
    info = {"has_robots_txt": False, "robots_disallowed": [], "has_sitemap": False, "has_security_txt": False}

    # Normalize base URL
    base_url = url.rstrip("/")

    async with httpx.AsyncClient(
        timeout=5.0, follow_redirects=True, verify=False
    ) as client:
        for file_info in SENSITIVE_FILES:
            try:
                check_url = f"{base_url}{file_info['path']}"
                res = await client.get(check_url, headers={"User-Agent": USER_AGENT})

                if file_info["path"] == "/robots.txt" and res.status_code == 200:
                    info["has_robots_txt"] = True
                    # Parse disallowed paths
                    for line in res.text.splitlines():
                        if line.strip().lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path:
                                info["robots_disallowed"].append(path)
                    continue

                if file_info["path"] == "/sitemap.xml" and res.status_code == 200:
                    info["has_sitemap"] = True
                    continue

                if file_info["path"] == "/.well-known/security.txt" and res.status_code == 200:
                    info["has_security_txt"] = True
                    continue

                # For actual sensitive files, check if truly exposed
                if res.status_code == 200 and file_info["severity"] != "INFO":
                    content = res.text[:500]
                    # Basic validation to avoid false positives on custom 404 pages
                    if _is_likely_real_content(file_info["path"], content, res):
                        exposed.append(ExposedFile(
                            path=file_info["path"],
                            severity=file_info["severity"],
                            description=file_info["description"],
                            status_code=res.status_code,
                            content_snippet=content[:100],
                        ))

            except Exception:
                continue

    return exposed, info


def _is_likely_real_content(path: str, content: str, response: httpx.Response) -> bool:
    """Basic heuristic to avoid false positives from custom 404 pages."""
    # Check content length — very short responses are likely custom error pages
    if len(content.strip()) < 10:
        return False

    # Check for common 404 indicators in the content
    not_found_indicators = ["not found", "404", "page not found", "does not exist"]
    content_lower = content.lower()
    if any(indicator in content_lower for indicator in not_found_indicators):
        return False

    # File-specific content validation
    if path == "/.git/config":
        return "[core]" in content or "[remote" in content
    if path == "/.env":
        return "=" in content and any(k in content.upper() for k in ["DB_", "API_", "SECRET", "PASSWORD", "KEY"])
    if path == "/phpinfo.php":
        return "phpinfo" in content.lower() or "PHP Version" in content
    if path.endswith(".sql"):
        return any(kw in content.upper() for kw in ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "-- MySQL"])

    # Default: accept if content type suggests file content (not HTML error page)
    content_type = response.headers.get("content-type", "").lower()
    if "text/html" in content_type and path not in ("/phpmyadmin/", "/adminer.php", "/server-status"):
        # HTML response for non-HTML files is likely a custom 404
        return False

    return True


async def run(url: str, domain: str) -> WebAppResult:
    """Run all web application security checks concurrently."""
    result = WebAppResult()

    try:
        # Run all checks concurrently
        observatory_task = _check_mozilla_observatory(domain)
        nuclei_task = _run_nuclei_scan(url)
        whatweb_task = _run_whatweb(url)
        sensitive_task = _check_sensitive_files(url)

        observatory, nuclei, techs, (exposed, info) = await asyncio.gather(
            observatory_task, nuclei_task, whatweb_task, sensitive_task,
            return_exceptions=False,
        )

        # Observatory
        if isinstance(observatory, MozillaObservatoryResult):
            result.observatory = {
                "grade": observatory.grade,
                "score": observatory.score,
                "tests_passed": observatory.tests_passed,
                "tests_failed": observatory.tests_failed,
                "test_results": observatory.test_results[:10],
                "error": observatory.error,
            }

        # Nuclei
        if isinstance(nuclei, NucleiScanResult):
            result.nuclei_findings = nuclei.findings
            result.nuclei_count = nuclei.findings_count

        # WhatWeb techs
        if isinstance(techs, list):
            result.technologies = [
                {"name": t.name, "version": t.version, "category": t.category}
                for t in techs
            ]

        # Exposed files
        if isinstance(exposed, list):
            result.exposed_files = [
                {
                    "path": f.path,
                    "severity": f.severity,
                    "description": f.description,
                    "status_code": f.status_code,
                }
                for f in exposed
            ]
            result.critical_exposures = sum(1 for f in exposed if f.severity == "CRITICAL")

        # Informational
        if isinstance(info, dict):
            result.has_robots_txt = info.get("has_robots_txt", False)
            result.robots_disallowed = info.get("robots_disallowed", [])
            result.has_sitemap = info.get("has_sitemap", False)
            result.has_security_txt = info.get("has_security_txt", False)

    except Exception as e:
        logger.error(f"WebApp check failed for url={url}: {e}", exc_info=True)
        result.error = str(e)

    return result
