"""
Parser for WPScan JSON output.

Extracts vulnerable plugins, themes, WordPress core version,
user enumeration results, and exposed files.
"""

import json
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class WPVulnerability:
    """A single WordPress vulnerability."""

    title: str
    vuln_type: str | None = None
    cve: str | None = None
    cvss_score: float | None = None
    fixed_in: str | None = None
    references: list[str] = field(default_factory=list)


@dataclass
class WPPlugin:
    """A detected WordPress plugin with vulnerabilities."""

    name: str
    version: str | None = None
    latest_version: str | None = None
    outdated: bool = False
    vulnerabilities: list[WPVulnerability] = field(default_factory=list)


@dataclass
class WPScanResult:
    """Complete parsed WPScan result."""

    wp_version: str | None = None
    wp_version_status: str | None = None  # "latest", "outdated", "insecure"
    main_theme: str | None = None
    theme_version: str | None = None
    plugins: list[WPPlugin] = field(default_factory=list)
    users_found: list[str] = field(default_factory=list)
    vulnerabilities: list[WPVulnerability] = field(default_factory=list)
    interesting_findings: list[str] = field(default_factory=list)
    readme_exposed: bool = False
    license_exposed: bool = False
    error: str | None = None


def parse_wpscan_output(raw_output: str) -> WPScanResult:
    """
    Parse WPScan JSON output into structured results.

    Args:
        raw_output: Raw stdout from wpscan --format json.

    Returns:
        WPScanResult with all parsed findings.
    """
    result = WPScanResult()

    if not raw_output or not raw_output.strip():
        result.error = "Empty WPScan output"
        return result

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse WPScan JSON: {e}")
        result.error = f"Invalid WPScan JSON output: {e}"
        return result

    # Parse WordPress version
    wp_version_info = data.get("version", {})
    if wp_version_info:
        result.wp_version = wp_version_info.get("number")
        status = wp_version_info.get("status", "")
        result.wp_version_status = status if status else None

        # Parse core vulnerabilities
        for vuln_data in wp_version_info.get("vulnerabilities", []):
            vuln = _parse_vulnerability(vuln_data)
            if vuln:
                result.vulnerabilities.append(vuln)

    # Parse main theme
    main_theme = data.get("main_theme", {})
    if main_theme:
        result.main_theme = main_theme.get("slug")
        result.theme_version = (
            main_theme.get("version", {}).get("number")
            if isinstance(main_theme.get("version"), dict)
            else main_theme.get("version")
        )

    # Parse plugins
    plugins_data = data.get("plugins", {})
    for plugin_slug, plugin_info in plugins_data.items():
        plugin = WPPlugin(name=plugin_slug)

        version_info = plugin_info.get("version", {})
        if isinstance(version_info, dict):
            plugin.version = version_info.get("number")
        elif isinstance(version_info, str):
            plugin.version = version_info

        plugin.latest_version = plugin_info.get("latest_version")
        plugin.outdated = plugin_info.get("outdated", False)

        for vuln_data in plugin_info.get("vulnerabilities", []):
            vuln = _parse_vulnerability(vuln_data)
            if vuln:
                plugin.vulnerabilities.append(vuln)

        result.plugins.append(plugin)

    # Parse users
    users_data = data.get("users", {})
    for username in users_data:
        result.users_found.append(username)

    # Parse interesting findings
    for finding in data.get("interesting_findings", []):
        url = finding.get("url", "")
        finding_type = finding.get("type", "")
        to_s = finding.get("to_s", "")
        entry = to_s if to_s else f"{finding_type}: {url}"
        result.interesting_findings.append(entry)

        # Check for specific exposed files
        if "readme" in url.lower():
            result.readme_exposed = True
        if "license" in url.lower():
            result.license_exposed = True

    logger.info(
        f"Parsed WPScan: version={result.wp_version}, "
        f"plugins={len(result.plugins)}, "
        f"vulns={len(result.vulnerabilities)}, "
        f"users={len(result.users_found)}"
    )
    return result


def _parse_vulnerability(vuln_data: dict) -> WPVulnerability | None:
    """Parse a single vulnerability entry from WPScan output."""
    if not vuln_data:
        return None

    title = vuln_data.get("title", "Unknown vulnerability")

    # Extract CVE
    references = vuln_data.get("references", {})
    cve_list = references.get("cve", [])
    cve = f"CVE-{cve_list[0]}" if cve_list else None

    # Extract references as flat list
    ref_urls: list[str] = []
    for ref_type, ref_values in references.items():
        if ref_type == "cve":
            ref_urls.extend(
                f"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-{c}"
                for c in ref_values
            )
        elif isinstance(ref_values, list):
            ref_urls.extend(ref_values)

    return WPVulnerability(
        title=title,
        vuln_type=vuln_data.get("vuln_type"),
        cve=cve,
        cvss_score=(
            vuln_data.get("cvss", {}).get("score")
            if isinstance(vuln_data.get("cvss"), dict)
            else None
        ),
        fixed_in=vuln_data.get("fixed_in"),
        references=ref_urls[:5],  # Limit reference count
    )
