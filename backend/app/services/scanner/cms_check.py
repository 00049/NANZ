"""
Domain 7: CMS & Software Vulnerability Scan.

Expanded: WPScan integration, multi-CMS detection (WordPress, Shopify,
Joomla, Drupal, Magento, Wix, Squarespace, Webflow), admin panel exposure,
installation file checks, tech version fingerprinting.

All checks are PASSIVE — only HTTP GET requests.
"""

import logging
import re
from dataclasses import dataclass, field

import httpx

from app.config import settings
from app.utils.subprocess_runner import is_tool_available, run_safe_subprocess
from app.utils.wpscan_parser import parse_wpscan_output

logger = logging.getLogger(__name__)

USER_AGENT = "ShieldCheck-Scanner/2.0 (+https://shieldcheck.in/bot)"

# CMS detection signatures
CMS_SIGNATURES = {
    "wordpress": {
        "html": [
            r'<meta name="generator" content="WordPress',
            r"wp-content",
            r"wp-includes",
        ],
        "headers": ["x-powered-by:wordpress"],
    },
    "shopify": {
        "html": [r"Shopify\.theme", r"cdn\.shopify\.com", r"shopify-section"],
        "headers": ["x-shopify-stage"],
    },
    "joomla": {
        "html": [
            r'<meta name="generator" content="Joomla',
            r"/media/jui/",
            r"/templates/system/",
        ],
        "headers": [],
    },
    "drupal": {
        "html": [
            r"Drupal\.settings",
            r"/sites/default/files/",
            r'<meta name="Generator" content="Drupal',
        ],
        "headers": ["x-drupal-cache", "x-generator:drupal"],
    },
    "magento": {
        "html": [r"/skin/frontend/", r"Mage\.Cookies", r"/js/mage/"],
        "headers": ["x-magento-cache"],
    },
    "wix": {
        "html": [r"wixsite\.com", r"X-Wix-", r"_wix_browser_sess"],
        "headers": ["x-wix-request-id"],
    },
    "squarespace": {
        "html": [r"squarespace\.com", r"squarespace-cdn", r"sqs-slide"],
        "headers": [],
    },
    "webflow": {
        "html": [r"webflow\.com", r"data-wf-page", r'class="w-'],
        "headers": ["x-powered-by:webflow"],
    },
}

# Admin panel paths to check
ADMIN_PATHS = [
    "/wp-admin/",
    "/wp-login.php",
    "/admin/",
    "/administrator/",
    "/backend/",
    "/manager/",
    "/panel/",
    "/cpanel/",
    "/whm/",
    "/login/",
]

# Installation files that should not be left behind
INSTALL_FILES = [
    "/install.php",
    "/setup.php",
    "/install/",
    "/upgrade.php",
    "/configuration.php~",
]

# Known latest versions (updated periodically)
KNOWN_LATEST_VERSIONS = {
    "wordpress": "6.5.3",
    "joomla": "5.1.0",
    "drupal": "10.3.0",
    "magento": "2.4.7",
}


@dataclass
class PluginVuln:
    """A vulnerable plugin/theme finding."""

    name: str
    version: str | None = None
    latest_version: str | None = None
    vulnerabilities: list[dict] = field(default_factory=list)
    outdated: bool = False


@dataclass
class CMSResult:
    """Complete CMS and software vulnerability scan result."""

    # CMS detection
    cms_type: str | None = None
    detected_version: str | None = None
    latest_known_version: str | None = None
    outdated_version: bool = False

    # Admin panel exposure
    admin_exposed: bool = False
    admin_urls_found: list[str] = field(default_factory=list)

    # Installation files
    install_files_exposed: list[str] = field(default_factory=list)

    # WordPress-specific (from WPScan)
    wp_plugins: list[dict] = field(default_factory=list)
    wp_vulnerable_plugins: int = 0
    wp_users_found: list[str] = field(default_factory=list)
    wp_readme_exposed: bool = False
    wp_core_vulnerabilities: list[dict] = field(default_factory=list)
    wp_main_theme: str | None = None

    # Tech fingerprinting
    server_software: str | None = None
    server_version: str | None = None
    php_version: str | None = None
    jquery_version: str | None = None
    framework_detected: str | None = None

    # Exposed API keys in source
    exposed_api_keys: list[str] = field(default_factory=list)

    # Error
    error: str | None = None


async def _detect_cms(
    html: str, headers: dict[str, str]
) -> tuple[str | None, str | None]:
    """Detect CMS type and version from HTML content and headers."""
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

    for cms_name, sigs in CMS_SIGNATURES.items():
        # Check HTML patterns
        for pattern in sigs["html"]:
            if re.search(pattern, html, re.IGNORECASE):
                version = _extract_version(cms_name, html)
                return cms_name, version

        # Check header patterns
        for header_sig in sigs["headers"]:
            if ":" in header_sig:
                hdr_name, hdr_val = header_sig.split(":", 1)
                if hdr_name in headers_lower and hdr_val in headers_lower[hdr_name]:
                    return cms_name, None
            elif header_sig in headers_lower:
                return cms_name, None

    return None, None


def _extract_version(cms_name: str, html: str) -> str | None:
    """Try to extract CMS version from HTML content."""
    if cms_name == "wordpress":
        match = re.search(
            r'<meta name="generator" content="WordPress ([\d.]+)"', html, re.IGNORECASE
        )
        if match:
            return match.group(1)
    elif cms_name == "joomla":
        match = re.search(
            r'<meta name="generator" content="Joomla! ([\d.]+)', html, re.IGNORECASE
        )
        if match:
            return match.group(1)
    elif cms_name == "drupal":
        match = re.search(
            r'<meta name="Generator" content="Drupal ([\d.]+)', html, re.IGNORECASE
        )
        if match:
            return match.group(1)
    return None


async def _run_wpscan(url: str) -> dict:
    """Run WPScan for WordPress sites."""
    wpscan_data = {"ran": False}

    if not is_tool_available("wpscan"):
        return wpscan_data

    try:
        command = [
            "wpscan",
            "--url",
            url,
            "--no-banner",
            "--format",
            "json",
            "--enumerate",
            "vp,vt,tt,cb,dbe,u1-5",
            "--plugins-detection",
            "passive",
        ]

        if settings.WPSCAN_API_TOKEN:
            command.extend(["--api-token", settings.WPSCAN_API_TOKEN])

        proc_result = await run_safe_subprocess(
            command, timeout=60.0, tool_name="wpscan"
        )

        if proc_result.error or not proc_result.stdout:
            return wpscan_data

        parsed = parse_wpscan_output(proc_result.stdout)
        wpscan_data["ran"] = True
        wpscan_data["version"] = parsed.wp_version
        wpscan_data["version_status"] = parsed.wp_version_status
        wpscan_data["main_theme"] = parsed.main_theme
        wpscan_data["users"] = parsed.users_found[:5]
        wpscan_data["readme_exposed"] = parsed.readme_exposed
        wpscan_data["interesting_findings"] = parsed.interesting_findings[:10]

        # Plugins with vulns
        wpscan_data["plugins"] = []
        for plugin in parsed.plugins:
            wpscan_data["plugins"].append(
                {
                    "name": plugin.name,
                    "version": plugin.version,
                    "outdated": plugin.outdated,
                    "vulns": [
                        {
                            "title": v.title,
                            "cve": v.cve,
                            "cvss_score": v.cvss_score,
                            "fixed_in": v.fixed_in,
                        }
                        for v in plugin.vulnerabilities
                    ],
                }
            )

        # Core vulnerabilities
        wpscan_data["core_vulns"] = [
            {"title": v.title, "cve": v.cve, "cvss_score": v.cvss_score}
            for v in parsed.vulnerabilities
        ]

    except Exception as e:
        logger.warning(f"WPScan failed for {url}: {e}")

    return wpscan_data


async def _check_admin_panels(client: httpx.AsyncClient, base_url: str) -> list[str]:
    """Check for exposed admin panel URLs."""
    found: list[str] = []

    for path in ADMIN_PATHS:
        try:
            res = await client.get(
                f"{base_url}{path}",
                headers={"User-Agent": USER_AGENT},
            )
            # 200 or 401/403 (exists but protected) are notable
            if res.status_code in (401, 403):
                found.append(path)
            elif res.status_code == 200:
                content = res.text.lower()
                # Validate it's not a soft 404 and actually looks like a login/admin page
                is_soft_404 = len(content.strip()) < 10 or any(
                    ind in content
                    for ind in [
                        "not found",
                        "404",
                        "page not found",
                        "does not exist",
                        "nothing found",
                    ]
                )
                if not is_soft_404 and (
                    "password" in content or "login" in content or "admin" in content
                ):
                    found.append(path)
        except Exception:
            continue

    return found


async def _check_install_files(client: httpx.AsyncClient, base_url: str) -> list[str]:
    """Check for leftover installation files."""
    found: list[str] = []

    for path in INSTALL_FILES:
        try:
            res = await client.get(
                f"{base_url}{path}",
                headers={"User-Agent": USER_AGENT},
            )
            if res.status_code == 200 and len(res.text) > 50:
                content_lower = res.text.lower()
                is_soft_404 = any(
                    ind in content_lower
                    for ind in [
                        "not found",
                        "404",
                        "page not found",
                        "does not exist",
                        "nothing found",
                    ]
                )
                if not is_soft_404 and (
                    "install" in content_lower
                    or "setup" in content_lower
                    or "database" in content_lower
                ):
                    found.append(path)
        except Exception:
            continue

    return found


def _extract_tech_versions(html: str, headers: dict[str, str]) -> dict:
    """Extract technology versions from HTML and headers."""
    tech = {}

    # PHP version from X-Powered-By
    powered_by = headers.get("x-powered-by", "")
    php_match = re.search(r"PHP/([\d.]+)", powered_by, re.IGNORECASE)
    if php_match:
        tech["php_version"] = php_match.group(1)

    # Server software and version
    server = headers.get("server", "")
    if server:
        tech["server_software"] = server.split("/")[0] if "/" in server else server
        version_match = re.search(r"/([\d.]+)", server)
        if version_match:
            tech["server_version"] = version_match.group(1)

    # jQuery version
    jquery_match = re.search(r"jquery[.-]?([\d.]+)(?:\.min)?\.js", html, re.IGNORECASE)
    if jquery_match:
        tech["jquery_version"] = jquery_match.group(1)

    # React detection
    if "react" in html.lower() or "_reactRoot" in html:
        tech["framework_detected"] = "React"
    elif "ng-app" in html or "ng-controller" in html:
        tech["framework_detected"] = "Angular"
    elif "vue" in html.lower() and ("v-bind" in html or "v-model" in html):
        tech["framework_detected"] = "Vue.js"

    return tech


def _find_exposed_keys(html: str) -> list[str]:
    """Search for exposed API keys in page source."""
    patterns = [
        (r"sk_live_[a-zA-Z0-9]{20,}", "Stripe Secret Key"),
        (r"pk_live_[a-zA-Z0-9]{20,}", "Stripe Publishable Key"),
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
    ]

    found: list[str] = []
    for pattern, label in patterns:
        if re.search(pattern, html):
            found.append(label)

    return found


async def run(url: str) -> CMSResult:
    """Run comprehensive CMS and software vulnerability scan."""
    result = CMSResult()

    try:
        async with httpx.AsyncClient(
            timeout=10.0, follow_redirects=True, verify=False
        ) as client:
            res = await client.get(url, headers={"User-Agent": USER_AGENT})
            html = res.text
            headers = {k.lower(): v for k, v in res.headers.items()}
            base_url = f"{res.url.scheme}://{res.url.host}"

            # ── CMS Detection ──
            cms_type, detected_version = await _detect_cms(html, headers)
            result.cms_type = cms_type or "unknown"
            result.detected_version = detected_version

            if cms_type and cms_type in KNOWN_LATEST_VERSIONS:
                result.latest_known_version = KNOWN_LATEST_VERSIONS[cms_type]
                if detected_version and detected_version != result.latest_known_version:
                    result.outdated_version = True

            # ── Admin Panel Check ──
            admin_urls = await _check_admin_panels(client, base_url)
            result.admin_exposed = len(admin_urls) > 0
            result.admin_urls_found = admin_urls

            # ── Installation Files ──
            result.install_files_exposed = await _check_install_files(client, base_url)

            # ── Tech Fingerprinting ──
            tech = _extract_tech_versions(html, headers)
            result.server_software = tech.get("server_software")
            result.server_version = tech.get("server_version")
            result.php_version = tech.get("php_version")
            result.jquery_version = tech.get("jquery_version")
            result.framework_detected = tech.get("framework_detected")

            # ── Exposed API Keys ──
            result.exposed_api_keys = _find_exposed_keys(html)

            # ── WordPress-specific: WPScan ──
            if result.cms_type == "wordpress":
                wpscan_data = await _run_wpscan(url)

                if wpscan_data.get("ran"):
                    if wpscan_data.get("version"):
                        result.detected_version = wpscan_data["version"]
                    result.wp_main_theme = wpscan_data.get("main_theme")
                    result.wp_users_found = wpscan_data.get("users", [])
                    result.wp_readme_exposed = wpscan_data.get("readme_exposed", False)

                    for plugin in wpscan_data.get("plugins", []):
                        result.wp_plugins.append(plugin)
                        if plugin.get("vulns"):
                            result.wp_vulnerable_plugins += 1

                    result.wp_core_vulnerabilities = wpscan_data.get("core_vulns", [])

    except Exception as e:
        logger.error(f"CMS check failed for url={url}: {e}", exc_info=True)
        result.error = str(e)

    return result
