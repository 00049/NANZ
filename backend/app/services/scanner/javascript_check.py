"""
JavaScript & HTML Source Analysis Module — passive client-side security checks.

Checks: hardcoded secrets, source maps, outdated JS libraries, debug code,
mixed content, inline event handlers.

SECURITY: Never logs or stores actual secret values — only pattern type and location.
"""

import re
import logging
import httpx
from dataclasses import dataclass, field
from typing import Optional
from html.parser import HTMLParser

logger = logging.getLogger(__name__)

# Secret detection patterns — NEVER log the matched value
SECRET_PATTERNS = {
    "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "stripe_key": re.compile(r'(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}'),
    "google_api_key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "private_key": re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),
    "generic_password": re.compile(r'password\s*[:=]\s*["\'][^"\']{6,}["\']', re.IGNORECASE),
    "internal_ip": re.compile(r'(?:^|["\'\s,;])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:["\'\s,;]|$)'),
    "generic_api_key": re.compile(r'(?:api[_-]?key|apikey|api_secret|secret_key)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,45})["\']', re.IGNORECASE),
}

# Outdated library detection
LIBRARY_PATTERNS = {
    "jQuery": {
        "pattern": re.compile(r'jquery[/\-\.](\d+\.\d+\.\d+)', re.IGNORECASE),
        "eol_version": "3.0.0",
        "severity": "RED",
    },
    "Bootstrap": {
        "pattern": re.compile(r'bootstrap[/\-\.](\d+\.\d+\.\d+)', re.IGNORECASE),
        "eol_version": "4.0.0",
        "severity": "AMBER",
    },
    "Angular": {
        "pattern": re.compile(r'angular[/\-\.](\d+)\.\d+', re.IGNORECASE),
        "eol_version": "12",
        "severity": "AMBER",
    },
    "Moment.js": {
        "pattern": re.compile(r'moment(?:\.min)?\.js', re.IGNORECASE),
        "eol_version": None,  # all versions deprecated
        "severity": "INFO",
    },
    "Prototype.js": {
        "pattern": re.compile(r'prototype(?:\.min)?\.js', re.IGNORECASE),
        "eol_version": None,
        "severity": "AMBER",
    },
    "Lodash": {
        "pattern": re.compile(r'lodash[/\-\.](\d+\.\d+\.\d+)', re.IGNORECASE),
        "eol_version": "4.17.0",
        "severity": "AMBER",
    },
}

MAX_JS_FILE_SIZE = 200 * 1024  # 200KB
MAX_JS_FILES = 3


@dataclass
class JavaScriptResult:
    secrets_found: list[dict] = field(default_factory=list)
    source_maps_exposed: list[str] = field(default_factory=list)
    outdated_libraries: list[dict] = field(default_factory=list)
    has_debug_code: bool = False
    debug_count: int = 0
    mixed_content_urls: list[str] = field(default_factory=list)
    inline_handlers_count: int = 0
    js_files_analyzed: int = 0
    error: Optional[str] = None


class _ScriptExtractor(HTMLParser):
    """Extract inline scripts and external JS file URLs from HTML."""

    def __init__(self):
        super().__init__()
        self.inline_scripts: list[str] = []
        self.external_js: list[str] = []
        self.src_urls: list[str] = []
        self.inline_handlers: int = 0
        self._in_script = False
        self._current_script = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "script":
            src = attr_dict.get("src", "")
            if src and src.endswith((".js", ".min.js")) or ".js?" in src:
                self.external_js.append(src)
            else:
                self._in_script = True
                self._current_script = []

        # Track all src/href for mixed content analysis
        for attr_name in ("src", "href", "action"):
            val = attr_dict.get(attr_name, "")
            if val and not val.startswith(("#", "javascript:", "data:", "mailto:")):
                self.src_urls.append(val)

        # Count inline event handlers
        handler_attrs = {"onclick", "onload", "onerror", "onmouseover", "onsubmit",
                         "onfocus", "onblur", "onchange", "onkeydown", "onkeyup"}
        for attr_name in attr_dict:
            if attr_name in handler_attrs:
                self.inline_handlers += 1

    def handle_data(self, data: str):
        if self._in_script:
            self._current_script.append(data)

    def handle_endtag(self, tag: str):
        if tag.lower() == "script" and self._in_script:
            self._in_script = False
            self.inline_scripts.append("".join(self._current_script))
            self._current_script = []


def _version_lt(version: str, threshold: str) -> bool:
    """Compare version strings. Returns True if version < threshold."""
    try:
        v_parts = [int(x) for x in version.split(".")[:3]]
        t_parts = [int(x) for x in threshold.split(".")[:3]]
        # Pad to same length
        while len(v_parts) < 3:
            v_parts.append(0)
        while len(t_parts) < 3:
            t_parts.append(0)
        return v_parts < t_parts
    except (ValueError, AttributeError):
        return False


def _scan_for_secrets(content: str, location: str) -> list[dict]:
    """Scan content for hardcoded secrets. Never stores matched values."""
    findings = []
    for pattern_type, regex in SECRET_PATTERNS.items():
        matches = regex.findall(content)
        if matches:
            # Map pattern type to severity
            severity = "RED"
            if pattern_type in ("aws_access_key", "private_key", "stripe_key"):
                severity = "CRITICAL"
            elif pattern_type in ("internal_ip", "generic_password"):
                severity = "AMBER"

            findings.append({
                "pattern_type": pattern_type,
                "location": location[:200],
                "match_count": len(matches),
                "severity": severity,
            })
    return findings


def _scan_for_libraries(content: str) -> list[dict]:
    """Detect outdated JavaScript libraries from content."""
    findings = []
    for lib_name, lib_info in LIBRARY_PATTERNS.items():
        match = lib_info["pattern"].search(content)
        if match:
            detected_version = match.group(1) if match.lastindex else "unknown"

            if lib_info["eol_version"] is None:
                # Library itself is deprecated (e.g., Moment.js)
                findings.append({
                    "name": lib_name,
                    "detected_version": detected_version,
                    "min_safe": "deprecated",
                    "severity": lib_info["severity"],
                })
            elif detected_version != "unknown" and _version_lt(detected_version, lib_info["eol_version"]):
                findings.append({
                    "name": lib_name,
                    "detected_version": detected_version,
                    "min_safe": lib_info["eol_version"],
                    "severity": lib_info["severity"],
                })
    return findings


def _check_mixed_content(page_url: str, src_urls: list[str]) -> list[str]:
    """Find HTTP resources loaded on an HTTPS page."""
    if not page_url.startswith("https://"):
        return []
    mixed = []
    for url in src_urls:
        if url.startswith("http://"):
            mixed.append(url[:200])
    return mixed[:10]  # Cap at 10


async def run(url: str, domain: str) -> JavaScriptResult:
    """
    Passive JavaScript and HTML source analysis.

    Fetches homepage HTML, parses inline scripts and up to 3 external JS files.
    Checks for hardcoded secrets, source maps, outdated libraries, debug code,
    mixed content, and inline event handlers.
    """
    result = JavaScriptResult()

    try:
        async with httpx.AsyncClient(
            timeout=15.0,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        ) as client:

            # Fetch homepage HTML
            res = await client.get(url)
            html = res.text

            if not html or len(html) < 50:
                return result

            # Parse HTML
            parser = _ScriptExtractor()
            try:
                parser.feed(html)
            except Exception:
                return JavaScriptResult(error="HTML parsing failed")

            result.inline_handlers_count = parser.inline_handlers

            # Mixed content check
            result.mixed_content_urls = _check_mixed_content(url, parser.src_urls)

            # Scan inline scripts for secrets and libraries
            for idx, script in enumerate(parser.inline_scripts):
                secrets = _scan_for_secrets(script, f"inline_script_{idx}")
                result.secrets_found.extend(secrets)

                libs = _scan_for_libraries(script)
                result.outdated_libraries.extend(libs)

            # Fetch and scan external JS files (max 3)
            base_url = url.rstrip("/")
            js_urls = []
            for js_src in parser.external_js[:MAX_JS_FILES]:
                if js_src.startswith("//"):
                    js_urls.append("https:" + js_src)
                elif js_src.startswith("/"):
                    js_urls.append(base_url + js_src)
                elif js_src.startswith("http"):
                    js_urls.append(js_src)
                else:
                    js_urls.append(base_url + "/" + js_src)

            for js_url in js_urls:
                try:
                    js_res = await client.get(js_url)
                    if js_res.status_code != 200:
                        continue
                    if len(js_res.content) > MAX_JS_FILE_SIZE:
                        continue

                    js_content = js_res.text
                    result.js_files_analyzed += 1

                    # Scan for secrets
                    secrets = _scan_for_secrets(js_content, js_url[:200])
                    result.secrets_found.extend(secrets)

                    # Scan for outdated libraries
                    libs = _scan_for_libraries(js_content)
                    result.outdated_libraries.extend(libs)

                    # Count debug statements
                    debug_count = len(re.findall(r'console\.(log|debug|info)\s*\(', js_content))
                    result.debug_count += debug_count

                    # Check for source map
                    map_url = js_url + ".map"
                    try:
                        map_res = await client.get(map_url)
                        if map_res.status_code == 200:
                            content_type = map_res.headers.get("content-type", "")
                            body = map_res.text[:500]
                            if "json" in content_type or '"sources"' in body or '"mappings"' in body:
                                result.source_maps_exposed.append(js_url[:200])
                    except Exception:
                        pass

                except Exception as e:
                    logger.debug(f"JS file fetch failed for {js_url}: {e}")

            # Also scan HTML source for libraries
            html_libs = _scan_for_libraries(html)
            for lib in html_libs:
                if not any(l["name"] == lib["name"] for l in result.outdated_libraries):
                    result.outdated_libraries.append(lib)

            # Check inline scripts debug count
            for script in parser.inline_scripts:
                result.debug_count += len(re.findall(r'console\.(log|debug|info)\s*\(', script))

            result.has_debug_code = result.debug_count > 10

            # Deduplicate secrets by pattern_type
            seen_patterns = set()
            unique_secrets = []
            for s in result.secrets_found:
                key = (s["pattern_type"], s["location"])
                if key not in seen_patterns:
                    seen_patterns.add(key)
                    unique_secrets.append(s)
            result.secrets_found = unique_secrets

    except Exception as e:
        logger.error(f"JavaScript check failed: {e}", exc_info=True)
        result.error = str(e)

    return result
