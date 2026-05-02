"""
IAST Behavioral Analysis — Passive runtime vulnerability indicator detection.

True IAST requires runtime agents inside the target application.
This module implements PASSIVE IAST BEHAVIORAL ANALYSIS — detecting runtime
vulnerability indicators from the outside via:
  - Error message intelligence (probe requests)
  - Timing-based behavioral analysis
  - Information disclosure pattern matching

PASSIVE ONLY: All probes are non-malicious. No exploit payloads.
"""

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from statistics import median
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

# ── Error pattern signatures ────────────────────────────────────────────────────

STACK_TRACE_PATTERNS = [
    (re.compile(r"at\s+[\w\.]+\([\w\.]+:\d+\)", re.IGNORECASE), "Java/Kotlin stack trace"),
    (re.compile(r"NullPointerException|IllegalArgumentException|ClassNotFoundException", re.IGNORECASE), "Java exception class"),
    (re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE), "Python traceback"),
    (re.compile(r"at\s+\S+\.js:\d+:\d+", re.IGNORECASE), "Node.js stack trace"),
    (re.compile(r"RuntimeError|AttributeError|KeyError|ValueError.*File.*line \d+", re.IGNORECASE), "Python error detail"),
    (re.compile(r"System\..*Exception|StackTrace|at System\.", re.IGNORECASE), ".NET stack trace"),
    (re.compile(r"Parse error:|Fatal error:|Warning:|Notice:\s+.*in\s+/", re.IGNORECASE), "PHP error"),
    (re.compile(r"ActionController::|ActionDispatch::|NoMethodError", re.IGNORECASE), "Ruby on Rails error"),
]

DB_ERROR_PATTERNS = [
    (re.compile(r"SQLSTATE\[[\w]+\]", re.IGNORECASE), "SQL state code"),
    (re.compile(r"mysql_connect|mysqli_connect|pg_query|pg_connect", re.IGNORECASE), "DB connection function"),
    (re.compile(r"ORA-\d{5}", re.IGNORECASE), "Oracle DB error"),
    (re.compile(r"syntax error.*near|near.*syntax error", re.IGNORECASE), "SQL syntax error"),
    (re.compile(r"relation .* does not exist|table .* doesn't exist", re.IGNORECASE), "DB schema hint"),
    (re.compile(r"column .* of relation|unknown column .* in", re.IGNORECASE), "DB column name"),
    (re.compile(r"Microsoft.*SQL Server|OLE DB.*SQL", re.IGNORECASE), "MSSQL error"),
    (re.compile(r"psycopg2\.errors|asyncpg\.exceptions", re.IGNORECASE), "PostgreSQL Python error"),
]

FRAMEWORK_VERSION_PATTERNS = [
    re.compile(r"Django\s+[\d\.]+", re.IGNORECASE),
    re.compile(r"Rails\s+[\d\.]+|Ruby on Rails [\d\.]+", re.IGNORECASE),
    re.compile(r"Spring Boot [\d\.]+|Spring Framework [\d\.]+", re.IGNORECASE),
    re.compile(r"Laravel v?[\d\.]+", re.IGNORECASE),
    re.compile(r"Flask/[\d\.]+|Flask [\d\.]+", re.IGNORECASE),
    re.compile(r"Express [\d\.]+|express@[\d\.]+", re.IGNORECASE),
    re.compile(r"ASP\.NET [\d\.]+|\.NET Core [\d\.]+", re.IGNORECASE),
]

INTERNAL_IP_PATTERNS = [
    re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b127\.0\.0\.[12]\b"),
    re.compile(r"\blocalhost\b"),
]

PATH_DISCLOSURE_PATTERNS = [
    re.compile(r"/var/www/[\w/\-\.]+", re.IGNORECASE),
    re.compile(r"/home/[\w]+/[\w/\-\.]+", re.IGNORECASE),
    re.compile(r"C:\\inetpub\\[\w\\]+", re.IGNORECASE),
    re.compile(r"C:\\Users\\[\w]+\\", re.IGNORECASE),
    re.compile(r"/opt/[\w]+/[\w/\-\.]{5,}", re.IGNORECASE),
    re.compile(r"/usr/local/[\w/\-\.]+", re.IGNORECASE),
    re.compile(r"D:\\[\w\\]+\\wwwroot", re.IGNORECASE),
]

# ── Result ─────────────────────────────────────────────────────────────────────

@dataclass
class IASTBehavioralResult:
    stack_traces_found: list = field(default_factory=list)      # {url, framework, pattern, severity}
    internal_ips_in_response: list = field(default_factory=list)
    db_errors_found: list = field(default_factory=list)         # {url, pattern, snippet}
    path_disclosure: list = field(default_factory=list)
    framework_versions_disclosed: list = field(default_factory=list)
    timing_anomalies: list = field(default_factory=list)        # {probe_type, baseline_ms, probe_ms, ratio}
    error_verbosity_score: int = 0                              # 0-100 danger scale
    probes_sent: int = 0
    error: Optional[str] = None


# ── Main entry point ────────────────────────────────────────────────────────────

async def run(url: str, domain: str) -> IASTBehavioralResult:
    result = IASTBehavioralResult()
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(15.0, connect=5.0),
            follow_redirects=True,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)",
                "Accept": "text/html,application/json,*/*",
            },
            limits=httpx.Limits(max_connections=5),
        ) as client:
            await _run_error_probes(client, url, result)
            await _run_timing_analysis(client, url, result)

        result.error_verbosity_score = _compute_verbosity_score(result)

    except Exception as exc:
        logger.error(f"IAST behavioral scan failed for {url}: {exc}")
        result.error = str(exc)[:200]

    return result


# ── Error probe analysis ────────────────────────────────────────────────────────

async def _run_error_probes(client: httpx.AsyncClient, base_url: str, result: IASTBehavioralResult) -> None:
    """Send crafted non-malicious probes and analyze error responses."""
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    probes = [
        # Missing required parameter
        {"url": urljoin(base, "/?q="), "method": "GET",
         "desc": "missing_param", "extra_headers": {}},
        # Wrong content-type header
        {"url": base_url, "method": "GET",
         "desc": "wrong_content_type",
         "extra_headers": {"Content-Type": "application/xml"}},
        # Oversized header value (8 KB of A's)
        {"url": base_url, "method": "GET",
         "desc": "oversized_header",
         "extra_headers": {"X-Custom-Header": "A" * 8192}},
        # Unexpected HTTP method
        {"url": base_url, "method": "PATCH",
         "desc": "unexpected_method", "extra_headers": {}},
        # Numeric parameter edge cases
        {"url": urljoin(base, "/?id=0"), "method": "GET",
         "desc": "id_zero", "extra_headers": {}},
        {"url": urljoin(base, "/?id=-1"), "method": "GET",
         "desc": "id_negative", "extra_headers": {}},
    ]

    for probe in probes:
        try:
            result.probes_sent += 1
            method = probe["method"]
            url = probe["url"]
            headers = probe.get("extra_headers", {})

            if method == "GET":
                resp = await client.get(url, headers=headers)
            elif method == "PATCH":
                resp = await client.patch(url, headers=headers)
            else:
                continue

            body = resp.text[:8000]  # cap for analysis
            _analyze_response_body(url, body, result)

        except (httpx.TimeoutException, httpx.ConnectError):
            pass
        except Exception as exc:
            logger.debug(f"IAST probe {probe['desc']} error: {exc}")

        await asyncio.sleep(0.3)


def _analyze_response_body(url: str, body: str, result: IASTBehavioralResult) -> None:
    """Scan response body for information disclosure patterns."""

    # Stack traces
    for pattern, framework in STACK_TRACE_PATTERNS:
        if pattern.search(body):
            snippet = _extract_snippet(body, pattern)
            result.stack_traces_found.append({
                "url": url,
                "framework": framework,
                "snippet": snippet[:200],
                "severity": "CRITICAL",
            })

    # DB errors
    for pattern, db_type in DB_ERROR_PATTERNS:
        if pattern.search(body):
            snippet = _extract_snippet(body, pattern)
            result.db_errors_found.append({
                "url": url,
                "db_type": db_type,
                "snippet": snippet[:200],
                "severity": "CRITICAL",
            })

    # Framework versions
    for pattern in FRAMEWORK_VERSION_PATTERNS:
        match = pattern.search(body)
        if match:
            result.framework_versions_disclosed.append({
                "url": url,
                "version_string": match.group(0)[:80],
                "severity": "RED",
            })

    # Internal IPs
    for pattern in INTERNAL_IP_PATTERNS:
        matches = pattern.findall(body)
        for ip in matches:
            if ip not in result.internal_ips_in_response:
                result.internal_ips_in_response.append(ip)

    # File system paths
    for pattern in PATH_DISCLOSURE_PATTERNS:
        match = pattern.search(body)
        if match:
            path = match.group(0)
            if path not in result.path_disclosure:
                result.path_disclosure.append(path)


# ── Timing analysis ─────────────────────────────────────────────────────────────

async def _run_timing_analysis(client: httpx.AsyncClient, url: str, result: IASTBehavioralResult) -> None:
    """Measure response time anomalies across different probe types."""

    # Baseline — 3 samples, take median
    baseline_times = []
    for _ in range(3):
        t = await _timed_get(client, url)
        if t is not None:
            baseline_times.append(t)
        await asyncio.sleep(0.2)

    if not baseline_times:
        return

    baseline_ms = median(baseline_times)

    # Probe 1: Deep JSON nesting (DoS indicator, not exploit)
    deep_json_url = f"{url}?data=" + "{}" * 50
    deep_json_time = await _timed_get(client, deep_json_url)
    if deep_json_time and baseline_ms > 0:
        ratio = deep_json_time / baseline_ms
        if ratio > 5:
            result.timing_anomalies.append({
                "probe_type": "deep_nesting",
                "baseline_ms": round(baseline_ms),
                "probe_ms": round(deep_json_time),
                "ratio": round(ratio, 1),
                "severity": "AMBER",
                "detail": "No input depth/complexity limiting detected",
            })

    # Probe 2: Harmless sleep(0) parameter test (detects time-based injection surface)
    # SAFE: SLEEP(0) returns immediately — just tests for difference in handling
    sleep_url = f"{url}?id=1%20AND%20SLEEP(0)"
    sleep_time = await _timed_get(client, sleep_url)
    if sleep_time and baseline_ms > 0:
        diff_ms = sleep_time - baseline_ms
        if diff_ms > 10000:
            result.timing_anomalies.append({
                "probe_type": "time_based_indicator",
                "baseline_ms": round(baseline_ms),
                "probe_ms": round(sleep_time),
                "diff_ms": round(diff_ms),
                "severity": "RED",
                "detail": "Unusual response time variance — potential blind injection surface",
            })

    # Probe 3: Large parameter value
    large_param_url = f"{url}?q=" + "x" * 10000
    large_time = await _timed_get(client, large_param_url)
    if large_time and baseline_ms > 0:
        ratio = large_time / baseline_ms
        if ratio > 3:
            result.timing_anomalies.append({
                "probe_type": "large_input",
                "baseline_ms": round(baseline_ms),
                "probe_ms": round(large_time),
                "ratio": round(ratio, 1),
                "severity": "AMBER",
                "detail": "Slow processing of large inputs — possible regex ReDoS or O(n) parsing",
            })


async def _timed_get(client: httpx.AsyncClient, url: str) -> Optional[float]:
    """Return request time in ms, or None on error."""
    try:
        start = time.monotonic()
        await client.get(url)
        return (time.monotonic() - start) * 1000
    except Exception:
        return None


# ── Scoring ────────────────────────────────────────────────────────────────────

def _compute_verbosity_score(result: IASTBehavioralResult) -> int:
    """
    Compute an error verbosity danger score 0–100.
    Higher = more dangerous information disclosure.
    """
    score = 0
    score += len(result.stack_traces_found) * 20
    score += len(result.db_errors_found) * 25
    score += len(result.framework_versions_disclosed) * 10
    score += len(result.internal_ips_in_response) * 15
    score += len(result.path_disclosure) * 10
    score += len(result.timing_anomalies) * 8
    return min(100, score)


def _extract_snippet(body: str, pattern: re.Pattern) -> str:
    """Extract a 200-char context window around the first match."""
    match = pattern.search(body)
    if not match:
        return ""
    start = max(0, match.start() - 40)
    end = min(len(body), match.end() + 160)
    return body[start:end].strip()
