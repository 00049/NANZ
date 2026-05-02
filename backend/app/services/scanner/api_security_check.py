"""
OWASP API Security Top 10 (2023) Scanner.

Discovers API endpoints and tests them against the OWASP API Top 10 2023
vulnerability categories. All tests are passive (GET requests only) unless
explicitly noted as rate limit testing.

PASSIVE CONSTRAINTS:
  - GET requests only for data retrieval tests
  - No POST/PUT/PATCH with exploit payloads
  - No authentication bypass attempts that modify state
  - Rate limit tests: sequential GETs only
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

REQUEST_TIMEOUT = 15.0
MAX_CONCURRENT = 4

# ── API endpoint discovery paths ────────────────────────────────────────────────

API_BASE_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3", "/rest",
    "/graphql", "/query",
]

OPENAPI_SPEC_PATHS = [
    "/swagger.json", "/openapi.json", "/api-docs",
    "/swagger/v1/swagger.json", "/api/swagger.json",
    "/api/openapi.json", "/api/docs/swagger.json",
    "/v1/api-docs", "/v2/api-docs",
]

SWAGGER_UI_PATHS = [
    "/swagger-ui", "/swagger-ui.html", "/redoc",
    "/api/docs", "/api/swagger", "/docs",
]

ADMIN_API_PATHS = [
    "/api/admin", "/api/admin/users", "/api/management",
    "/api/internal", "/admin/api", "/api/config",
    "/api/system", "/api/control", "/api/ops",
]

DEBUG_PATHS = [
    "/api/debug", "/api/test", "/api/health/detailed",
    "/api/status", "/debug", "/api/ping/detailed",
    "/health/details", "/metrics", "/actuator/env",
    "/actuator/beans", "/actuator/health",
]

SENSITIVE_FLOW_PATHS = [
    "/api/forgot-password", "/api/reset-password",
    "/api/register", "/api/signup", "/api/auth/register",
    "/api/checkout", "/api/purchase", "/api/payment",
    "/api/transfer", "/api/withdraw",
]

# JWT pattern: three base64url segments separated by dots
JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
)


@dataclass
class APIFinding:
    api_risk_id: str    # e.g. "API1", "API2"
    api_risk_name: str
    endpoint: str
    severity: str       # CRITICAL / RED / AMBER
    detail: str
    method: str = "GET"
    confirmed: bool = False


@dataclass
class APISecurityResult:
    openapi_spec_exposed: bool = False
    openapi_spec_path: str = ""
    swagger_ui_exposed: bool = False
    endpoints_discovered: list = field(default_factory=list)
    bola_vulnerable_endpoints: list = field(default_factory=list)
    auth_bypass_endpoints: list = field(default_factory=list)
    missing_rate_limiting: list = field(default_factory=list)
    admin_endpoints_found: list = field(default_factory=list)
    shadow_apis_detected: list = field(default_factory=list)
    api_versions: list = field(default_factory=list)
    debug_endpoints_exposed: list = field(default_factory=list)
    sensitive_endpoints_no_rate_limit: list = field(default_factory=list)
    owasp_api_findings: list = field(default_factory=list)
    error: Optional[str] = None


async def run(url: str, domain: str) -> APISecurityResult:
    result = APISecurityResult()
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(REQUEST_TIMEOUT, connect=5.0),
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)",
                     "Accept": "application/json, text/html, */*"},
            limits=httpx.Limits(max_connections=MAX_CONCURRENT),
        ) as client:

            # Discovery phase
            discovered = await _discover_api_endpoints(client, base, result)
            result.endpoints_discovered = discovered

            # Parallel security checks
            await asyncio.gather(
                _check_openapi_exposure(client, base, result),
                _check_api_auth(client, base, discovered, result),
                _check_rate_limiting(client, base, result),
                _check_admin_endpoints(client, base, result),
                _check_api_misconfiguration(client, base, result),
                _check_api_versions(client, base, result),
                _check_bola(client, base, discovered, result),
                return_exceptions=True,
            )

    except Exception as exc:
        logger.error(f"API security scan failed for {url}: {exc}")
        result.error = str(exc)[:200]

    return result


# ── API1: BOLA / IDOR ───────────────────────────────────────────────────────────

async def _check_bola(
    client: httpx.AsyncClient,
    base: str,
    discovered: list,
    result: APISecurityResult,
) -> None:
    """Test for Broken Object Level Authorization via sequential ID access."""
    id_endpoints = [ep for ep in discovered if re.search(r"/\d+$|/\d+[/?]", ep)]

    sem = asyncio.Semaphore(2)

    async def test_bola(endpoint: str) -> None:
        async with sem:
            try:
                # Try to access the endpoint as-is
                resp1 = await client.get(endpoint)
                if resp1.status_code not in (200, 201):
                    return

                # Try sequential ID
                new_endpoint = re.sub(r"/(\d+)([/?]|$)", _increment_id, endpoint)
                if new_endpoint == endpoint:
                    return

                resp2 = await client.get(new_endpoint)
                if resp2.status_code in (200, 201) and len(resp2.text) > 50:
                    result.bola_vulnerable_endpoints.append(endpoint)
                    result.owasp_api_findings.append(APIFinding(
                        api_risk_id="API1",
                        api_risk_name="Broken Object Level Authorization",
                        endpoint=endpoint,
                        severity="CRITICAL",
                        detail=f"Sequential object access returns data — BOLA/IDOR confirmed",
                        confirmed=True,
                    ).__dict__)
            except Exception:
                pass
            await asyncio.sleep(0.3)

    await asyncio.gather(*[test_bola(ep) for ep in id_endpoints[:5]], return_exceptions=True)


def _increment_id(match: re.Match) -> str:
    num = int(match.group(1))
    suffix = match.group(2)
    return f"/{num + 1}{suffix}"


# ── API2: Broken Authentication ─────────────────────────────────────────────────

async def _check_api_auth(
    client: httpx.AsyncClient,
    base: str,
    discovered: list,
    result: APISecurityResult,
) -> None:
    """Test API endpoints for authentication requirements."""
    test_endpoints = [ep for ep in discovered
                      if any(kw in ep for kw in ["/user", "/account", "/profile", "/me", "/data"])]

    # Limit to first 5 to avoid too many requests
    for endpoint in test_endpoints[:5]:
        try:
            # Test without auth header
            resp = await client.get(f"{base}{endpoint}")
            if resp.status_code == 200 and len(resp.text) > 100:
                result.auth_bypass_endpoints.append(endpoint)
                result.owasp_api_findings.append(APIFinding(
                    api_risk_id="API2",
                    api_risk_name="Broken Authentication",
                    endpoint=endpoint,
                    severity="CRITICAL",
                    detail="Endpoint returns data without any Authorization header",
                    confirmed=True,
                ).__dict__)

            # Check for API key in URL (bad practice)
            if "api_key" in resp.url.query or "apikey" in resp.url.query:
                result.owasp_api_findings.append(APIFinding(
                    api_risk_id="API2",
                    api_risk_name="Broken Authentication",
                    endpoint=endpoint,
                    severity="RED",
                    detail="API key passed in URL query string — will be logged in server logs",
                ).__dict__)

        except Exception as exc:
            logger.debug(f"Auth check {endpoint}: {exc}")
        await asyncio.sleep(0.2)


# ── API4: Rate Limiting ─────────────────────────────────────────────────────────

async def _check_rate_limiting(
    client: httpx.AsyncClient,
    base: str,
    result: APISecurityResult,
) -> None:
    """Test rate limiting by sending 20 rapid requests to key endpoints."""
    endpoints_to_test = [
        "/api/auth/login", "/api/login", "/login",
        "/api/auth", "/api/v1/auth/login",
    ]

    for endpoint in endpoints_to_test:
        try:
            rate_limited = False
            for i in range(20):
                resp = await client.get(f"{base}{endpoint}")
                if resp.status_code == 429:
                    rate_limited = True
                    break
                await asyncio.sleep(0.05)  # 50ms between requests

            if not rate_limited:
                result.missing_rate_limiting.append(endpoint)
                result.owasp_api_findings.append(APIFinding(
                    api_risk_id="API4",
                    api_risk_name="Unrestricted Resource Consumption",
                    endpoint=endpoint,
                    severity="RED",
                    detail=f"No rate limiting detected after 20 rapid requests to {endpoint}",
                ).__dict__)
        except Exception:
            pass


# ── API5: BFLA — Admin Endpoints ────────────────────────────────────────────────

async def _check_admin_endpoints(
    client: httpx.AsyncClient,
    base: str,
    result: APISecurityResult,
) -> None:
    """Check for exposed administrative endpoints."""
    sem = asyncio.Semaphore(MAX_CONCURRENT)

    async def check_admin(path: str) -> None:
        async with sem:
            try:
                resp = await client.get(f"{base}{path}")
                if resp.status_code == 200:
                    result.admin_endpoints_found.append(path)
                    result.owasp_api_findings.append(APIFinding(
                        api_risk_id="API5",
                        api_risk_name="Broken Function Level Authorization",
                        endpoint=path,
                        severity="CRITICAL",
                        detail=f"Admin endpoint returns 200 without authentication",
                        confirmed=True,
                    ).__dict__)
                elif resp.status_code == 403:
                    # 403 means it exists but is blocked — still flag it
                    result.admin_endpoints_found.append(path)
                    result.owasp_api_findings.append(APIFinding(
                        api_risk_id="API5",
                        api_risk_name="Broken Function Level Authorization",
                        endpoint=path,
                        severity="RED",
                        detail=f"Admin endpoint confirmed (403 = exists but forbidden)",
                    ).__dict__)
            except Exception:
                pass
            await asyncio.sleep(0.1)

    await asyncio.gather(*[check_admin(p) for p in ADMIN_API_PATHS], return_exceptions=True)


# ── API8: Security Misconfiguration ────────────────────────────────────────────

async def _check_api_misconfiguration(
    client: httpx.AsyncClient,
    base: str,
    result: APISecurityResult,
) -> None:
    """Check for debug endpoints and API security misconfigurations."""
    sem = asyncio.Semaphore(MAX_CONCURRENT)

    async def check_debug(path: str) -> None:
        async with sem:
            try:
                resp = await client.get(f"{base}{path}")
                if resp.status_code == 200:
                    content = resp.text[:2000]
                    # Check if it exposes internal info
                    if any(kw in content.lower() for kw in
                           ["version", "build", "environment", "config", "secret", "password", "key"]):
                        result.debug_endpoints_exposed.append(path)
                        result.owasp_api_findings.append(APIFinding(
                            api_risk_id="API8",
                            api_risk_name="Security Misconfiguration",
                            endpoint=path,
                            severity="AMBER",
                            detail=f"Debug/health endpoint exposes internal information",
                        ).__dict__)
            except Exception:
                pass
            await asyncio.sleep(0.1)

    await asyncio.gather(*[check_debug(p) for p in DEBUG_PATHS], return_exceptions=True)

    # Check sensitive flows for rate limiting
    for path in SENSITIVE_FLOW_PATHS:
        try:
            rate_limited = False
            for _ in range(10):
                resp = await client.get(f"{base}{path}")
                if resp.status_code == 429:
                    rate_limited = True
                    break
                await asyncio.sleep(0.1)

            if not rate_limited and any(
                kw in path for kw in ["forgot-password", "reset", "register", "checkout"]
            ):
                result.sensitive_endpoints_no_rate_limit.append(path)
                result.owasp_api_findings.append(APIFinding(
                    api_risk_id="API6",
                    api_risk_name="Unrestricted Access to Sensitive Business Flows",
                    endpoint=path,
                    severity="RED",
                    detail=f"Sensitive flow endpoint has no rate limiting — vulnerable to abuse",
                ).__dict__)
        except Exception:
            pass


# ── API9: Inventory — Multiple Versions ────────────────────────────────────────

async def _check_api_versions(
    client: httpx.AsyncClient,
    base: str,
    result: APISecurityResult,
) -> None:
    """Detect multiple active API versions simultaneously."""
    live_versions = []
    for path in API_BASE_PATHS:
        try:
            resp = await client.get(f"{base}{path}")
            if resp.status_code not in (404, 410):
                version_match = re.search(r"/v(\d+)", path)
                if version_match:
                    live_versions.append(f"v{version_match.group(1)}")
        except Exception:
            pass
        await asyncio.sleep(0.1)

    result.api_versions = list(set(live_versions))
    if len(live_versions) > 1:
        result.owasp_api_findings.append(APIFinding(
            api_risk_id="API9",
            api_risk_name="Improper Inventory Management",
            endpoint=", ".join(live_versions),
            severity="AMBER",
            detail=f"Multiple API versions active simultaneously: {', '.join(live_versions)} — older versions may lack security patches",
        ).__dict__)


# ── OpenAPI Spec Exposure ───────────────────────────────────────────────────────

async def _check_openapi_exposure(
    client: httpx.AsyncClient,
    base: str,
    result: APISecurityResult,
) -> None:
    """Detect exposed API documentation and spec files."""
    for path in OPENAPI_SPEC_PATHS:
        try:
            resp = await client.get(f"{base}{path}")
            if resp.status_code == 200:
                try:
                    spec = resp.json()
                    if "paths" in spec or "swagger" in spec or "openapi" in spec:
                        result.openapi_spec_exposed = True
                        result.openapi_spec_path = path
                        # Parse endpoints from spec
                        paths = spec.get("paths", {})
                        for ep_path in list(paths.keys())[:50]:
                            result.endpoints_discovered.append(ep_path)
                        result.owasp_api_findings.append(APIFinding(
                            api_risk_id="API8",
                            api_risk_name="Security Misconfiguration",
                            endpoint=path,
                            severity="AMBER",
                            detail=f"OpenAPI/Swagger spec publicly exposed at {path} — reveals full API surface",
                        ).__dict__)
                        break
                except Exception:
                    pass
        except Exception:
            pass
        await asyncio.sleep(0.1)

    for path in SWAGGER_UI_PATHS:
        try:
            resp = await client.get(f"{base}{path}")
            if resp.status_code == 200 and "swagger" in resp.text.lower():
                result.swagger_ui_exposed = True
                result.owasp_api_findings.append(APIFinding(
                    api_risk_id="API8",
                    api_risk_name="Security Misconfiguration",
                    endpoint=path,
                    severity="AMBER",
                    detail=f"Swagger UI accessible in production at {path}",
                ).__dict__)
                break
        except Exception:
            pass


# ── Endpoint Discovery ─────────────────────────────────────────────────────────

async def _discover_api_endpoints(
    client: httpx.AsyncClient,
    base: str,
    result: APISecurityResult,
) -> list[str]:
    """Discover active API endpoints from common paths and HTML/JS source."""
    discovered = set()
    sem = asyncio.Semaphore(MAX_CONCURRENT)

    async def check_path(path: str) -> None:
        async with sem:
            try:
                resp = await client.get(f"{base}{path}")
                if resp.status_code not in (404, 410, 405):
                    discovered.add(path)
            except Exception:
                pass
            await asyncio.sleep(0.05)

    probe_paths = API_BASE_PATHS + [
        "/api/users", "/api/user", "/api/me", "/api/profile",
        "/api/products", "/api/orders", "/api/items",
        "/api/auth", "/api/token", "/api/auth/login",
    ]

    await asyncio.gather(*[check_path(p) for p in probe_paths], return_exceptions=True)

    # Also scrape from homepage JS/HTML
    try:
        resp = await client.get(base)
        if resp.status_code == 200:
            # Find API calls in source
            api_refs = re.findall(r'["\']/(api/[\w/\-]+)["\']', resp.text)
            for ref in api_refs[:20]:
                discovered.add(f"/{ref}")
    except Exception:
        pass

    return list(discovered)
