"""
Identity & Auth Security Audit.

Detects JWT and OAuth/OIDC vulnerabilities via passive and active probing.
Checks for:
  - JWT 'none' algorithm bypass vulnerability (detects endpoints accepting alg: none).
  - JWT Algorithm Confusion (RS256 -> HS256) surface.
  - Missing OAuth PKCE enforcement.
  - Exposed sensitive JWT claims.
"""

import asyncio
import base64
import json
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 15.0

# Common OAuth endpoints
OAUTH_PATHS = [
    "/oauth/authorize",
    "/oauth2/authorize",
    "/api/oauth/authorize",
    "/api/v1/oauth/authorize",
    "/auth/realms/master/protocol/openid-connect/auth",
    "/oauth/token",
    "/oauth2/token",
]

# Simple regex for JWT tokens (Header.Payload.Signature)
JWT_PATTERN = re.compile(r"(eyJ[a-zA-Z0-9_-]+)\.(eyJ[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)")

@dataclass
class IdentityAuthResult:
    jwt_tokens_discovered: int = 0
    jwt_none_alg_vulnerable: bool = False
    jwt_algorithm_confusion_surface: bool = False
    sensitive_claims_exposed: list = field(default_factory=list)
    oauth_endpoints_discovered: list = field(default_factory=list)
    missing_pkce_endpoints: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    error: str | None = None

async def run(url: str, domain: str) -> IdentityAuthResult:
    result = IdentityAuthResult()
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(REQUEST_TIMEOUT, connect=5.0),
            follow_redirects=True,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)",
                "Accept": "application/json, text/html, */*",
            },
            limits=httpx.Limits(max_connections=4),
        ) as client:

            await asyncio.gather(
                _check_oauth_pkce(client, base, result),
                _discover_and_test_jwts(client, base, result),
                return_exceptions=True,
            )

    except Exception as exc:
        logger.error(f"Identity & Auth scan failed for {url}: {exc}")
        result.error = str(exc)[:200]

    return result

async def _check_oauth_pkce(client: httpx.AsyncClient, base: str, result: IdentityAuthResult) -> None:
    """Test OAuth/OIDC endpoints for PKCE enforcement."""
    for path in OAUTH_PATHS:
        try:
            full_url = f"{base}{path}"
            # Send an authorize request without code_challenge
            params = {
                "response_type": "code",
                "client_id": "test_client_id_scan",
                "redirect_uri": f"{base}/callback",
            }
            resp = await client.get(full_url, params=params)
            
            # If the endpoint exists (not 404) and doesn't explicitly reject due to missing PKCE
            if resp.status_code not in (404, 405, 410):
                result.oauth_endpoints_discovered.append(path)
                
                body = resp.text.lower()
                # A good implementation should return a 400 Bad Request indicating missing code_challenge
                if "code_challenge" not in body and "pkce" not in body:
                    result.missing_pkce_endpoints.append(path)
                    result.findings.append({
                        "type": "oauth_missing_pkce",
                        "endpoint": path,
                        "severity": "AMBER",
                        "detail": f"OAuth authorization endpoint at {path} does not appear to enforce PKCE (code_challenge missing error not returned).",
                    })

        except Exception:
            pass
        await asyncio.sleep(0.1)

def _decode_jwt_part(part: str) -> dict | None:
    try:
        # Add padding if needed
        part += "=" * ((4 - len(part) % 4) % 4)
        decoded = base64.urlsafe_b64decode(part).decode("utf-8")
        return json.loads(decoded)
    except Exception:
        return None

def _encode_jwt_part(data: dict) -> str:
    json_data = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(json_data).decode("utf-8").rstrip("=")

async def _discover_and_test_jwts(client: httpx.AsyncClient, base: str, result: IdentityAuthResult) -> None:
    """Discover JWTs from a standard endpoint and test for vulnerabilities."""
    probe_endpoints = ["/api/auth/token", "/api/login", "/api/user", "/"]
    jwts_found = []

    # Attempt to grab a JWT token from public or common endpoints
    for path in probe_endpoints:
        try:
            resp = await client.get(f"{base}{path}")
            if resp.status_code == 200:
                matches = JWT_PATTERN.findall(resp.text)
                for match in matches:
                    jwt_str = f"{match[0]}.{match[1]}.{match[2]}"
                    if jwt_str not in jwts_found:
                        jwts_found.append(jwt_str)
        except Exception:
            pass

    result.jwt_tokens_discovered = len(jwts_found)

    for jwt in jwts_found[:2]: # Test max 2 tokens
        header_str, payload_str, signature = jwt.split(".")
        header = _decode_jwt_part(header_str)
        payload = _decode_jwt_part(payload_str)

        if not header or not payload:
            continue

        # 1. Check for sensitive claims
        sensitive_keys = ["password", "hash", "secret", "ssn", "credit_card", "key"]
        for key in sensitive_keys:
            if key in payload:
                result.sensitive_claims_exposed.append(key)
                result.findings.append({
                    "type": "jwt_sensitive_data_exposure",
                    "severity": "RED",
                    "detail": f"JWT token exposes sensitive claim: '{key}'.",
                })

        # 2. Check for None Algorithm Vulnerability Surface
        # Modify the header to alg: none, and strip the signature
        header["alg"] = "none"
        none_alg_jwt = f"{_encode_jwt_part(header)}.{payload_str}."

        try:
            # We passively test by sending it to a generic /api/user endpoint
            resp = await client.get(f"{base}/api/user", headers={"Authorization": f"Bearer {none_alg_jwt}"})
            if resp.status_code in (200, 201):
                result.jwt_none_alg_vulnerable = True
                result.findings.append({
                    "type": "jwt_none_alg_bypass",
                    "severity": "CRITICAL",
                    "detail": "API endpoint accepted a JWT with the 'none' algorithm (Signature stripped). Authentication bypass possible.",
                })
        except Exception:
            pass

        # 3. Algorithm Confusion Surface Check (RS256 -> HS256)
        if header.get("alg") in ["RS256", "RS384", "RS512"]:
            result.jwt_algorithm_confusion_surface = True
            result.findings.append({
                "type": "jwt_algorithm_confusion_surface",
                "severity": "AMBER",
                "detail": "JWT uses asymmetric encryption (RS256). Surface exists for Algorithm Confusion (RS256 -> HS256) if the public key is exposed.",
            })
