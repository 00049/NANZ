"""
Business Logic Security Audit.

Detects business logic vulnerabilities via passive analysis
and targeted probe sequences. No exploit payloads.

Detects:
  - Price manipulation surfaces
  - Workflow bypass indicators
  - Mass assignment risk vectors
  - Account enumeration surfaces (timing + status code)
  - Predictable token/ID patterns
  - Coupon/promo code exposure
"""

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 15.0

# Predictable token/ID indicators
PREDICTABLE_ID_PATTERNS = [
    re.compile(r"\"id\":\s*\d{1,5}\b"),  # Small sequential int IDs
    re.compile(r"\"order_id\":\s*\d{1,5}\b"),
    re.compile(r"\"user_id\":\s*\d{1,6}\b"),
    re.compile(r"/orders/\d{1,5}[^/]"),
    re.compile(r"/users/\d{1,5}[^/]"),
    re.compile(r"/invoice/\d{1,5}[^/]"),
]

# Price manipulation surface patterns
PRICE_MUTATION_PATTERNS = [
    re.compile(r"\"price\":\s*\d+", re.IGNORECASE),
    re.compile(r"\"amount\":\s*\d+", re.IGNORECASE),
    re.compile(r"\"quantity\":\s*\d+", re.IGNORECASE),
    re.compile(r"\"total\":\s*\d+", re.IGNORECASE),
]

# Mass assignment risk fields
MASS_ASSIGNMENT_RISK_FIELDS = [
    "is_admin",
    "role",
    "is_verified",
    "account_type",
    "subscription",
    "credits",
    "balance",
    "is_active",
    "permissions",
    "plan",
    "user_type",
    "tier",
]

# Account enumeration endpoints
ACCOUNT_ENUM_ENDPOINTS = [
    "/forgot-password",
    "/api/forgot-password",
    "/api/auth/forgot-password",
    "/reset-password",
    "/api/auth/reset",
    "/api/user/reset",
    "/register",
    "/api/register",
    "/api/auth/register",
]

# Promo/coupon exposure paths
PROMO_PATHS = [
    "/api/coupons",
    "/api/promo",
    "/api/discounts",
    "/api/vouchers",
    "/api/offers",
    "/api/codes",
    "/coupon-list",
    "/promo-codes",
]

# Transaction replay surface paths
TRANSACTION_PATHS = [
    "/api/checkout",
    "/api/purchase",
    "/api/orders/confirm",
    "/api/payment/complete",
    "/api/order/place",
]


@dataclass
class BusinessLogicResult:
    # BL1: Price Manipulation
    price_manipulation_surface: bool = False
    price_fields_in_source: list = field(default_factory=list)

    # BL2: Workflow Bypass
    workflow_bypass_indicators: list = field(default_factory=list)

    # BL3: Mass Assignment
    mass_assignment_risk_fields: list = field(default_factory=list)
    mass_assignment_endpoints: list = field(default_factory=list)

    # BL4: Account Enumeration
    account_enumeration_confirmed: bool = False
    enumeration_method: str = ""
    enumerable_endpoints: list = field(default_factory=list)

    # BL5: Predictable IDs
    predictable_ids_found: bool = False
    predictable_id_samples: list = field(default_factory=list)

    # BL6: Promo Abuse
    promo_codes_accessible: bool = False
    exposed_promo_paths: list = field(default_factory=list)

    # BL7: Transaction Replay
    transaction_replay_surface: list = field(default_factory=list)

    probes_sent: int = 0
    error: str | None = None


async def run(url: str, domain: str) -> BusinessLogicResult:
    result = BusinessLogicResult()
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
                _check_price_manipulation(client, base, url, result),
                _check_account_enumeration(client, base, result),
                _check_predictable_ids(client, base, url, result),
                _check_promo_exposure(client, base, result),
                _check_mass_assignment(client, base, result),
                _check_transaction_replay(client, base, result),
                return_exceptions=True,
            )

    except Exception as exc:
        logger.error(f"Business logic scan failed for {url}: {exc}")
        result.error = str(exc)[:200]

    return result


async def _check_price_manipulation(
    client: httpx.AsyncClient,
    base: str,
    url: str,
    result: BusinessLogicResult,
) -> None:
    """Detect price/quantity manipulation surfaces in API responses."""
    try:
        result.probes_sent += 1
        resp = await client.get(url)
        body = resp.text[:8000]

        price_fields = []
        for pattern in PRICE_MUTATION_PATTERNS:
            matches = pattern.findall(body)
            price_fields.extend(matches[:3])

        if price_fields:
            result.price_manipulation_surface = True
            result.price_fields_in_source = price_fields[:10]

        # Check for price in API endpoints
        for path in ["/api/cart", "/api/products", "/api/items", "/api/basket"]:
            try:
                result.probes_sent += 1
                resp = await client.get(f"{base}{path}")
                if resp.status_code == 200:
                    body = resp.text[:5000]
                    for pattern in PRICE_MUTATION_PATTERNS:
                        if pattern.search(body):
                            result.price_manipulation_surface = True
                            result.workflow_bypass_indicators.append(
                                {
                                    "endpoint": path,
                                    "type": "price_field_in_api",
                                    "severity": "AMBER",
                                    "detail": f"Modifiable price/amount fields returned by {path} — client-side price manipulation risk",
                                }
                            )
                            break
            except Exception:
                pass
            await asyncio.sleep(0.1)

    except Exception as exc:
        logger.debug(f"Price check error: {exc}")


async def _check_account_enumeration(
    client: httpx.AsyncClient,
    base: str,
    result: BusinessLogicResult,
) -> None:
    """
    Detect account enumeration via timing or status code differences.
    Uses a known-fake email vs potentially real pattern.
    """
    test_emails = [
        ("nanz_test_nonexistent_9z7x@example.com", "fake"),
        ("admin@example.com", "potentially_real"),
        ("test@test.com", "common"),
    ]

    for endpoint in ACCOUNT_ENUM_ENDPOINTS:
        url = f"{base}{endpoint}"
        status_codes = []
        response_lengths = []
        timings = []

        for email, _label in test_emails:
            try:
                result.probes_sent += 1
                start = time.monotonic()
                resp = await client.get(
                    url,
                    params={"email": email},
                )
                elapsed = (time.monotonic() - start) * 1000

                status_codes.append(resp.status_code)
                response_lengths.append(len(resp.text))
                timings.append(elapsed)
                await asyncio.sleep(0.3)
            except Exception:
                pass

        if len(status_codes) >= 2:
            # Status code enumeration
            if len(set(status_codes)) > 1:
                result.account_enumeration_confirmed = True
                result.enumeration_method = "status_code_difference"
                result.enumerable_endpoints.append(
                    {
                        "endpoint": endpoint,
                        "method": "status_code",
                        "status_codes": status_codes,
                        "severity": "RED",
                        "detail": f"Different HTTP status codes for valid vs invalid accounts at {endpoint}",
                    }
                )

            # Response length enumeration
            elif (
                len(response_lengths) >= 2
                and max(response_lengths) - min(response_lengths) > 200
            ):
                result.account_enumeration_confirmed = True
                result.enumeration_method = "response_length_difference"
                result.enumerable_endpoints.append(
                    {
                        "endpoint": endpoint,
                        "method": "response_length",
                        "severity": "RED",
                        "detail": f"Response length differs significantly for valid vs invalid accounts at {endpoint}",
                    }
                )

            # Timing enumeration
            elif len(timings) >= 2 and max(timings) - min(timings) > 500:
                result.account_enumeration_confirmed = True
                result.enumeration_method = "timing_difference"
                result.enumerable_endpoints.append(
                    {
                        "endpoint": endpoint,
                        "method": "timing",
                        "timing_diff_ms": round(max(timings) - min(timings)),
                        "severity": "AMBER",
                        "detail": f"Response time varies by {round(max(timings) - min(timings))}ms for valid vs invalid accounts",
                    }
                )

        if result.account_enumeration_confirmed:
            break


async def _check_predictable_ids(
    client: httpx.AsyncClient,
    base: str,
    url: str,
    result: BusinessLogicResult,
) -> None:
    """Detect sequential/predictable object IDs in API responses."""
    endpoints = [
        url,
        f"{base}/api/orders",
        f"{base}/api/users",
        f"{base}/api/products",
        f"{base}/api/items",
    ]

    for endpoint in endpoints:
        try:
            result.probes_sent += 1
            resp = await client.get(endpoint)
            if resp.status_code != 200:
                continue
            body = resp.text[:8000]

            for pattern in PREDICTABLE_ID_PATTERNS:
                matches = pattern.findall(body)
                if matches:
                    result.predictable_ids_found = True
                    result.predictable_id_samples.extend(matches[:3])

        except Exception:
            pass
        await asyncio.sleep(0.1)

    if result.predictable_ids_found:
        result.predictable_id_samples = result.predictable_id_samples[:10]


async def _check_promo_exposure(
    client: httpx.AsyncClient,
    base: str,
    result: BusinessLogicResult,
) -> None:
    """Check for exposed promo/coupon code endpoints."""
    for path in PROMO_PATHS:
        try:
            result.probes_sent += 1
            resp = await client.get(f"{base}{path}")
            if resp.status_code == 200 and len(resp.text) > 50:
                result.promo_codes_accessible = True
                result.exposed_promo_paths.append(path)
        except Exception:
            pass
        await asyncio.sleep(0.05)


async def _check_mass_assignment(
    client: httpx.AsyncClient,
    base: str,
    result: BusinessLogicResult,
) -> None:
    """Detect mass assignment risk by analyzing API form fields and JSON keys."""
    form_endpoints = [
        "/api/profile",
        "/api/user/update",
        "/api/account",
        "/api/user/profile",
        "/api/settings",
        "/api/user/settings",
    ]

    for endpoint in form_endpoints:
        try:
            result.probes_sent += 1
            resp = await client.get(f"{base}{endpoint}")
            if resp.status_code != 200:
                continue
            body = resp.text.lower()

            found = []
            for field_name in MASS_ASSIGNMENT_RISK_FIELDS:
                if f'"{field_name}"' in body or f"'{field_name}'" in body:
                    found.append(field_name)

            if found:
                result.mass_assignment_risk_fields.extend(found)
                result.mass_assignment_endpoints.append(
                    {
                        "endpoint": endpoint,
                        "risk_fields": found,
                        "severity": "RED",
                        "detail": f"API exposes privilege fields ({', '.join(found[:3])}) in response — mass assignment risk",
                    }
                )
        except Exception:
            pass
        await asyncio.sleep(0.1)


async def _check_transaction_replay(
    client: httpx.AsyncClient,
    base: str,
    result: BusinessLogicResult,
) -> None:
    """Detect transaction endpoints lacking idempotency protection."""
    for path in TRANSACTION_PATHS:
        try:
            result.probes_sent += 1
            # Check if idempotency key is enforced
            resp1 = await client.get(f"{base}{path}")
            headers = dict(resp1.headers)

            # Missing idempotency key header handling
            if resp1.status_code not in (404, 405):
                if not any(
                    h in headers
                    for h in ["idempotency-key", "x-idempotency-key", "x-request-id"]
                ):
                    result.transaction_replay_surface.append(
                        {
                            "endpoint": path,
                            "severity": "AMBER",
                            "detail": f"No idempotency key mechanism detected at {path} — replay attacks possible",
                        }
                    )
        except Exception:
            pass
        await asyncio.sleep(0.1)
