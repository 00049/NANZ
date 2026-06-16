"""
GraphQL Security Check — OWASP GraphQL Top 10 scanner.

Tests for introspection exposure, query depth limits,
batching attacks, and field suggestion disclosure.

PASSIVE CONSTRAINTS:
  - Only sends legitimate GraphQL queries
  - No mutation payloads
  - No exploit payloads in query fields
  - All queries are read-only (introspection/schema queries)
"""

import asyncio
import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 15.0

# Common GraphQL endpoint paths
GRAPHQL_PATHS = [
    "/graphql",
    "/query",
    "/api/graphql",
    "/v1/graphql",
    "/graph",
    "/gql",
    "/api/query",
    "/graphql/v1",
    "/graphql/v2",
]

# Minimal introspection query
INTROSPECTION_QUERY = {"query": """
    {
      __schema {
        types {
          name
          kind
          fields {
            name
            type {
              name
              kind
            }
          }
        }
        queryType { name }
        mutationType { name }
        subscriptionType { name }
      }
    }
    """}

# Depth limit test query (5 levels deep, harmless)
DEPTH_TEST_QUERY = {"query": """
    {
      __schema {
        types {
          fields {
            type {
              fields {
                type {
                  name
                }
              }
            }
          }
        }
      }
    }
    """}

# Field suggestion detection
FIELD_SUGGESTION_QUERY = {"query": "{ __typename nonExistentFieldNanztest }"}

# Aliases abuse test (100 identical aliases)
ALIAS_ABUSE_QUERY = {
    "query": "{ " + " ".join(f"a{i}: __typename" for i in range(100)) + " }"
}


@dataclass
class GraphQLFinding:
    vulnerability_type: str
    endpoint: str
    severity: str
    detail: str
    confirmed: bool = False


@dataclass
class GraphQLResult:
    graphql_detected: bool = False
    active_endpoints: list = field(default_factory=list)
    introspection_enabled: bool = False
    introspection_data: dict = field(default_factory=dict)
    depth_limit_missing: bool = False
    rate_limit_missing: bool = False
    alias_limit_missing: bool = False
    field_suggestions_enabled: bool = False
    mutation_types_found: list = field(default_factory=list)
    dangerous_mutation_types: list = field(default_factory=list)
    subscription_enabled: bool = False
    playground_exposed: bool = False
    batching_supported: bool = False
    type_count: int = 0
    findings: list = field(default_factory=list)
    error: str | None = None


async def run(url: str, domain: str) -> GraphQLResult:
    result = GraphQLResult()
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(REQUEST_TIMEOUT, connect=5.0),
            follow_redirects=True,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            limits=httpx.Limits(max_connections=4),
        ) as client:

            # Phase 1: Discover GraphQL endpoints
            active_endpoints = await _discover_graphql(client, base, result)

            if not active_endpoints:
                return result

            result.graphql_detected = True
            result.active_endpoints = active_endpoints
            gql_url = active_endpoints[0]

            # Phase 2: Run all checks against first active endpoint
            await asyncio.gather(
                _check_introspection(client, gql_url, result),
                _check_playground(client, base, result),
                _check_depth_limit(client, gql_url, result),
                _check_alias_limit(client, gql_url, result),
                _check_field_suggestions(client, gql_url, result),
                _check_batching(client, gql_url, result),
                _check_rate_limiting(client, gql_url, result),
                return_exceptions=True,
            )

    except Exception as exc:
        logger.error(f"GraphQL scan failed for {url}: {exc}")
        result.error = str(exc)[:200]

    return result


async def _discover_graphql(
    client: httpx.AsyncClient,
    base: str,
    result: GraphQLResult,
) -> list[str]:
    """Discover active GraphQL endpoints."""
    active = []

    async def probe(path: str) -> None:
        try:
            # Probe with a minimal __typename query
            url = f"{base}{path}"
            resp = await client.post(
                url,
                json={"query": "{ __typename }"},
            )
            content_type = resp.headers.get("content-type", "")
            if resp.status_code in (200, 400) and (
                "json" in content_type
                or "graphql" in content_type
                or (resp.status_code == 200 and "data" in resp.text)
            ):
                try:
                    data = resp.json()
                    if "data" in data or "errors" in data:
                        active.append(url)
                except Exception:
                    pass
        except Exception:
            pass
        await asyncio.sleep(0.1)

    for path in GRAPHQL_PATHS:
        await probe(path)

    return active


async def _check_introspection(
    client: httpx.AsyncClient,
    gql_url: str,
    result: GraphQLResult,
) -> None:
    """Test whether full introspection is enabled."""
    try:
        resp = await client.post(gql_url, json=INTROSPECTION_QUERY)
        if resp.status_code != 200:
            return

        data = resp.json()
        schema = data.get("data", {}).get("__schema", {})
        if not schema:
            return

        result.introspection_enabled = True
        types = schema.get("types", [])
        result.type_count = len(types)

        # Collect mutation types
        mutation_type = schema.get("mutationType")
        if mutation_type:
            result.subscription_enabled = bool(schema.get("subscriptionType"))
            # Find mutation fields from types list
            for t in types:
                if t.get("name") == mutation_type.get("name"):
                    fields = t.get("fields") or []
                    for f in fields:
                        name = f.get("name", "")
                        result.mutation_types_found.append(name)
                        # Flag sensitive mutations
                        if any(
                            kw in name.lower()
                            for kw in [
                                "delete",
                                "remove",
                                "purge",
                                "admin",
                                "ban",
                                "promote",
                                "reset",
                                "change_password",
                                "transfer",
                            ]
                        ):
                            result.dangerous_mutation_types.append(name)

        result.introspection_data = {
            "type_count": result.type_count,
            "mutation_type": mutation_type.get("name") if mutation_type else None,
            "subscription_enabled": result.subscription_enabled,
        }

        result.findings.append(
            GraphQLFinding(
                vulnerability_type="graphql_introspection_enabled",
                endpoint=gql_url,
                severity="RED",
                detail=f"GraphQL introspection enabled — {result.type_count} types exposed including full schema",
                confirmed=True,
            ).__dict__
        )

        if result.dangerous_mutation_types:
            result.findings.append(
                GraphQLFinding(
                    vulnerability_type="graphql_dangerous_mutations",
                    endpoint=gql_url,
                    severity="RED",
                    detail=f"Sensitive mutation types exposed: {', '.join(result.dangerous_mutation_types[:5])}",
                    confirmed=True,
                ).__dict__
            )

    except Exception as exc:
        logger.debug(f"Introspection check error: {exc}")


async def _check_playground(
    client: httpx.AsyncClient,
    base: str,
    result: GraphQLResult,
) -> None:
    """Check for exposed GraphQL playground/IDE."""
    playground_paths = [
        "/graphql",
        "/graphiql",
        "/api/graphql",
        "/playground",
        "/graphql-playground",
        "/v1/graphql",
    ]

    for path in playground_paths:
        try:
            resp = await client.get(f"{base}{path}")
            if resp.status_code == 200:
                body = resp.text.lower()
                if any(
                    kw in body
                    for kw in [
                        "graphiql",
                        "playground",
                        "graphql-ui",
                        "graphql playground",
                        "apollo studio",
                    ]
                ):
                    result.playground_exposed = True
                    result.findings.append(
                        GraphQLFinding(
                            vulnerability_type="graphql_playground_exposed",
                            endpoint=f"{base}{path}",
                            severity="AMBER",
                            detail="GraphQL playground/IDE exposed in production — allows query exploration",
                            confirmed=True,
                        ).__dict__
                    )
                    return
        except Exception:
            pass
        await asyncio.sleep(0.1)


async def _check_depth_limit(
    client: httpx.AsyncClient,
    gql_url: str,
    result: GraphQLResult,
) -> None:
    """Test whether query depth limiting is enforced."""
    try:
        resp = await client.post(gql_url, json=DEPTH_TEST_QUERY)
        if resp.status_code == 200:
            data = resp.json()
            # If we got data back with deep nesting, no depth limit
            if data.get("data") and not data.get("errors"):
                result.depth_limit_missing = True
                result.findings.append(
                    GraphQLFinding(
                        vulnerability_type="graphql_no_depth_limit",
                        endpoint=gql_url,
                        severity="AMBER",
                        detail="No query depth limit — deeply nested queries could cause resource exhaustion",
                        confirmed=True,
                    ).__dict__
                )
    except Exception as exc:
        logger.debug(f"Depth limit check: {exc}")


async def _check_alias_limit(
    client: httpx.AsyncClient,
    gql_url: str,
    result: GraphQLResult,
) -> None:
    """Test whether alias amplification is limited."""
    try:
        resp = await client.post(gql_url, json=ALIAS_ABUSE_QUERY)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("data") and len(data["data"]) >= 90:  # Got most aliases back
                result.alias_limit_missing = True
                result.findings.append(
                    GraphQLFinding(
                        vulnerability_type="graphql_alias_abuse",
                        endpoint=gql_url,
                        severity="AMBER",
                        detail="No alias limit enforced — 100-alias query returned full data (query amplification risk)",
                        confirmed=True,
                    ).__dict__
                )
    except Exception as exc:
        logger.debug(f"Alias limit check: {exc}")


async def _check_field_suggestions(
    client: httpx.AsyncClient,
    gql_url: str,
    result: GraphQLResult,
) -> None:
    """Detect field suggestion disclosure (schema enumeration without introspection)."""
    try:
        resp = await client.post(gql_url, json=FIELD_SUGGESTION_QUERY)
        if resp.status_code in (200, 400):
            body = resp.text
            if "Did you mean" in body or "Suggestion" in body:
                result.field_suggestions_enabled = True
                result.findings.append(
                    GraphQLFinding(
                        vulnerability_type="graphql_field_suggestions",
                        endpoint=gql_url,
                        severity="GREEN",
                        detail='Field suggestions enabled — "Did you mean" hints reveal schema even without introspection',
                        confirmed=True,
                    ).__dict__
                )
    except Exception as exc:
        logger.debug(f"Field suggestion check: {exc}")


async def _check_batching(
    client: httpx.AsyncClient,
    gql_url: str,
    result: GraphQLResult,
) -> None:
    """Test whether query batching is supported."""
    batch_query = [
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
    ]
    try:
        resp = await client.post(gql_url, json=batch_query)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) > 1:
                result.batching_supported = True
                result.findings.append(
                    GraphQLFinding(
                        vulnerability_type="graphql_batching_allowed",
                        endpoint=gql_url,
                        severity="AMBER",
                        detail="Query batching supported — multiplies attack surface for brute-force and rate limit bypass",
                        confirmed=True,
                    ).__dict__
                )
    except Exception as exc:
        logger.debug(f"Batching check: {exc}")


async def _check_rate_limiting(
    client: httpx.AsyncClient,
    gql_url: str,
    result: GraphQLResult,
) -> None:
    """Send 30 rapid queries to test rate limiting."""
    try:
        rate_limited = False
        for _ in range(30):
            resp = await client.post(gql_url, json={"query": "{ __typename }"})
            if resp.status_code == 429:
                rate_limited = True
                break
            await asyncio.sleep(0.02)

        if not rate_limited:
            result.rate_limit_missing = True
            result.findings.append(
                GraphQLFinding(
                    vulnerability_type="graphql_no_rate_limit",
                    endpoint=gql_url,
                    severity="RED",
                    detail="No rate limiting on GraphQL endpoint — 30 rapid queries succeeded without throttling",
                    confirmed=True,
                ).__dict__
            )
    except Exception as exc:
        logger.debug(f"Rate limit check: {exc}")
