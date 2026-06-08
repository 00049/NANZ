import logging

import sentry_sdk
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sqlalchemy.exc import SQLAlchemyError

from app.config import settings


def get_client_ip(request: Request) -> str:
    """Return the client IP address, honoring the first forwarded IP."""
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return get_remote_address(request)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

if settings.SENTRY_DSN:
    try:
        sentry_sdk.init(
            dsn=settings.SENTRY_DSN,
            environment=settings.APP_ENV,
            integrations=[FastApiIntegration()],
            traces_sample_rate=0.2,
        )
        logger.info("Sentry initialized successfully.")
    except (RuntimeError, ValueError) as e:
        logger.error(f"Failed to initialize Sentry: {e}", exc_info=True)

limiter = Limiter(key_func=get_client_ip)

app = FastAPI(
    title="ShieldCheck API",
    version="2.0.0",
    description="Enterprise ASPM Platform — ShieldCheck / NAANZ Intelligence Engine",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.on_event("startup")
async def configure_dns() -> None:
    """Override system DNS with reliable public resolvers (avoids broken IPv6 nameservers)."""
    try:
        import dns.resolver
        import dns.asyncresolver
        # Configure the default sync resolver
        dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
        dns.resolver.default_resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
        dns.resolver.default_resolver.lifetime = 5.0
        dns.resolver.default_resolver.timeout = 3.0
        # Configure the default async resolver
        dns.asyncresolver.default_resolver = dns.asyncresolver.Resolver(configure=False)
        dns.asyncresolver.default_resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
        dns.asyncresolver.default_resolver.lifetime = 5.0
        dns.asyncresolver.default_resolver.timeout = 3.0
        logger.info("✅ DNS resolver configured to use public nameservers (8.8.8.8, 1.1.1.1)")
    except Exception as e:
        logger.warning(f"Could not configure DNS resolver: {e}")


@app.on_event("startup")
async def ensure_schema() -> None:
    """Ensure all required DB columns exist — idempotent, safe to run on every startup."""
    from app.db.session import engine
    from sqlalchemy import text

    ADD_COLS = [
        # reports table — columns added in later migrations
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS waf_detected BOOLEAN",
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS waf_provider VARCHAR(100)",
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS javascript_findings JSONB",
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS cors_findings JSONB",
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS cloud_findings JSONB",
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS ai_summary TEXT",
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS executive_summary TEXT",
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS compliance_report JSONB",
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS brand_threats JSONB",
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS bola_findings JSONB",
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS api_findings JSONB",
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS llm_findings JSONB",
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS oast_interactions JSONB",
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS email_findings JSONB",
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS performance_findings JSONB",
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS tech_findings JSONB",
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS crawl_findings JSONB",
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS cve_findings JSONB",
        # scans table
        "ALTER TABLE scans ADD COLUMN IF NOT EXISTS user_id UUID",
        "ALTER TABLE scans ADD COLUMN IF NOT EXISTS domain_id UUID",
        "ALTER TABLE scans ADD COLUMN IF NOT EXISTS workspace_id UUID",
        # users table
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS hashed_password VARCHAR(255)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS name VARCHAR(255)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS company VARCHAR(255)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(50)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS scan_credits INTEGER DEFAULT 0",
        # new tables for report access
        """
        CREATE TABLE IF NOT EXISTS report_share_links (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            token VARCHAR(255) UNIQUE NOT NULL,
            created_by_id UUID REFERENCES users(id) ON DELETE SET NULL,
            expires_at TIMESTAMP WITH TIME ZONE,
            is_revoked BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS report_audit_logs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            viewer_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
            viewer_ip VARCHAR(45),
            action VARCHAR(50) DEFAULT 'view',
            share_token_used VARCHAR(255),
            timestamp TIMESTAMP WITH TIME ZONE DEFAULT now()
        )
        """
    ]

    for stmt in ADD_COLS:
        try:
            async with engine.begin() as conn:
                await conn.execute(text(stmt))
        except Exception as col_err:
            logger.warning(f"Schema patch skipped ({stmt[:50]}...): {col_err}")
    logger.info("✅ Schema self-heal complete")


@app.exception_handler(SQLAlchemyError)
async def database_exception_handler(request: Request, exc: SQLAlchemyError) -> JSONResponse:
    """Return a safe 503 response for database failures."""
    logger.error(f"Database error while handling {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(status_code=503, content={"detail": "Database temporarily unavailable"})

origins = [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://localhost:3002",
    "http://localhost:3003",
    "http://localhost:3004",
    "http://localhost:3005",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "http://127.0.0.1:3002",
    "http://127.0.0.1:3002",
    "http://127.0.0.1:3003",
    "https://shieldcheck.in",
    "https://www.shieldcheck.in",
    "https://nanz.in",
    "https://www.nanz.in",
    "https://nanz-drab.vercel.app",
    "https://frontend-eight-beige-98.vercel.app",
    settings.FRONTEND_URL,
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Inject security headers into all responses."""
    try:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response
    except Exception as e:
        logger.error(f"Unhandled server error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"}
        )


from app.routers import health, scans, reports, payments, email, auth, domains, workspaces, fixes, report_sharing, risk_exceptions
from app.routers import ingest  # BYOS scanner ingestion layer

app.include_router(health.router)
app.include_router(auth.router, prefix="/api/auth")
app.include_router(domains.router, prefix="/api/domains")
app.include_router(workspaces.router, prefix="/api/workspaces")
app.include_router(scans.router, prefix="/api/scans")
app.include_router(reports.router, prefix="/api/reports")
app.include_router(report_sharing.router, prefix="/api")
app.include_router(payments.router, prefix="/api/payments")
app.include_router(email.router, prefix="/api/tools")
app.include_router(fixes.router, prefix="/api/v1")
app.include_router(risk_exceptions.router, prefix="/api/v1")
app.include_router(ingest.router)  # Mounted at /api/ingest

@app.get("/api/debug-db")
async def debug_db():
    try:
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy import text
        from app.config import settings
        url = settings.DATABASE_URL
        safe_url = url
        if "@" in url and ":" in url:
            safe_url = "MASKED_URL_PRESENT"
        engine = create_async_engine(url)
        async with engine.begin() as conn:
            result = await conn.execute(text("SELECT * FROM users LIMIT 1"))
        return {"status": "success", "url": safe_url, "rows": len(result.fetchall())}
    except Exception as e:
        return {"status": "error", "error": str(e), "type": type(e).__name__}
