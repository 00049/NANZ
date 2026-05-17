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


from app.routers import health, scans, reports, payments, email, auth, domains, workspaces, fixes
from app.routers import ingest  # BYOS scanner ingestion layer

app.include_router(health.router)
app.include_router(auth.router, prefix="/api/auth")
app.include_router(domains.router, prefix="/api/domains")
app.include_router(workspaces.router, prefix="/api/workspaces")
app.include_router(scans.router, prefix="/api/scans")
app.include_router(reports.router, prefix="/api/reports")
app.include_router(payments.router, prefix="/api/payments")
app.include_router(email.router, prefix="/api/tools")
app.include_router(fixes.router, prefix="/api/v1")
app.include_router(ingest.router)  # Mounted at /api/ingest
