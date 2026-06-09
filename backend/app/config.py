from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    """Application configuration from environment variables."""

    APP_ENV: str = "development"
    DATABASE_URL: str = "postgresql+asyncpg://postgres:localdev@localhost:5432/shieldcheck"
    REDIS_URL: str = "redis://localhost:6379"
    FRONTEND_URL: str = "http://localhost:3000"

    JWT_SECRET: str = "change_this_to_64_char_random_hex"
    APP_SECRET_KEY: str = "change_this_to_64_char_random_hex"

    SHODAN_API_KEY: str | None = None
    HIBP_API_KEY: str | None = None
    OPENAI_API_KEY: str | None = None
    ANTHROPIC_API_KEY: str | None = None

    RAZORPAY_KEY_ID: str = "rzp_test_SxtgwaC82qBq7z"
    RAZORPAY_KEY_SECRET: str = "tVfa7qR5MpUZP2jBZ0ZFfTCh"

    RESEND_API_KEY: str | None = None
    FROM_EMAIL: str = "reports@shieldcheck.in"

    MAX_SCANS_PER_IP_PER_HOUR: int = 5
    SCAN_CACHE_HOURS: int = 6
    SENTRY_DSN: str | None = None

    # ── Expanded scan engine API keys ──
    VIRUSTOTAL_API_KEY: str | None = None
    GOOGLE_SAFE_BROWSING_KEY: str | None = None
    URLSCAN_API_KEY: str | None = None
    LEAKIX_API_KEY: str | None = None
    WPSCAN_API_TOKEN: str | None = None
    ABUSEIPDB_API_KEY: str | None = None
    NUCLEI_TEMPLATES_PATH: str = "/opt/nuclei-templates"

    # ── Threat Intelligence cache settings (EPSS + CISA KEV) ──
    EPSS_CACHE_TTL: int = 86400              # 24 hours in seconds
    KEV_CATALOG_REFRESH_HOURS: int = 1       # 1 hour in seconds

    # ── Brand Protection APIs (optional) ──
    INTELX_API_KEY: str | None = None        # IntelligenceX dark web search
    GOOGLE_CSE_API_KEY: str | None = None    # Google Custom Search Engine
    GOOGLE_CSE_CX: str | None = None         # Custom Search Engine ID

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()

# ── Automatically fix Supabase / asyncpg DATABASE_URL ──
# 1. Strip invisible characters (BOM, NBSP, etc.)
# 2. Ensure the asyncpg driver prefix is used
# 3. Inject statement_cache_size=0 to prevent pgBouncer
#    DuplicatePreparedStatementError in both transaction and session mode.
if settings.DATABASE_URL:
    url = settings.DATABASE_URL.strip()
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    # Inject statement_cache_size=0 if not already present
    if "statement_cache_size" not in url:
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}prepared_statement_cache_size=0"
    settings.DATABASE_URL = url
