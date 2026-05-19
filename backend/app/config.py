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

    RAZORPAY_KEY_ID: str = ""
    RAZORPAY_KEY_SECRET: str = ""

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

# Automatically fix Supabase pooler URLs to use the asyncpg driver
if settings.DATABASE_URL and settings.DATABASE_URL.startswith("postgresql://"):
    settings.DATABASE_URL = settings.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

# Inject statement_cache_size=0 for PgBouncer compatibility (applies to all connections)
if settings.DATABASE_URL and "statement_cache_size" not in settings.DATABASE_URL:
    separator = "&" if "?" in settings.DATABASE_URL else "?"
    settings.DATABASE_URL += f"{separator}statement_cache_size=0"
