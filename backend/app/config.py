from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration from environment variables."""

    APP_ENV: str = "development"
    DATABASE_URL: str = "postgresql+asyncpg://postgres:localdev@localhost:5432/shieldcheck"
    REDIS_URL: str = "redis://localhost:6379"

    JWT_SECRET: str = "change_this_to_64_char_random_hex"
    APP_SECRET_KEY: str = "change_this_to_64_char_random_hex"

    SHODAN_API_KEY: str | None = None
    HIBP_API_KEY: str | None = None
    ANTHROPIC_API_KEY: str | None = None

    RAZORPAY_KEY_ID: str = ""
    RAZORPAY_KEY_SECRET: str = ""

    RESEND_API_KEY: str | None = None
    FROM_EMAIL: str = "reports@shieldcheck.in"

    MAX_SCANS_PER_IP_PER_HOUR: int = 5
    SCAN_CACHE_HOURS: int = 6
    SENTRY_DSN: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
