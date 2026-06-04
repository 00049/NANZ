from collections.abc import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.config import settings
import app.models  # noqa: F401

# NOTE: Supabase has TWO pooler ports:
#   - Port 6543 = Transaction mode (pgBouncer) — does NOT support prepared statements
#   - Port 5432 = Session mode — supports prepared statements ✅
#
# We set statement_cache_size=0 unconditionally to prevent:
#   "prepared statement already exists" (DuplicatePreparedStatementError)
# This error occurs when the asyncpg connection pool recycles connections and
# tries to re-register a cached prepared statement that pgBouncer already dropped.
# Setting cache to 0 is safe — it just disables client-side statement caching.

from uuid import uuid4

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
    connect_args={
        "statement_cache_size": 0,
        "prepared_statement_name_func": lambda: f"__asyncpg_{uuid4()}__",
    },
)

# Create an async session maker instance
async_session_maker = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that provides an async database session setup and tear down.
    Ensures safe, short-lived session usage inside api routes.
    """
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()
