from collections.abc import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.config import settings
import app.models  # noqa: F401

# NOTE: Supabase has TWO pooler ports:
#   - Port 6543 = Transaction mode (pgBouncer) — does NOT support prepared statements
#   - Port 5432 = Session mode — fully supports prepared statements ✅
# Always use port 5432 in DATABASE_URL when connecting via the Supabase pooler.
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
)

# Create an async session maker instance
async_session_maker = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
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

