import asyncio
import os

import pytest
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

os.environ["APP_ENV"] = "testing"
os.environ["DATABASE_URL"] = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://postgres:localdev@localhost:5432/shieldcheck_test",
)

from datetime import UTC

from app.db.base import Base
from app.main import app

# Re-create engine/session logic for test DB
test_engine = create_async_engine(os.environ["DATABASE_URL"])
TestSessionLocal = async_sessionmaker(bind=test_engine)


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for each test case."""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(autouse=True)
async def setup_db():
    redis_client = Redis.from_url("redis://localhost:6379", decode_responses=True)
    try:
        keys = await redis_client.keys("scan:*")
        if keys:
            await redis_client.delete(*keys)
    finally:
        await redis_client.aclose()

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def db_session():
    async with TestSessionLocal() as session:
        yield session


@pytest.fixture
async def test_client():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client


@pytest.fixture
async def sample_scan_id(db_session):
    import uuid

    from app.models.scan import Scan

    scan_id = uuid.uuid4()
    scan = Scan(
        id=scan_id, url="https://example.com", domain="example.com", status="pending"
    )
    db_session.add(scan)
    await db_session.commit()
    return scan_id


@pytest.fixture
async def sample_completed_scan(db_session):
    import uuid
    from datetime import datetime, timezone

    from app.models.report import Report
    from app.models.scan import Scan

    scan_id = uuid.uuid4()
    scan = Scan(
        id=scan_id,
        url="https://example.com",
        domain="example.com",
        status="complete",
        completed_at=datetime.now(UTC),
    )
    db_session.add(scan)
    await db_session.flush()

    report = Report(
        scan_id=scan_id,
        overall_severity="RED",
        risk_items=[
            {
                "title": "Risk 1",
                "severity": "RED",
                "business_impact": "Loss",
                "fix_action": "Fix it",
                "confidence": "HIGH",
            }
        ],
        checks_run={"checks": ["ssl"]},
    )
    db_session.add(report)
    await db_session.commit()
    return scan_id


@pytest.fixture
async def client():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
