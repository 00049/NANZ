import pytest
import os
import asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from redis.asyncio import Redis

os.environ["APP_ENV"] = "testing"
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "postgresql+asyncpg://postgres:localdev@localhost:5432/shieldcheck_test")

from app.main import app
from app.db.base import Base

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
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client

@pytest.fixture
async def sample_scan_id(db_session):
    from app.models.scan import Scan
    import uuid
    scan_id = uuid.uuid4()
    scan = Scan(id=scan_id, url="https://example.com", domain="example.com", status="pending")
    db_session.add(scan)
    await db_session.commit()
    return scan_id

@pytest.fixture
async def sample_completed_scan(db_session):
    from app.models.scan import Scan
    from app.models.report import Report
    import uuid
    from datetime import datetime, timezone
    
    scan_id = uuid.uuid4()
    scan = Scan(id=scan_id, url="https://example.com", domain="example.com", status="complete", completed_at=datetime.now(timezone.utc))
    db_session.add(scan)
    await db_session.flush()
    
    report = Report(
        scan_id=scan_id,
        overall_severity="RED",
        risk_items=[{"title": "Risk 1", "severity": "RED", "business_impact": "Loss", "fix_action": "Fix it", "confidence": "HIGH"}],
        checks_run={"checks": ["ssl"]}
    )
    db_session.add(report)
    await db_session.commit()
    return scan_id
