import asyncio
import uuid
from app.db.session import async_session_maker
from app.models.scan import Scan
from app.services.scanner.orchestrator import run_full_scan
from redis.asyncio import Redis

async def main():
    scan_id = uuid.uuid4()
    async with async_session_maker() as db:
        scan = Scan(id=scan_id, url="https://www.bennett.edu.in/", domain="www.bennett.edu.in", status="queued")
        db.add(scan)
        await db.commit()

    redis_client = Redis.from_url("redis://localhost:6379")
    print(f"Running scan {scan_id}...")
    await run_full_scan(str(scan_id), "https://www.bennett.edu.in/", redis_client)
    
    async with async_session_maker() as db:
        from sqlalchemy import select
        from app.models.report import Report
        s = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = s.scalars().first()
        print("Final scan status:", scan.status)
        print("Final error message:", scan.error_message)

        r = await db.execute(select(Report).where(Report.scan_id == scan_id))
        report = r.scalars().first()
        print("Report created:", report is not None)

if __name__ == "__main__":
    asyncio.run(main())
