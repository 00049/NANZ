import asyncio
from app.db.session import async_session_maker
from app.models.report import Report
from app.models.scan import Scan
from sqlalchemy import select

async def main():
    async with async_session_maker() as db:
        # get the latest scan
        r = await db.execute(select(Scan).order_by(Scan.created_at.desc()))
        scan = r.scalars().first()
        print(f"Scan ID: {scan.id}")
        print(f"Status: {scan.status}")
        
        rep = await db.execute(select(Report).where(Report.scan_id == scan.id))
        report = rep.scalars().first()
        print(f"Report Exists: {report is not None}")

if __name__ == "__main__":
    asyncio.run(main())
