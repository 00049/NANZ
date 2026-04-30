import logging
from datetime import datetime, timedelta
from typing import List

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.scan_schedule import ScanSchedule
from app.services.scan_service import create_new_scan

logger = logging.getLogger(__name__)

async def get_due_schedules(db: AsyncSession) -> List[ScanSchedule]:
    """Retrieve all active scan schedules that are due to run."""
    now = datetime.utcnow()
    result = await db.execute(
        select(ScanSchedule)
        .where(ScanSchedule.is_active == True)
        .where(ScanSchedule.next_scan_time <= now)
    )
    return result.scalars().all()

async def execute_scheduled_scan(schedule: ScanSchedule, db: AsyncSession, redis_client) -> None:
    """Execute a scan for a given schedule and update next run time."""
    logger.info(f"Executing scheduled scan for {schedule.domain}")
    
    # Actually trigger the scan
    # For a scheduled scan we don't have a specific client IP
    result = await create_new_scan(schedule.domain, schedule.domain, "127.0.0.1", db, redis_client)
    
    if "error" not in result:
        schedule.last_scan_id = result["scan_id"]
        schedule.last_scan_time = datetime.utcnow()
        
        # Calculate next scan time
        if schedule.frequency == 'daily':
            schedule.next_scan_time = schedule.last_scan_time + timedelta(days=1)
        elif schedule.frequency == 'weekly':
            schedule.next_scan_time = schedule.last_scan_time + timedelta(days=7)
        elif schedule.frequency == 'monthly':
            schedule.next_scan_time = schedule.last_scan_time + timedelta(days=30)
            
        await db.commit()
    else:
        logger.error(f"Failed to execute scheduled scan for {schedule.domain}: {result['error']}")
