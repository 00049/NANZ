from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, EmailStr

from app.db.session import get_db
from app.models.waitlist import APIWaitlist

router = APIRouter(tags=["Waitlist"])

class WaitlistRequest(BaseModel):
    email: EmailStr

@router.post("/")
async def join_waitlist(body: WaitlistRequest, db: AsyncSession = Depends(get_db)):
    """Join the API access waitlist."""
    result = await db.execute(select(APIWaitlist).where(APIWaitlist.email == body.email))
    existing = result.scalars().first()
    
    if existing:
        return {"message": "You are already on the waitlist."}
        
    entry = APIWaitlist(email=body.email)
    db.add(entry)
    await db.commit()
    
    return {"message": "Successfully joined the waitlist!"}
