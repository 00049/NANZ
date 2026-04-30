from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID

from app.db.session import get_db
from app.models.user import User
from app.models.domain import Domain
from app.schemas.domain import DomainCreate, DomainResponse
from app.core.security import get_current_user

router = APIRouter(tags=["Domains"])

@router.get("/", response_model=List[DomainResponse])
async def get_domains(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve domains for the current user."""
    result = await db.execute(select(Domain).where(Domain.user_id == current_user.id).offset(skip).limit(limit))
    domains = result.scalars().all()
    return domains

@router.post("/", response_model=DomainResponse)
async def create_domain(
    domain_in: DomainCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Add a new domain to monitor."""
    # Check if domain already exists for user
    result = await db.execute(
        select(Domain).where(
            Domain.user_id == current_user.id,
            Domain.domain_name == domain_in.domain_name
        )
    )
    existing = result.scalars().first()
    
    if existing:
        raise HTTPException(status_code=400, detail="Domain already exists in your workspace")
        
    db_domain = Domain(
        user_id=current_user.id,
        domain_name=domain_in.domain_name,
        monitoring_frequency=domain_in.monitoring_frequency
    )
    db.add(db_domain)
    await db.commit()
    await db.refresh(db_domain)
    return db_domain

@router.delete("/{domain_id}", response_model=dict)
async def delete_domain(
    domain_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Remove a domain from monitoring."""
    result = await db.execute(
        select(Domain).where(
            Domain.id == domain_id,
            Domain.user_id == current_user.id
        )
    )
    domain = result.scalars().first()
    
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
        
    await db.delete(domain)
    await db.commit()
    return {"status": "success", "message": "Domain deleted"}
