from typing import List, Optional
from uuid import UUID
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.models.risk_exception import RiskException, RiskExceptionHistory
from app.schemas.risk_exception import RiskExceptionCreate, RiskExceptionUpdate

def get_exception(db: Session, exception_id: UUID) -> Optional[RiskException]:
    return db.query(RiskException).filter(RiskException.id == exception_id).first()

def get_active_exceptions_for_domain(db: Session, domain_id: UUID) -> List[RiskException]:
    now = datetime.now(timezone.utc)
    # Active if expires_at is null OR expires_at > now
    return db.query(RiskException).filter(
        RiskException.domain_id == domain_id,
        (RiskException.expires_at == None) | (RiskException.expires_at > now)
    ).all()

def get_exception_by_key(db: Session, domain_id: UUID, finding_key: str) -> Optional[RiskException]:
    now = datetime.now(timezone.utc)
    return db.query(RiskException).filter(
        RiskException.domain_id == domain_id,
        RiskException.finding_key == finding_key,
        (RiskException.expires_at == None) | (RiskException.expires_at > now)
    ).first()

def create_exception(db: Session, domain_id: UUID, user_id: UUID, exception_in: RiskExceptionCreate) -> RiskException:
    # Check if active exception already exists for this key
    existing = get_exception_by_key(db, domain_id, exception_in.finding_key)
    if existing:
        return update_exception(db, existing, RiskExceptionUpdate(**exception_in.model_dump()), user_id)
        
    db_obj = RiskException(
        domain_id=domain_id,
        finding_key=exception_in.finding_key,
        status=exception_in.status,
        justification=exception_in.justification,
        owner=exception_in.owner,
        expires_at=exception_in.expires_at,
        created_by=user_id
    )
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    
    # Log history
    history = RiskExceptionHistory(
        exception_id=db_obj.id,
        action="created",
        new_status=db_obj.status,
        actor_id=user_id,
        notes=f"Risk exception created: {db_obj.status}"
    )
    db.add(history)
    db.commit()
    
    return db_obj

def update_exception(db: Session, db_obj: RiskException, exception_in: RiskExceptionUpdate, user_id: UUID) -> RiskException:
    old_status = db_obj.status
    update_data = exception_in.model_dump(exclude_unset=True)
    
    for field, value in update_data.items():
        setattr(db_obj, field, value)
        
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    
    # Log history
    history = RiskExceptionHistory(
        exception_id=db_obj.id,
        action="updated",
        previous_status=old_status,
        new_status=db_obj.status,
        actor_id=user_id,
        notes=f"Risk exception updated"
    )
    db.add(history)
    db.commit()
    
    return db_obj

def remove_exception(db: Session, db_obj: RiskException, user_id: UUID) -> None:
    # Instead of deleting, we can just expire it or hard delete. Let's hard delete for simplicity
    # but log it first (though ON DELETE CASCADE will wipe history).
    # So actually, it's better to update expires_at to now.
    db_obj.expires_at = datetime.now(timezone.utc)
    db.add(db_obj)
    
    history = RiskExceptionHistory(
        exception_id=db_obj.id,
        action="revoked",
        previous_status=db_obj.status,
        new_status="revoked",
        actor_id=user_id,
        notes="Risk exception revoked by user"
    )
    db.add(history)
    db.commit()
