from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.models.user import User
from app.schemas.user import UserCreate, UserResponse, UserUpdate
from app.schemas.auth import AuthResponse, Token, ChangePasswordRequest
from app.core.security import verify_password, get_password_hash, create_access_token, get_current_user
from app.services.email_service import send_welcome_email

router = APIRouter(tags=["Authentication"])

@router.post("/register", response_model=AuthResponse)
async def register_user(user_in: UserCreate, db: AsyncSession = Depends(get_db)):
    """Register a new user and return a JWT."""
    result = await db.execute(select(User).where(User.email == user_in.email))
    user = result.scalars().first()
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this email already exists in the system.",
        )
    
    db_user = User(
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        name=user_in.name,
        company=user_in.company,
        role="user"
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    
    # Send welcome email asynchronously without blocking response
    import asyncio
    asyncio.create_task(asyncio.to_thread(send_welcome_email, db_user.email))
    
    access_token = create_access_token(subject=db_user.id)
    return {
        "user": db_user,
        "token": {
            "access_token": access_token,
            "token_type": "bearer"
        }
    }

@router.post("/login", response_model=AuthResponse)
async def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    """OAuth2 compatible token login, get an access token for future requests"""
    result = await db.execute(select(User).where(User.email == form_data.username))
    user = result.scalars().first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    
    user.last_login_at = datetime.utcnow()
    await db.commit()
    
    access_token = create_access_token(subject=user.id)
    return {
        "user": user,
        "token": {
            "access_token": access_token,
            "token_type": "bearer"
        }
    }

@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current user details"""
    return current_user

@router.patch("/me", response_model=UserResponse)
async def update_me(user_in: UserUpdate, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Update current user details"""
    if user_in.name is not None:
        current_user.name = user_in.name
    if user_in.company is not None:
        current_user.company = user_in.company
        
    current_user.updated_at = datetime.utcnow()
    db.add(current_user)
    await db.commit()
    await db.refresh(current_user)
    return current_user

@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest, 
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    """Change the user's password"""
    if not current_user.hashed_password:
        raise HTTPException(status_code=400, detail="User has no password set (OAuth login)")
        
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect current password")
        
    current_user.hashed_password = get_password_hash(body.new_password)
    current_user.updated_at = datetime.utcnow()
    
    db.add(current_user)
    await db.commit()
    
    return {"message": "Password updated successfully"}

