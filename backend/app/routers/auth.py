from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.models.user import User
from app.schemas.user import UserCreate, UserResponse
from app.schemas.auth import AuthResponse, Token
from app.core.security import verify_password, get_password_hash, create_access_token, get_current_user

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
