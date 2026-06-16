
from pydantic import BaseModel

from .user import UserResponse


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: str | None = None
    user_id: str | None = None


class LoginRequest(BaseModel):
    email: str
    password: str


class AuthResponse(BaseModel):
    user: UserResponse
    token: Token


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str
