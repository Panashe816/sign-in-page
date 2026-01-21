# schemas.py
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class SignUpIn(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class TokenPairOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshIn(BaseModel):
    refresh_token: str

class UserOut(BaseModel):
    id: int
    email: EmailStr
    name: Optional[str] = None
    is_active: bool

    class Config:
        from_attributes = True

class BookmarkIn(BaseModel):
    article_id: int

class BookmarkOut(BaseModel):
    id: int
    article_id: int
    created_at: datetime

    class Config:
        from_attributes = True
