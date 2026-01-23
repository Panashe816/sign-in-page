# auth_routes.py
import os
from google.oauth2 import id_token
from google.auth.transport import requests as grequests

from datetime import datetime, timedelta
import hashlib

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from database import get_db
from models import User, RefreshSession, Bookmark
from schemas import SignUpIn, LoginIn, UserOut, TokenPairOut, RefreshIn, BookmarkIn, BookmarkOut
from auth import (
    hash_password, verify_password,
    create_access_token, create_refresh_token,
    decode_access_token, decode_refresh_token,
    REFRESH_TOKEN_DAYS
)

router = APIRouter(prefix="/auth", tags=["auth"])
security = HTTPBearer()

def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    sub = decode_access_token(creds.credentials)
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid or expired access token")

    user = db.query(User).filter(User.id == int(sub)).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user

@router.post("/signup", response_model=UserOut)
def signup(payload: SignUpIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=409, detail="Email already registered")

    if len(payload.password.encode("utf-8")) > 72:
        raise HTTPException(status_code=400, detail="Password too long (max 72 bytes)")

    user = User(email=email, password_hash=hash_password(payload.password), name=payload.name)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@router.post("/login", response_model=TokenPairOut)
from schemas import GoogleIn

@router.post("/google", response_model=TokenPairOut)
def google_login(payload: GoogleIn, db: Session = Depends(get_db)):
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    if not client_id:
        raise HTTPException(status_code=500, detail="GOOGLE_CLIENT_ID missing")

    try:
        info = id_token.verify_oauth2_token(payload.credential, grequests.Request(), client_id)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid Google credential")

    email = (info.get("email") or "").lower().strip()
    name = info.get("name")
    sub = info.get("sub")  # unique Google user id

    if not email or not sub:
        raise HTTPException(status_code=400, detail="Google token missing email/sub")

    # find by google_sub, else by email
    user = db.query(User).filter(User.google_sub == sub).first()
    if not user:
        user = db.query(User).filter(User.email == email).first()
        if user:
            user.google_sub = sub
            user.auth_provider = "google"
        else:
            user = User(
                email=email,
                password_hash=None,
                name=name,
                is_active=True,
            )
            user.google_sub = sub
            user.auth_provider = "google"
            db.add(user)

        db.commit()
        db.refresh(user)

    access = create_access_token(subject=str(user.id))
    refresh = create_refresh_token(subject=str(user.id))

    token_hash = _hash_token(refresh)
    expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_DAYS)
    db.add(RefreshSession(user_id=user.id, token_hash=token_hash, expires_at=expires_at, revoked=False))
    db.commit()

    return TokenPairOut(access_token=access, refresh_token=refresh)

def login(payload: LoginIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access = create_access_token(subject=str(user.id))
    refresh = create_refresh_token(subject=str(user.id))

    token_hash = _hash_token(refresh)
    expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_DAYS)

    db.add(RefreshSession(user_id=user.id, token_hash=token_hash, expires_at=expires_at, revoked=False))
    db.commit()

    return TokenPairOut(access_token=access, refresh_token=refresh)

@router.post("/refresh", response_model=TokenPairOut)
def refresh(payload: RefreshIn, db: Session = Depends(get_db)):
    sub = decode_refresh_token(payload.refresh_token)
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    token_hash = _hash_token(payload.refresh_token)
    session = db.query(RefreshSession).filter(RefreshSession.token_hash == token_hash).first()
    if not session or session.revoked:
        raise HTTPException(status_code=401, detail="Refresh token revoked or not recognized")

    if session.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Refresh token expired")

    # rotate
    session.revoked = True
    db.add(session)

    new_access = create_access_token(subject=str(sub))
    new_refresh = create_refresh_token(subject=str(sub))

    new_hash = _hash_token(new_refresh)
    new_expires = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_DAYS)

    db.add(RefreshSession(user_id=int(sub), token_hash=new_hash, expires_at=new_expires, revoked=False))
    db.commit()

    return TokenPairOut(access_token=new_access, refresh_token=new_refresh)

@router.post("/logout")
def logout(payload: RefreshIn, db: Session = Depends(get_db)):
    token_hash = _hash_token(payload.refresh_token)
    session = db.query(RefreshSession).filter(RefreshSession.token_hash == token_hash).first()
    if session:
        session.revoked = True
        db.add(session)
        db.commit()
    return {"ok": True}

@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user

@router.post("/bookmarks", response_model=BookmarkOut)
def add_bookmark(payload: BookmarkIn, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    existing = db.query(Bookmark).filter(Bookmark.user_id == user.id, Bookmark.article_id == payload.article_id).first()
    if existing:
        return existing
    bm = Bookmark(user_id=user.id, article_id=payload.article_id)
    db.add(bm)
    db.commit()
    db.refresh(bm)
    return bm

@router.get("/bookmarks", response_model=list[BookmarkOut])
def list_bookmarks(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return db.query(Bookmark).filter(Bookmark.user_id == user.id).order_by(Bookmark.created_at.desc()).all()

@router.delete("/bookmarks/{article_id}")
def remove_bookmark(article_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    row = db.query(Bookmark).filter(Bookmark.user_id == user.id, Bookmark.article_id == article_id).first()
    if row:
        db.delete(row)
        db.commit()
    return {"ok": True}
