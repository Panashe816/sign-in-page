# auth.py
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import jwt, JWTError
from passlib.context import CryptContext

load_dotenv()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_REFRESH_SECRET = os.getenv("JWT_REFRESH_SECRET")
JWT_ALG = "HS256"

ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "15"))
REFRESH_TOKEN_DAYS = int(os.getenv("REFRESH_TOKEN_DAYS", "30"))

if not JWT_SECRET or not JWT_REFRESH_SECRET:
    raise RuntimeError("JWT secrets are missing")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def create_access_token(subject: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    payload = {"sub": subject, "iat": int(now.timestamp()), "exp": int(exp.timestamp())}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def create_refresh_token(subject: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=REFRESH_TOKEN_DAYS)
    payload = {"sub": subject, "iat": int(now.timestamp()), "exp": int(exp.timestamp())}
    return jwt.encode(payload, JWT_REFRESH_SECRET, algorithm=JWT_ALG)

def decode_access_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return payload.get("sub")
    except JWTError:
        return None

def decode_refresh_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, JWT_REFRESH_SECRET, algorithms=[JWT_ALG])
        return payload.get("sub")
    except JWTError:
        return None
