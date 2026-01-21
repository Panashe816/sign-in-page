# models.py
from sqlalchemy import Column, Integer, Text, DateTime, Boolean, String, UniqueConstraint, ForeignKey
from database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("email", name="uq_users_email"),)

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), nullable=False, index=True)
    password_hash = Column(Text, nullable=False)
    name = Column(String(120), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class RefreshSession(Base):
    __tablename__ = "refresh_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(Text, nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False)

class Bookmark(Base):
    __tablename__ = "bookmarks"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    article_id = Column(Integer, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
