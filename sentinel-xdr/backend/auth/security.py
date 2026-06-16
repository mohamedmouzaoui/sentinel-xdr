"""
Sentinel XDR Pro — Authentication & RBAC
==========================================
JWT-based auth with role-based access control.

Roles hierarchy:
  SUPERADMIN > ADMIN > ANALYST_L3 > ANALYST_L2 > ANALYST_L1 > READONLY
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.core.database import get_db
from backend.core.models import User, UserRole
from backend.core.settings import settings

# ── Password hashing ──────────────────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

# ── JWT ───────────────────────────────────────────────────────────────────────
bearer_scheme = HTTPBearer(auto_error=False)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {e}")

# ── Role hierarchy ────────────────────────────────────────────────────────────
ROLE_HIERARCHY = {
    UserRole.SUPERADMIN: 6,
    UserRole.ADMIN:      5,
    UserRole.ANALYST_L3: 4,
    UserRole.ANALYST_L2: 3,
    UserRole.ANALYST_L1: 2,
    UserRole.READONLY:   1,
}

def has_permission(user_role: UserRole, required_role: UserRole) -> bool:
    return ROLE_HIERARCHY.get(user_role, 0) >= ROLE_HIERARCHY.get(required_role, 0)

# ── Dependency: get current user ──────────────────────────────────────────────
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    payload = decode_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    user_id: int = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    result = await db.execute(select(User).where(User.id == int(user_id), User.is_active == True))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    return user


def require_role(minimum_role: UserRole):
    """Dependency factory — use as: Depends(require_role(UserRole.ANALYST_L2))"""
    async def _checker(current_user: User = Depends(get_current_user)) -> User:
        if not has_permission(current_user.role, minimum_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {minimum_role.value}, Your role: {current_user.role.value}"
            )
        return current_user
    return _checker

# Shortcut dependencies
require_readonly   = require_role(UserRole.READONLY)
require_analyst_l1 = require_role(UserRole.ANALYST_L1)
require_analyst_l2 = require_role(UserRole.ANALYST_L2)
require_analyst_l3 = require_role(UserRole.ANALYST_L3)
require_admin      = require_role(UserRole.ADMIN)
require_superadmin = require_role(UserRole.SUPERADMIN)
