"""Sentinel XDR Pro — Auth API router (login, refresh, me)."""
from __future__ import annotations
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr
from backend.core.database import get_db
from backend.core.models import User, UserRole, Tenant
from backend.auth.security import (
    verify_password, hash_password,
    create_access_token, create_refresh_token, decode_token,
    get_current_user, require_admin,
)
from backend.services.audit import audit_log
from backend.core.settings import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: dict

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str
    full_name: str
    role: UserRole = UserRole.ANALYST_L1
    tenant_id: str = settings.DEFAULT_TENANT_ID


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.username == payload.username, User.is_active == True))
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    user.last_login = datetime.now(timezone.utc)
    await db.commit()

    token_data = {"sub": str(user.id), "tenant": user.tenant_id, "role": user.role.value}
    access_token  = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    await audit_log(
        db=db, tenant_id=user.tenant_id, user=user,
        action="LOGIN", resource_type="session", resource_id=None,
        description=f"User '{user.username}' logged in",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    return TokenResponse(
        access_token=access_token, refresh_token=refresh_token,
        user={"id": user.id, "username": user.username, "email": user.email,
              "full_name": user.full_name, "role": user.role.value,
              "tenant_id": user.tenant_id, "avatar_url": user.avatar_url}
    )


@router.post("/refresh")
async def refresh_token(refresh_token: str, db: AsyncSession = Depends(get_db)):
    payload = decode_token(refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    user_id = payload.get("sub")
    result = await db.execute(select(User).where(User.id == int(user_id), User.is_active == True))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    token_data = {"sub": str(user.id), "tenant": user.tenant_id, "role": user.role.value}
    return {"access_token": create_access_token(token_data), "token_type": "bearer"}


@router.get("/me")
async def me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id, "username": current_user.username,
        "email": current_user.email, "full_name": current_user.full_name,
        "role": current_user.role.value, "tenant_id": current_user.tenant_id,
        "last_login": current_user.last_login, "mfa_enabled": current_user.mfa_enabled,
        "avatar_url": current_user.avatar_url,
    }


@router.post("/register")
async def register(
    payload: RegisterRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
):
    """Only admins can create users."""
    existing = await db.execute(select(User).where(
        (User.email == payload.email) | (User.username == payload.username)
    ))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="User already exists")

    user = User(
        tenant_id=payload.tenant_id, email=payload.email,
        username=payload.username, full_name=payload.full_name,
        hashed_password=hash_password(payload.password), role=payload.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return {"id": user.id, "username": user.username, "role": user.role.value}


@router.post("/logout")
async def logout(request: Request, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await audit_log(
        db=db, tenant_id=current_user.tenant_id, user=current_user,
        action="LOGOUT", resource_type="session", resource_id=None,
        description=f"User '{current_user.username}' logged out",
        ip_address=request.client.host if request.client else None,
    )
    return {"message": "Logged out"}
