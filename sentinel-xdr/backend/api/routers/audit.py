"""Sentinel XDR Pro — Audit Log Router (read-only for analysts, admin for export)."""
from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.core.database import get_db
from backend.core.models import AuditLog, User
from backend.auth.security import require_analyst_l1, require_admin

router = APIRouter(prefix="/audit-logs", tags=["Audit Log"])


@router.get("/")
async def list_audit_logs(
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    username: Optional[str] = None,
    skip: int = 0, limit: int = Query(default=100, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l1),
):
    q = select(AuditLog).where(AuditLog.tenant_id == current_user.tenant_id)
    if action:
        q = q.where(AuditLog.action == action.upper())
    if resource_type:
        q = q.where(AuditLog.resource_type == resource_type)
    if username:
        q = q.where(AuditLog.username.ilike(f"%{username}%"))
    q = q.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(q)
    logs = result.scalars().all()
    return [
        {
            "id": log.id, "action": log.action, "resource_type": log.resource_type,
            "resource_id": log.resource_id, "username": log.username,
            "user_role": log.user_role, "description": log.description,
            "reason": log.reason, "ip_address": log.ip_address,
            "before_state": log.before_state, "after_state": log.after_state,
            "created_at": log.created_at.isoformat() if log.created_at else None,
        }
        for log in logs
    ]
