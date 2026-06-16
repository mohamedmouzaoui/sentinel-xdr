"""
Sentinel XDR Pro — Audit Log Service
======================================
ISO 27001 A.12.4.1 — every significant analyst action must be logged.
Usage: await audit_log(db, tenant_id, user, action, resource_type, ...)
"""
from __future__ import annotations
from typing import Any, Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from backend.core.models import AuditLog, User


async def audit_log(
    db: AsyncSession,
    tenant_id: str,
    user: Optional[User],
    action: str,
    resource_type: str,
    resource_id: Optional[str],
    description: str,
    reason: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    before_state: Optional[Dict[str, Any]] = None,
    after_state: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    """
    Create an immutable audit log entry.

    Actions (non-exhaustive):
      LOGIN, LOGOUT, REGISTER
      INCIDENT_ACK, INCIDENT_ASSIGN, INCIDENT_STATUS_CHANGE, INCIDENT_CLOSE
      ALERT_ACK, ALERT_FP (false positive)
      IOC_CREATE, IOC_UPDATE, IOC_DELETE
      PLAYBOOK_EXECUTE
      RULE_ENABLE, RULE_DISABLE, RULE_CREATE
      USER_CREATE, USER_UPDATE, USER_DELETE, ROLE_CHANGE
      REPORT_GENERATE
    """
    entry = AuditLog(
        tenant_id=tenant_id,
        user_id=user.id if user else None,
        username=user.username if user else "SYSTEM",
        user_role=user.role.value if user else "system",
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        description=description,
        reason=reason,
        ip_address=ip_address,
        user_agent=user_agent,
        before_state=before_state,
        after_state=after_state,
    )
    db.add(entry)
    # Note: caller must commit the session
    return entry
