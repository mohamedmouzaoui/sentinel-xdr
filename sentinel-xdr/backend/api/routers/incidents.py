"""
Sentinel XDR Pro — Incidents Router
=====================================
Full workflow: NEW → TRIAGED → IN_PROGRESS → CONTAINED → RESOLVED → CLOSED
SLA tracking, MTTD/MTTR, assignment, event timeline.
All state changes produce AuditLog entries.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy import select, func, and_
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from backend.core.database import get_db
from backend.core.models import Incident, IncidentEvent, IncidentStatus, User
from backend.auth.security import get_current_user, require_analyst_l1, require_analyst_l2
from backend.services.audit import audit_log
from backend.core.settings import settings

router = APIRouter(prefix="/incidents", tags=["Incidents"])


class StatusUpdateRequest(BaseModel):
    status: IncidentStatus
    reason: Optional[str] = None
    comment: Optional[str] = None

class AssignRequest(BaseModel):
    assignee_id: int
    comment: Optional[str] = None

class CommentRequest(BaseModel):
    body: str


def _sla_minutes(severity: str) -> int:
    return {
        "CRITICAL": settings.SLA_CRITICAL_MINUTES,
        "HIGH":     settings.SLA_HIGH_MINUTES,
        "MEDIUM":   settings.SLA_MEDIUM_MINUTES,
    }.get(severity, 480)


@router.get("/")
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assigned_to_me: bool = False,
    skip: int = 0, limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l1),
):
    q = select(Incident).where(Incident.tenant_id == current_user.tenant_id)
    if status:
        q = q.where(Incident.status == status)
    if severity:
        q = q.where(Incident.severity == severity)
    if assigned_to_me:
        q = q.where(Incident.assigned_to == current_user.id)
    q = q.order_by(Incident.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(q)
    incidents = result.scalars().all()
    return [_serialize(i) for i in incidents]


@router.get("/stats")
async def incident_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l1),
):
    base = and_(Incident.tenant_id == current_user.tenant_id)
    total      = (await db.execute(select(func.count(Incident.id)).where(base))).scalar()
    open_count = (await db.execute(select(func.count(Incident.id)).where(base, Incident.status == IncidentStatus.NEW))).scalar()
    breached   = (await db.execute(select(func.count(Incident.id)).where(base, Incident.sla_breached == True, Incident.status.in_([IncidentStatus.NEW, IncidentStatus.TRIAGED, IncidentStatus.IN_PROGRESS])))).scalar()
    avg_mttr_r = await db.execute(select(func.avg(Incident.mttr_seconds)).where(base, Incident.mttr_seconds != None))
    avg_mttr   = avg_mttr_r.scalar() or 0
    return {
        "total": total, "open": open_count, "sla_breached": breached,
        "avg_mttr_minutes": round(avg_mttr / 60, 1) if avg_mttr else None,
    }


@router.get("/{incident_id}")
async def get_incident(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l1),
):
    result = await db.execute(
        select(Incident)
        .options(selectinload(Incident.events), selectinload(Incident.alerts), selectinload(Incident.playbook_runs))
        .where(Incident.id == incident_id, Incident.tenant_id == current_user.tenant_id)
    )
    inc = result.scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _serialize_full(inc)


@router.patch("/{incident_id}/status")
async def update_status(
    incident_id: int,
    payload: StatusUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l2),
):
    inc = await _get_or_404(db, incident_id, current_user.tenant_id)
    old_status = inc.status
    inc.status = payload.status

    now = datetime.now(timezone.utc)
    if payload.status == IncidentStatus.RESOLVED:
        inc.resolved_at = now
        if inc.created_at:
            diff = (now - inc.created_at.replace(tzinfo=timezone.utc)).total_seconds()
            inc.mttr_seconds = diff
    if payload.status == IncidentStatus.CLOSED:
        inc.closed_at = now

    # SLA check
    if inc.sla_deadline and now > inc.sla_deadline.replace(tzinfo=timezone.utc):
        inc.sla_breached = True

    # Timeline event
    event = IncidentEvent(
        incident_id=inc.id, user_id=current_user.id,
        username=current_user.username, event_type="STATUS_CHANGE",
        title=f"Status changed: {old_status.value} → {payload.status.value}",
        body=payload.comment,
        metadata={"old_status": old_status.value, "new_status": payload.status.value},
    )
    db.add(event)

    await audit_log(
        db=db, tenant_id=current_user.tenant_id, user=current_user,
        action="INCIDENT_STATUS_CHANGE", resource_type="incident", resource_id=str(inc.id),
        description=f"Incident #{inc.id} status: {old_status.value} → {payload.status.value}",
        reason=payload.reason,
        ip_address=request.client.host if request.client else None,
        before_state={"status": old_status.value},
        after_state={"status": payload.status.value},
    )
    await db.commit()
    return {"id": inc.id, "status": inc.status.value, "mttr_seconds": inc.mttr_seconds}


@router.patch("/{incident_id}/assign")
async def assign_incident(
    incident_id: int,
    payload: AssignRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l2),
):
    inc = await _get_or_404(db, incident_id, current_user.tenant_id)
    now = datetime.now(timezone.utc)

    # Set MTTD if first assignment
    if inc.assigned_to is None and inc.created_at:
        inc.mttd_seconds = (now - inc.created_at.replace(tzinfo=timezone.utc)).total_seconds()

    inc.assigned_to = payload.assignee_id
    inc.assigned_at = now
    if inc.status == IncidentStatus.NEW:
        inc.status = IncidentStatus.TRIAGED

    # SLA deadline
    if not inc.sla_deadline:
        inc.sla_deadline = now + timedelta(minutes=_sla_minutes(inc.severity))

    event = IncidentEvent(
        incident_id=inc.id, user_id=current_user.id,
        username=current_user.username, event_type="ASSIGNMENT",
        title=f"Incident assigned to analyst #{payload.assignee_id}",
        body=payload.comment,
        metadata={"assignee_id": payload.assignee_id, "mttd_seconds": inc.mttd_seconds},
    )
    db.add(event)

    await audit_log(
        db=db, tenant_id=current_user.tenant_id, user=current_user,
        action="INCIDENT_ASSIGN", resource_type="incident", resource_id=str(inc.id),
        description=f"Incident #{inc.id} assigned to user #{payload.assignee_id}",
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return {"id": inc.id, "assigned_to": inc.assigned_to, "mttd_seconds": inc.mttd_seconds}


@router.post("/{incident_id}/comment")
async def add_comment(
    incident_id: int,
    payload: CommentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l1),
):
    inc = await _get_or_404(db, incident_id, current_user.tenant_id)
    event = IncidentEvent(
        incident_id=inc.id, user_id=current_user.id,
        username=current_user.username, event_type="COMMENT",
        title="Analyst note", body=payload.body,
    )
    db.add(event)
    await db.commit()
    return {"ok": True}


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_or_404(db, incident_id, tenant_id):
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_id)
    )
    inc = result.scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


def _serialize(i: Incident) -> dict:
    now = datetime.now(timezone.utc)
    sla_deadline = i.sla_deadline.replace(tzinfo=timezone.utc) if i.sla_deadline else None
    return {
        "id": i.id, "title": i.title, "status": i.status.value,
        "severity": i.severity, "score": i.score,
        "source_ip": i.source_ip, "target_hostname": i.target_hostname,
        "kill_chain_phase": i.kill_chain_phase,
        "mitre_tactics": i.mitre_tactics, "mitre_techniques": i.mitre_techniques,
        "assigned_to": i.assigned_to,
        "sla_deadline": i.sla_deadline.isoformat() if i.sla_deadline else None,
        "sla_breached": i.sla_breached or (sla_deadline and now > sla_deadline and i.status not in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]),
        "mttd_seconds": i.mttd_seconds, "mttr_seconds": i.mttr_seconds,
        "created_at": i.created_at.isoformat() if i.created_at else None,
        "resolved_at": i.resolved_at.isoformat() if i.resolved_at else None,
        "alert_count": 0,
    }

def _serialize_full(i: Incident) -> dict:
    d = _serialize(i)
    d["description"] = i.description
    d["prediction"] = i.prediction
    d["recommended_action"] = i.recommended_action
    d["correlation_path"] = i.correlation_path
    d["auto_response"] = i.auto_response
    d["thehive_case_id"] = i.thehive_case_id
    d["affected_assets"] = i.affected_assets
    d["alert_count"] = len(i.alerts)
    d["events"] = [
        {"id": e.id, "event_type": e.event_type, "title": e.title,
         "body": e.body, "username": e.username, "metadata": e.metadata,
         "created_at": e.created_at.isoformat()}
        for e in (i.events or [])
    ]
    d["playbook_runs"] = [
        {"id": p.id, "playbook_name": p.playbook_name, "status": p.status,
         "triggered_by": p.triggered_by, "started_at": p.started_at.isoformat()}
        for p in (i.playbook_runs or [])
    ]
    return d
