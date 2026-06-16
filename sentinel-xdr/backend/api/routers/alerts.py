"""Sentinel XDR Pro — Alerts Router with ACK, FP, and WebSocket broadcast."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from backend.core.database import get_db
from backend.core.models import Alert, User
from backend.auth.security import require_analyst_l1, require_analyst_l2
from backend.services.audit import audit_log

router = APIRouter(prefix="/alerts", tags=["Alerts"])


class AckRequest(BaseModel):
    reason: Optional[str] = None

class FalsePositiveRequest(BaseModel):
    reason: str


@router.get("/")
async def list_alerts(
    severity: Optional[str] = None,
    is_processed: Optional[bool] = None,
    source_ip: Optional[str] = None,
    skip: int = 0, limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l1),
):
    q = select(Alert).where(Alert.tenant_id == current_user.tenant_id)
    if severity:
        q = q.where(Alert.severity == severity.upper())
    if is_processed is not None:
        q = q.where(Alert.is_processed == is_processed)
    if source_ip:
        q = q.where(Alert.source_ip == source_ip)
    q = q.order_by(Alert.timestamp.desc()).offset(skip).limit(limit)
    result = await db.execute(q)
    return [_serialize(a) for a in result.scalars().all()]


@router.get("/stats")
async def alert_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l1),
):
    base = Alert.tenant_id == current_user.tenant_id
    total = (await db.execute(select(func.count(Alert.id)).where(base))).scalar()
    by_sev = {}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cnt = (await db.execute(select(func.count(Alert.id)).where(base, Alert.severity == sev))).scalar()
        by_sev[sev] = cnt
    unack = (await db.execute(select(func.count(Alert.id)).where(base, Alert.is_processed == False))).scalar()
    fp = (await db.execute(select(func.count(Alert.id)).where(base, Alert.is_false_positive == True))).scalar()
    return {"total": total, "by_severity": by_sev, "unacknowledged": unack, "false_positives": fp}


@router.get("/{alert_id}")
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_analyst_l1)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id, Alert.tenant_id == current_user.tenant_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _serialize(alert)


@router.patch("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    payload: AckRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l1),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id, Alert.tenant_id == current_user.tenant_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.is_processed = True
    alert.acknowledged_by = current_user.id
    alert.acknowledged_at = datetime.now(timezone.utc)

    await audit_log(
        db=db, tenant_id=current_user.tenant_id, user=current_user,
        action="ALERT_ACK", resource_type="alert", resource_id=str(alert_id),
        description=f"Alert #{alert_id} acknowledged by {current_user.username}",
        reason=payload.reason,
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    return {"id": alert_id, "acknowledged": True}


@router.patch("/{alert_id}/false-positive")
async def mark_false_positive(
    alert_id: int,
    payload: FalsePositiveRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l2),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id, Alert.tenant_id == current_user.tenant_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.is_false_positive = True
    alert.is_processed = True

    await audit_log(
        db=db, tenant_id=current_user.tenant_id, user=current_user,
        action="ALERT_FP", resource_type="alert", resource_id=str(alert_id),
        description=f"Alert #{alert_id} marked as false positive",
        reason=payload.reason,
    )
    await db.commit()
    return {"id": alert_id, "false_positive": True}


def _serialize(a: Alert) -> dict:
    return {
        "id": a.id, "timestamp": a.timestamp.isoformat() if a.timestamp else None,
        "title": a.title, "description": a.description,
        "severity": a.severity, "score": a.score,
        "source_ip": a.source_ip, "destination_ip": a.destination_ip,
        "destination_port": a.destination_port, "target_hostname": a.target_hostname,
        "sigma_rule_id": a.sigma_rule_id, "rule_id": a.rule_id,
        "mitre_technique": a.mitre_technique, "mitre_tactic": a.mitre_tactic,
        "mitre_name": a.mitre_name,
        "is_processed": a.is_processed, "is_false_positive": a.is_false_positive,
        "acknowledged_by": a.acknowledged_by,
        "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
        "incident_id": a.incident_id,
        "enrichment": a.enrichment, "ml_anomaly_score": a.ml_anomaly_score,
    }
