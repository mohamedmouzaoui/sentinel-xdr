"""Sentinel XDR Pro — Dashboard & SOC Metrics Router."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession
from backend.core.database import get_db
from backend.core.models import Incident, Alert, AuditLog, User, IncidentStatus
from backend.auth.security import require_analyst_l1

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/overview")
async def dashboard_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l1),
):
    tenant = current_user.tenant_id
    since_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    since_7d  = datetime.now(timezone.utc) - timedelta(days=7)

    total_events_24h = (await db.execute(
        select(func.count(Alert.id)).where(Alert.tenant_id == tenant, Alert.timestamp >= since_24h)
    )).scalar()

    active_alerts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.tenant_id == tenant, Alert.is_processed == False)
    )).scalar()

    open_incidents = (await db.execute(
        select(func.count(Incident.id)).where(
            Incident.tenant_id == tenant,
            Incident.status.in_([IncidentStatus.NEW, IncidentStatus.TRIAGED, IncidentStatus.IN_PROGRESS])
        )
    )).scalar()

    sla_breached = (await db.execute(
        select(func.count(Incident.id)).where(
            Incident.tenant_id == tenant, Incident.sla_breached == True,
            Incident.status.in_([IncidentStatus.NEW, IncidentStatus.TRIAGED, IncidentStatus.IN_PROGRESS])
        )
    )).scalar()

    avg_mttr = (await db.execute(
        select(func.avg(Incident.mttr_seconds)).where(
            Incident.tenant_id == tenant, Incident.created_at >= since_7d, Incident.mttr_seconds != None
        )
    )).scalar()

    avg_mttd = (await db.execute(
        select(func.avg(Incident.mttd_seconds)).where(
            Incident.tenant_id == tenant, Incident.created_at >= since_7d, Incident.mttd_seconds != None
        )
    )).scalar()

    # Severity breakdown
    sev_counts = {}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cnt = (await db.execute(
            select(func.count(Alert.id)).where(Alert.tenant_id == tenant, Alert.severity == sev, Alert.timestamp >= since_24h)
        )).scalar()
        sev_counts[sev] = cnt

    # ML anomaly count
    ml_anomalies = (await db.execute(
        select(func.count(Alert.id)).where(
            Alert.tenant_id == tenant, Alert.timestamp >= since_24h,
            Alert.ml_anomaly_score != None, Alert.ml_anomaly_score >= 0.7
        )
    )).scalar()

    return {
        "kpis": {
            "total_events_24h": total_events_24h,
            "active_alerts": active_alerts,
            "open_incidents": open_incidents,
            "sla_breached": sla_breached,
            "ml_anomalies": ml_anomalies,
            "avg_mttr_minutes": round(avg_mttr / 60, 1) if avg_mttr else None,
            "avg_mttd_minutes": round(avg_mttd / 60, 1) if avg_mttd else None,
        },
        "severity_distribution": sev_counts,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
