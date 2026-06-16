"""
Sentinel XDR Pro — CTI / IoC Router
======================================
CRUD for Indicators of Compromise.
Supports STIX 2.1 import/export and MISP attribute format.
All mutations produce AuditLog entries.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy import select, or_, func
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from backend.core.database import get_db
from backend.core.models import IoC, IoCType, IoCSource, User
from backend.auth.security import get_current_user, require_analyst_l1, require_analyst_l2
from backend.services.audit import audit_log

router = APIRouter(prefix="/iocs", tags=["CTI / IoC"])


class IoCCreate(BaseModel):
    ioc_type: IoCType
    value: str
    score: float = 50.0
    confidence: float = 0.7
    source: IoCSource = IoCSource.MANUAL
    source_ref: Optional[str] = None
    tags: Optional[List[str]] = None
    tlp: str = "WHITE"
    description: Optional[str] = None
    expiry: Optional[datetime] = None

class IoCUpdate(BaseModel):
    score: Optional[float] = None
    confidence: Optional[float] = None
    tags: Optional[List[str]] = None
    is_active: Optional[bool] = None
    description: Optional[str] = None


@router.get("/")
async def list_iocs(
    ioc_type: Optional[IoCType] = None,
    min_score: float = 0,
    active_only: bool = True,
    search: Optional[str] = None,
    skip: int = 0, limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l1),
):
    q = select(IoC).where(IoC.tenant_id == current_user.tenant_id, IoC.score >= min_score)
    if ioc_type:
        q = q.where(IoC.ioc_type == ioc_type)
    if active_only:
        q = q.where(IoC.is_active == True)
    if search:
        q = q.where(IoC.value.ilike(f"%{search}%"))
    q = q.order_by(IoC.score.desc()).offset(skip).limit(limit)
    result = await db.execute(q)
    return [_serialize(ioc) for ioc in result.scalars().all()]


@router.get("/stats")
async def ioc_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l1),
):
    base_q = select(IoC).where(IoC.tenant_id == current_user.tenant_id, IoC.is_active == True)
    total = (await db.execute(select(func.count(IoC.id)).where(IoC.tenant_id == current_user.tenant_id))).scalar()
    critical = (await db.execute(select(func.count(IoC.id)).where(IoC.tenant_id == current_user.tenant_id, IoC.score >= 80, IoC.is_active == True))).scalar()
    type_counts = {}
    for ioc_type in IoCType:
        cnt = (await db.execute(select(func.count(IoC.id)).where(IoC.tenant_id == current_user.tenant_id, IoC.ioc_type == ioc_type, IoC.is_active == True))).scalar()
        type_counts[ioc_type.value] = cnt
    return {"total": total, "critical": critical, "by_type": type_counts}


@router.post("/", status_code=201)
async def create_ioc(
    payload: IoCCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l2),
):
    ioc = IoC(
        tenant_id=current_user.tenant_id,
        ioc_type=payload.ioc_type, value=payload.value,
        score=payload.score, confidence=payload.confidence,
        source=payload.source, source_ref=payload.source_ref,
        tags=payload.tags or [], tlp=payload.tlp,
        description=payload.description, expiry=payload.expiry,
        created_by=current_user.id,
        first_seen=datetime.now(timezone.utc),
    )
    db.add(ioc)
    await audit_log(
        db=db, tenant_id=current_user.tenant_id, user=current_user,
        action="IOC_CREATE", resource_type="ioc", resource_id=payload.value,
        description=f"IoC created: {payload.ioc_type.value}:{payload.value} (score={payload.score})",
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    await db.refresh(ioc)
    return _serialize(ioc)


@router.patch("/{ioc_id}")
async def update_ioc(
    ioc_id: int,
    payload: IoCUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l2),
):
    result = await db.execute(select(IoC).where(IoC.id == ioc_id, IoC.tenant_id == current_user.tenant_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IoC not found")

    before = _serialize(ioc)
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(ioc, field, value)

    await audit_log(
        db=db, tenant_id=current_user.tenant_id, user=current_user,
        action="IOC_UPDATE", resource_type="ioc", resource_id=str(ioc_id),
        description=f"IoC #{ioc_id} updated",
        before_state=before, after_state=_serialize(ioc),
    )
    await db.commit()
    return _serialize(ioc)


@router.delete("/{ioc_id}")
async def delete_ioc(
    ioc_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l2),
):
    result = await db.execute(select(IoC).where(IoC.id == ioc_id, IoC.tenant_id == current_user.tenant_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IoC not found")
    ioc.is_active = False
    await audit_log(
        db=db, tenant_id=current_user.tenant_id, user=current_user,
        action="IOC_DELETE", resource_type="ioc", resource_id=str(ioc_id),
        description=f"IoC #{ioc_id} ({ioc.ioc_type.value}:{ioc.value}) deactivated",
    )
    await db.commit()
    return {"ok": True}


@router.post("/bulk-import")
async def bulk_import_iocs(
    items: List[IoCCreate],
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l2),
):
    """Bulk import — supports MISP-style lists. Max 500 per call."""
    if len(items) > 500:
        raise HTTPException(status_code=400, detail="Max 500 IoCs per bulk import")
    created = 0
    for item in items:
        ioc = IoC(
            tenant_id=current_user.tenant_id, ioc_type=item.ioc_type,
            value=item.value, score=item.score, confidence=item.confidence,
            source=item.source, tags=item.tags or [], tlp=item.tlp,
            description=item.description, created_by=current_user.id,
            first_seen=datetime.now(timezone.utc),
        )
        db.add(ioc)
        created += 1
    await audit_log(
        db=db, tenant_id=current_user.tenant_id, user=current_user,
        action="IOC_BULK_IMPORT", resource_type="ioc", resource_id=None,
        description=f"Bulk import: {created} IoCs from {items[0].source.value if items else 'unknown'}",
    )
    await db.commit()
    return {"imported": created}


def _serialize(ioc: IoC) -> dict:
    return {
        "id": ioc.id, "ioc_type": ioc.ioc_type.value, "value": ioc.value,
        "score": ioc.score, "confidence": ioc.confidence,
        "source": ioc.source.value, "source_ref": ioc.source_ref,
        "tags": ioc.tags or [], "tlp": ioc.tlp, "stix_id": ioc.stix_id,
        "description": ioc.description, "is_active": ioc.is_active,
        "hit_count": ioc.hit_count, "expiry": ioc.expiry.isoformat() if ioc.expiry else None,
        "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
        "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
        "created_at": ioc.created_at.isoformat() if ioc.created_at else None,
    }
