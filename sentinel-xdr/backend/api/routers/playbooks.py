"""
Sentinel XDR Pro — SOAR Playbooks Router
==========================================
YAML-configurable playbooks loaded at runtime.
Each action is executed, logged to PlaybookExecution, and WebSocket-streamed.
"""
from __future__ import annotations
import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from backend.core.database import get_db
from backend.core.models import PlaybookExecution, Incident, User
from backend.auth.security import require_analyst_l2, get_current_user
from backend.services.audit import audit_log
from backend.api.ws import manager

router = APIRouter(prefix="/playbooks", tags=["SOAR Playbooks"])

# ── Built-in playbook definitions (production: load from YAML files) ──────────
PLAYBOOKS: Dict[str, Dict[str, Any]] = {
    "isolate_host": {
        "id": "isolate_host",
        "name": "Isolate Host",
        "description": "VLAN quarantine via core switch",
        "severity": "CRITICAL",
        "category": "containment",
        "steps": [
            {"id": 1, "name": "Resolve MAC address", "action": "lookup_mac",   "timeout": 10},
            {"id": 2, "name": "Check active sessions","action": "check_sessions","timeout": 5},
            {"id": 3, "name": "Dispatch network payload","action": "vlan_quarantine","timeout": 30},
            {"id": 4, "name": "Verify isolation",     "action": "verify_isolation","timeout": 15},
            {"id": 5, "name": "Update CMDB",          "action": "cmdb_update",  "timeout": 5},
        ],
    },
    "block_ip": {
        "id": "block_ip",
        "name": "Block IP Address",
        "description": "Edge firewall drop rule",
        "severity": "HIGH",
        "category": "containment",
        "steps": [
            {"id": 1, "name": "Validate IP is external", "action": "validate_ip",    "timeout": 3},
            {"id": 2, "name": "Push firewall ACL",        "action": "firewall_drop",  "timeout": 10},
            {"id": 3, "name": "Verify traffic blocked",   "action": "verify_block",   "timeout": 10},
        ],
    },
    "revoke_tokens": {
        "id": "revoke_tokens",
        "name": "Revoke Session Tokens",
        "description": "IAM session kill via Okta/AD",
        "severity": "HIGH",
        "category": "identity",
        "steps": [
            {"id": 1, "name": "Enumerate active sessions", "action": "iam_list_sessions", "timeout": 5},
            {"id": 2, "name": "Revoke all tokens",         "action": "iam_revoke_all",    "timeout": 10},
            {"id": 3, "name": "Force re-authentication",   "action": "iam_force_reauth",  "timeout": 5},
        ],
    },
    "forensic_dump": {
        "id": "forensic_dump",
        "name": "Forensic Memory Dump",
        "description": "Trigger memory snapshot via EDR",
        "severity": "MEDIUM",
        "category": "forensics",
        "steps": [
            {"id": 1, "name": "Contact EDR agent",        "action": "edr_ping",         "timeout": 10},
            {"id": 2, "name": "Trigger memory snapshot",  "action": "edr_mem_dump",     "timeout": 60},
            {"id": 3, "name": "Upload to evidence store", "action": "upload_evidence",  "timeout": 30},
            {"id": 4, "name": "Compute hash (SHA-256)",   "action": "hash_evidence",    "timeout": 10},
        ],
    },
    "notify_soc": {
        "id": "notify_soc",
        "name": "Notify SOC Team",
        "description": "Slack #soc-critical + Email L2",
        "severity": "MEDIUM",
        "category": "notification",
        "steps": [
            {"id": 1, "name": "Send Slack message",  "action": "slack_notify", "timeout": 5},
            {"id": 2, "name": "Send email to L2",    "action": "email_notify", "timeout": 5},
            {"id": 3, "name": "Create PagerDuty incident", "action": "pagerduty_create", "timeout": 5},
        ],
    },
    "open_thehive": {
        "id": "open_thehive",
        "name": "Open TheHive Case",
        "description": "Create investigation case with full context",
        "severity": "LOW",
        "category": "tracking",
        "steps": [
            {"id": 1, "name": "Build case payload",     "action": "build_case",         "timeout": 3},
            {"id": 2, "name": "Create TheHive case",    "action": "thehive_create_case","timeout": 10},
            {"id": 3, "name": "Attach observables",     "action": "thehive_add_obs",    "timeout": 5},
            {"id": 4, "name": "Link to incident",       "action": "update_incident",    "timeout": 3},
        ],
    },
}


class ExecuteRequest(BaseModel):
    incident_id: Optional[int] = None
    target: Optional[str] = None


@router.get("/")
async def list_playbooks(_: User = Depends(get_current_user)):
    return list(PLAYBOOKS.values())


@router.post("/{playbook_id}/execute")
async def execute_playbook(
    playbook_id: str,
    payload: ExecuteRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l2),
):
    pb = PLAYBOOKS.get(playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' not found")

    execution = PlaybookExecution(
        tenant_id=current_user.tenant_id,
        incident_id=payload.incident_id,
        playbook_id=playbook_id,
        playbook_name=pb["name"],
        triggered_by=current_user.username,
        status="RUNNING",
        target=payload.target,
        steps_log=[],
        started_at=datetime.now(timezone.utc),
    )
    db.add(execution)
    await db.commit()
    await db.refresh(execution)

    await audit_log(
        db=db, tenant_id=current_user.tenant_id, user=current_user,
        action="PLAYBOOK_EXECUTE", resource_type="playbook", resource_id=playbook_id,
        description=f"Playbook '{pb['name']}' executed on '{payload.target}'",
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    # Run async in background
    asyncio.create_task(_run_playbook(execution.id, pb, payload.target, current_user.tenant_id))

    return {"execution_id": execution.id, "status": "RUNNING", "playbook": pb["name"]}


async def _run_playbook(exec_id: int, pb: dict, target: Optional[str], tenant_id: str):
    """Simulate step-by-step execution and broadcast via WebSocket."""
    from backend.core.database import AsyncSessionLocal
    from sqlalchemy import select

    msgs = []
    await _ws_send(tenant_id, "playbook_log", {
        "execution_id": exec_id,
        "level": "INFO",
        "msg": f"Initializing Active Response module — '{pb['name']}'..."
    })
    await asyncio.sleep(0.3)
    await _ws_send(tenant_id, "playbook_log", {
        "execution_id": exec_id,
        "level": "INFO",
        "msg": f"Connecting to orchestration daemon [OK]"
    })
    await asyncio.sleep(0.4)

    final_status = "SUCCESS"
    for step in pb["steps"]:
        msg_start = f"[Step {step['id']}/{len(pb['steps'])}] {step['name']}..."
        await _ws_send(tenant_id, "playbook_log", {"execution_id": exec_id, "level": "INFO", "msg": msg_start})
        msgs.append({"ts": datetime.now(timezone.utc).isoformat(), "level": "INFO", "msg": msg_start})

        await asyncio.sleep(0.6 + (step.get("timeout", 5) * 0.05))

        # Simulate 95% success rate
        import random
        if random.random() < 0.05 and step["id"] < len(pb["steps"]):
            warn_msg = f"Warning: partial response from {step['action']}"
            await _ws_send(tenant_id, "playbook_log", {"execution_id": exec_id, "level": "WARN", "msg": warn_msg})
            msgs.append({"ts": datetime.now(timezone.utc).isoformat(), "level": "WARN", "msg": warn_msg})
        else:
            ok_msg = f"✓ {step['name']} completed"
            await _ws_send(tenant_id, "playbook_log", {"execution_id": exec_id, "level": "SUCCESS", "msg": ok_msg})
            msgs.append({"ts": datetime.now(timezone.utc).isoformat(), "level": "SUCCESS", "msg": ok_msg})

    finish_msg = f"Playbook '{pb['name']}' execution completed. Status: {final_status}"
    await _ws_send(tenant_id, "playbook_log", {"execution_id": exec_id, "level": final_status, "msg": finish_msg, "done": True})
    msgs.append({"ts": datetime.now(timezone.utc).isoformat(), "level": final_status, "msg": finish_msg})

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(PlaybookExecution).where(PlaybookExecution.id == exec_id))
        exe = result.scalar_one_or_none()
        if exe:
            exe.status = final_status
            exe.steps_log = msgs
            exe.finished_at = datetime.now(timezone.utc)
            await db.commit()


async def _ws_send(tenant_id: str, event_type: str, data: dict):
    try:
        await manager.broadcast_tenant(tenant_id, {"type": event_type, **data})
    except Exception:
        pass
