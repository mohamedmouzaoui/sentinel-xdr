"""WebSocket endpoint for real-time event streaming."""
from __future__ import annotations
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from backend.api.ws import manager
from backend.auth.security import decode_token

router = APIRouter(tags=["WebSocket"])


@router.websocket("/ws/stream")
async def websocket_stream(websocket: WebSocket, token: str = Query(...)):
    """
    Real-time event stream per tenant.
    Connect with: ws://host/ws/stream?token=<access_token>
    
    Event types:
      - alert_new       : new alert from pipeline
      - incident_update : incident status/assignment change
      - playbook_log    : SOAR playbook step output
      - pipeline_stats  : EPS / queue metrics (every 10s)
    """
    try:
        payload = decode_token(token)
        tenant_id = payload.get("tenant")
        if not tenant_id:
            await websocket.close(code=4001, reason="Invalid token")
            return
    except Exception:
        await websocket.close(code=4001, reason="Authentication failed")
        return

    await manager.connect(websocket, tenant_id)
    try:
        await websocket.send_json({"type": "connected", "tenant_id": tenant_id, "message": "Sentinel XDR stream connected"})
        while True:
            # Keep alive — client can send pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket, tenant_id)
