"""
Sentinel XDR Pro — WebSocket Manager
=======================================
Manages per-tenant WebSocket connections for:
  - Live alert stream
  - Playbook execution logs
  - Incident status updates
  - Pipeline health
"""
from __future__ import annotations
import json
from typing import Dict, List
from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        # tenant_id → list of WebSocket connections
        self._connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, tenant_id: str):
        await websocket.accept()
        self._connections.setdefault(tenant_id, [])
        self._connections[tenant_id].append(websocket)

    def disconnect(self, websocket: WebSocket, tenant_id: str):
        if tenant_id in self._connections:
            try:
                self._connections[tenant_id].remove(websocket)
            except ValueError:
                pass

    async def broadcast_tenant(self, tenant_id: str, message: dict):
        """Send a message to all connections for a given tenant."""
        connections = self._connections.get(tenant_id, [])
        dead = []
        for ws in connections:
            try:
                await ws.send_text(json.dumps(message, default=str))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws, tenant_id)

    async def broadcast_all(self, message: dict):
        for tenant_id in list(self._connections.keys()):
            await self.broadcast_tenant(tenant_id, message)


manager = ConnectionManager()
