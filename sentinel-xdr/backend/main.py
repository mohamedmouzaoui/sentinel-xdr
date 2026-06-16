"""
Sentinel XDR Pro — FastAPI Application Entry Point
====================================================
Production-grade async XDR platform.

Features:
  - JWT auth + RBAC (6 roles)
  - Multi-tenant architecture
  - ISO 27001 audit logging
  - WebSocket real-time stream
  - SOAR playbooks
  - CTI / IoC management (STIX/MISP)
  - PDF reporting
  - SLA tracking + MTTD/MTTR
  - Async pipeline (UDP → Redis → Consumer)
  - ML anomaly detection + kill chain correlation
"""
from __future__ import annotations
import asyncio
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.core.database import check_db_connection, init_db
from backend.core.settings import settings
from backend.api.routers import (
    auth, alerts, incidents, dashboard,
    iocs, playbooks, audit, reports, websocket,
)

try:
    from backend.pipeline.ingestion.receiver import LogQueueProducer, start_udp_receiver
    from backend.pipeline.consumer import pipeline_consumer
    PIPELINE_AVAILABLE = True
except ImportError:
    PIPELINE_AVAILABLE = False

# Logging
try:
    import structlog
    log = structlog.get_logger("app")
except ImportError:
    import logging
    log = logging.getLogger("app")

_app_state: Dict[str, Any] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("sentinel_xdr_starting", version=settings.APP_VERSION, env=settings.APP_ENV)
    try:
        await init_db()
        log.info("database_ready")

        await _seed_default_tenant()

        if PIPELINE_AVAILABLE:
            producer = LogQueueProducer()
            await producer.connect()
            _app_state["producer"] = producer

            transport = await start_udp_receiver(producer)
            _app_state["udp_transport"] = transport

            consumer_task = asyncio.create_task(pipeline_consumer.start(), name="pipeline-consumer")
            _app_state["consumer_task"] = consumer_task
            log.info("pipeline_ready", udp_port=settings.UDP_PORT)

        log.info("sentinel_xdr_ready", version=settings.APP_VERSION)
    except Exception as exc:
        log.error("startup_failed", error=str(exc))
        raise

    yield

    log.info("sentinel_xdr_shutting_down")
    if PIPELINE_AVAILABLE:
        if hasattr(pipeline_consumer, 'stop'):
            await pipeline_consumer.stop()
        if transport := _app_state.get("udp_transport"):
            transport.close()
        if producer := _app_state.get("producer"):
            await producer.disconnect()
    log.info("sentinel_xdr_stopped")


async def _seed_default_tenant():
    """Create the default tenant and admin user if they don't exist."""
    from backend.core.database import AsyncSessionLocal
    from backend.core.models import Tenant, User, UserRole
    from backend.auth.security import hash_password
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        # Tenant
        result = await db.execute(select(Tenant).where(Tenant.id == settings.DEFAULT_TENANT_ID))
        if not result.scalar_one_or_none():
            tenant = Tenant(
                id=settings.DEFAULT_TENANT_ID,
                name=settings.DEFAULT_TENANT_NAME,
                slug="default",
                plan="enterprise",
            )
            db.add(tenant)
            await db.commit()
            log.info("default_tenant_created")

        # Admin user
        result = await db.execute(select(User).where(User.username == "admin"))
        if not result.scalar_one_or_none():
            admin = User(
                tenant_id=settings.DEFAULT_TENANT_ID,
                email="admin@sentinel.local",
                username="admin",
                full_name="SOC Administrator",
                hashed_password=hash_password("SentinelXDR@2024!"),
                role=UserRole.SUPERADMIN,
            )
            db.add(admin)
            await db.commit()
            log.info("default_admin_created", username="admin", password="SentinelXDR@2024!")


# ── FastAPI App ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Sentinel XDR Pro",
    description=(
        "Production-grade Extended Detection & Response Platform. "
        "JWT auth, RBAC, multi-tenant, ISO 27001 audit logs, SOAR, CTI/IoC, PDF reports, WebSocket."
    ),
    version=settings.APP_VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# ── Middleware ─────────────────────────────────────────────────────────────────

@app.middleware("http")
async def request_id_middleware(request: Request, call_next) -> Response:
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time"] = f"{duration_ms}ms"
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Response-Time"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    log.error("unhandled_exception", path=request.url.path, error=str(exc))
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "request_id": str(uuid.uuid4())},
    )


# ── Routers ────────────────────────────────────────────────────────────────────
PREFIX = "/api/v1"
app.include_router(auth.router,       prefix=PREFIX)
app.include_router(alerts.router,     prefix=PREFIX)
app.include_router(incidents.router,  prefix=PREFIX)
app.include_router(dashboard.router,  prefix=PREFIX)
app.include_router(iocs.router,       prefix=PREFIX)
app.include_router(playbooks.router,  prefix=PREFIX)
app.include_router(audit.router,      prefix=PREFIX)
app.include_router(reports.router,    prefix=PREFIX)
app.include_router(websocket.router)  # /ws/stream (no prefix)


# ── Health ─────────────────────────────────────────────────────────────────────
@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "version": settings.APP_VERSION, "service": "sentinel-xdr-pro"}


@app.get("/ready", tags=["Health"])
async def readiness():
    db_ok = await check_db_connection()
    return JSONResponse(
        status_code=200 if db_ok else 503,
        content={"ready": db_ok, "database": db_ok, "version": settings.APP_VERSION},
    )


@app.get("/", tags=["Health"])
async def root():
    return {
        "service": "Sentinel XDR Pro",
        "version": settings.APP_VERSION,
        "docs": "/api/docs",
        "health": "/health",
        "ws": "/ws/stream?token=<jwt>",
    }
