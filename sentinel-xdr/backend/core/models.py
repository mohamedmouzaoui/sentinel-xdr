"""
Sentinel XDR Pro — ORM Models
===============================
Full model set:
  - Tenant (multi-org SaaS)
  - User + Role (RBAC)
  - AuditLog (ISO 27001 compliance)
  - Log, Alert, Incident (core XDR)
  - IncidentEvent (workflow timeline)
  - BlockedIP, SigmaRule
  - IoC (CTI/STIX indicators)
  - PlaybookExecution (SOAR)
"""
from __future__ import annotations
import enum
from datetime import datetime
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Index, Integer,
    String, Text, Enum as SAEnum
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func
from backend.core.database import Base


# ── Enums ─────────────────────────────────────────────────────────────────────

class UserRole(str, enum.Enum):
    SUPERADMIN = "superadmin"   # platform-wide admin
    ADMIN      = "admin"        # tenant admin
    ANALYST_L3 = "analyst_l3"  # senior analyst — full access
    ANALYST_L2 = "analyst_l2"  # standard analyst
    ANALYST_L1 = "analyst_l1"  # read + acknowledge only
    READONLY   = "readonly"     # view-only

class IncidentStatus(str, enum.Enum):
    NEW          = "NEW"
    TRIAGED      = "TRIAGED"
    IN_PROGRESS  = "IN_PROGRESS"
    CONTAINED    = "CONTAINED"
    RESOLVED     = "RESOLVED"
    CLOSED       = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

class IoCType(str, enum.Enum):
    IP       = "ip"
    DOMAIN   = "domain"
    URL      = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1= "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL    = "email"
    CVE      = "cve"

class IoCSource(str, enum.Enum):
    MANUAL       = "manual"
    MISP         = "misp"
    OTX          = "otx"
    ABUSEIPDB    = "abuseipdb"
    VIRUSTOTAL   = "virustotal"
    INTERNAL     = "internal"


# ── Tenant (multi-org) ────────────────────────────────────────────────────────

class Tenant(Base):
    __tablename__ = "tenants"

    id:         Mapped[str]      = mapped_column(String(64), primary_key=True)
    name:       Mapped[str]      = mapped_column(String(255), unique=True)
    slug:       Mapped[str]      = mapped_column(String(64), unique=True)
    plan:       Mapped[str]      = mapped_column(String(20), default="standard")  # standard/enterprise
    is_active:  Mapped[bool]     = mapped_column(Boolean, default=True)
    settings:   Mapped[Optional[Dict]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    users:      Mapped[List["User"]]     = relationship("User", back_populates="tenant")
    incidents:  Mapped[List["Incident"]] = relationship("Incident", back_populates="tenant")
    audit_logs: Mapped[List["AuditLog"]] = relationship("AuditLog", back_populates="tenant")
    iocs:       Mapped[List["IoC"]]      = relationship("IoC", back_populates="tenant")


# ── User + RBAC ───────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        Index("ix_users_email", "email"),
        Index("ix_users_tenant", "tenant_id"),
    )

    id:             Mapped[int]           = mapped_column(Integer, primary_key=True, index=True)
    tenant_id:      Mapped[str]           = mapped_column(String(64), ForeignKey("tenants.id"), index=True)
    email:          Mapped[str]           = mapped_column(String(255), unique=True, index=True)
    username:       Mapped[str]           = mapped_column(String(100), unique=True)
    hashed_password:Mapped[str]           = mapped_column(String(255))
    full_name:      Mapped[str]           = mapped_column(String(255))
    role:           Mapped[UserRole]      = mapped_column(SAEnum(UserRole), default=UserRole.ANALYST_L1)
    is_active:      Mapped[bool]          = mapped_column(Boolean, default=True)
    last_login:     Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at:     Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now())
    mfa_enabled:    Mapped[bool]          = mapped_column(Boolean, default=False)
    avatar_url:     Mapped[Optional[str]] = mapped_column(String(500))

    tenant:     Mapped["Tenant"]       = relationship("Tenant", back_populates="users")
    audit_logs: Mapped[List["AuditLog"]] = relationship("AuditLog", back_populates="user")


# ── Audit Log (ISO 27001 / SOC 2) ─────────────────────────────────────────────

class AuditLog(Base):
    """
    Immutable record of every analyst action.
    Who did what, when, why, on which resource — ISO 27001 A.12.4.1
    """
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_tenant_ts", "tenant_id", "created_at"),
        Index("ix_audit_user_id", "user_id"),
        Index("ix_audit_resource", "resource_type", "resource_id"),
    )

    id:            Mapped[int]           = mapped_column(Integer, primary_key=True, index=True)
    tenant_id:     Mapped[str]           = mapped_column(String(64), ForeignKey("tenants.id"))
    user_id:       Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"))
    username:      Mapped[str]           = mapped_column(String(100))  # denormalized for read performance
    user_role:     Mapped[str]           = mapped_column(String(30))
    action:        Mapped[str]           = mapped_column(String(100))  # ACKNOWLEDGE, ISOLATE, CLOSE, etc.
    resource_type: Mapped[str]           = mapped_column(String(50))   # incident, alert, ioc, rule, user
    resource_id:   Mapped[Optional[str]] = mapped_column(String(100))
    description:   Mapped[str]           = mapped_column(Text)         # human-readable summary
    reason:        Mapped[Optional[str]] = mapped_column(Text)         # analyst's justification
    ip_address:    Mapped[Optional[str]] = mapped_column(String(50))
    user_agent:    Mapped[Optional[str]] = mapped_column(String(500))
    before_state:  Mapped[Optional[Dict]] = mapped_column(JSONB)       # state before action
    after_state:   Mapped[Optional[Dict]] = mapped_column(JSONB)       # state after action
    created_at:    Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="audit_logs")
    user:   Mapped[Optional["User"]] = relationship("User", back_populates="audit_logs")


# ── Incident (with full workflow) ─────────────────────────────────────────────

class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_tenant_status", "tenant_id", "status"),
        Index("ix_incidents_severity", "severity"),
        Index("ix_incidents_source_ip", "source_ip"),
        Index("ix_incidents_assignee", "assigned_to"),
    )

    id:                  Mapped[int]           = mapped_column(Integer, primary_key=True, index=True)
    tenant_id:           Mapped[str]           = mapped_column(String(64), ForeignKey("tenants.id"), index=True)
    title:               Mapped[str]           = mapped_column(String(500))
    description:         Mapped[str]           = mapped_column(Text)
    status:              Mapped[IncidentStatus]= mapped_column(SAEnum(IncidentStatus), default=IncidentStatus.NEW)
    severity:            Mapped[str]           = mapped_column(String(20), default="MEDIUM")
    score:               Mapped[float]         = mapped_column(Float, default=0.0)

    # Scope
    source_ip:           Mapped[Optional[str]] = mapped_column(String(50))
    target_hostname:     Mapped[Optional[str]] = mapped_column(String(255))
    affected_assets:     Mapped[Optional[List]]= mapped_column(JSONB)
    host_criticality:    Mapped[Optional[str]] = mapped_column(String(20))

    # MITRE ATT&CK
    mitre_techniques:    Mapped[Optional[List]] = mapped_column(JSONB)
    mitre_tactics:       Mapped[Optional[List]] = mapped_column(JSONB)
    kill_chain_phase:    Mapped[Optional[str]]  = mapped_column(String(100))
    prediction:          Mapped[Optional[str]]  = mapped_column(Text)
    recommended_action:  Mapped[Optional[str]]  = mapped_column(Text)
    correlation_path:    Mapped[Optional[Dict]] = mapped_column(JSONB)

    # Workflow
    assigned_to:         Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"))
    assigned_at:         Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    sla_deadline:        Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    sla_breached:        Mapped[bool]          = mapped_column(Boolean, default=False)
    mttd_seconds:        Mapped[Optional[float]] = mapped_column(Float)  # detect time
    mttr_seconds:        Mapped[Optional[float]] = mapped_column(Float)  # resolve time

    # Response
    auto_response:       Mapped[Optional[Dict]] = mapped_column(JSONB)
    thehive_case_id:     Mapped[Optional[str]]  = mapped_column(String(100))

    # Timestamps
    first_seen:          Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at:          Mapped[datetime]       = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at:          Mapped[datetime]       = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    resolved_at:         Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    closed_at:           Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Relationships
    tenant:   Mapped["Tenant"]   = relationship("Tenant", back_populates="incidents")
    assignee: Mapped[Optional["User"]] = relationship("User", foreign_keys=[assigned_to])
    alerts:   Mapped[List["Alert"]] = relationship("Alert", back_populates="incident")
    events:   Mapped[List["IncidentEvent"]] = relationship("IncidentEvent", back_populates="incident", order_by="IncidentEvent.created_at")
    playbook_runs: Mapped[List["PlaybookExecution"]] = relationship("PlaybookExecution", back_populates="incident")


class IncidentEvent(Base):
    """Chronological audit trail for an incident — every state change, comment, action."""
    __tablename__ = "incident_events"
    __table_args__ = (Index("ix_inc_events_incident", "incident_id"),)

    id:          Mapped[int]           = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int]           = mapped_column(Integer, ForeignKey("incidents.id"), index=True)
    user_id:     Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"))
    username:    Mapped[str]           = mapped_column(String(100))
    event_type:  Mapped[str]           = mapped_column(String(50))   # STATUS_CHANGE, COMMENT, PLAYBOOK, ASSIGNMENT
    title:       Mapped[str]           = mapped_column(String(500))
    body:        Mapped[Optional[str]] = mapped_column(Text)
    event_meta:  Mapped[Optional[Dict]]= mapped_column(JSONB, name="event_metadata")
    created_at:  Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now())

    incident: Mapped["Incident"] = relationship("Incident", back_populates="events")


# ── Alert ─────────────────────────────────────────────────────────────────────

class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_tenant_ts", "tenant_id", "timestamp"),
        Index("ix_alerts_source_ip", "source_ip"),
        Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_incident_id", "incident_id"),
    )

    id:               Mapped[int]           = mapped_column(Integer, primary_key=True, index=True)
    tenant_id:        Mapped[str]           = mapped_column(String(64), ForeignKey("tenants.id"), index=True)
    timestamp:        Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now())
    title:            Mapped[str]           = mapped_column(String(500))
    description:      Mapped[str]           = mapped_column(Text)
    severity:         Mapped[str]           = mapped_column(String(20), default="MEDIUM")
    score:            Mapped[float]         = mapped_column(Float, default=0.0)

    source_ip:        Mapped[Optional[str]] = mapped_column(String(50))
    destination_ip:   Mapped[Optional[str]] = mapped_column(String(50))
    destination_port: Mapped[Optional[str]] = mapped_column(String(20))
    target_hostname:  Mapped[Optional[str]] = mapped_column(String(255))

    sigma_rule_id:    Mapped[Optional[str]] = mapped_column(String(50))
    rule_id:          Mapped[Optional[str]] = mapped_column(String(50))
    mitre_technique:  Mapped[Optional[str]] = mapped_column(String(50))
    mitre_tactic:     Mapped[Optional[str]] = mapped_column(String(100))
    mitre_name:       Mapped[Optional[str]] = mapped_column(String(200))

    raw_data:         Mapped[Optional[Dict]] = mapped_column(JSONB)
    enrichment:       Mapped[Optional[Dict]] = mapped_column(JSONB)
    ml_features:      Mapped[Optional[Dict]] = mapped_column(JSONB)
    ml_anomaly_score: Mapped[Optional[float]]= mapped_column(Float)

    is_processed:      Mapped[bool]          = mapped_column(Boolean, default=False)
    is_false_positive: Mapped[bool]          = mapped_column(Boolean, default=False)
    acknowledged_by:   Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"))
    acknowledged_at:   Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    incident_id:  Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("incidents.id"))
    incident:     Mapped[Optional["Incident"]] = relationship("Incident", back_populates="alerts")


# ── Log ───────────────────────────────────────────────────────────────────────

class Log(Base):
    __tablename__ = "logs"
    __table_args__ = (
        Index("ix_logs_tenant_ts", "tenant_id", "timestamp"),
        Index("ix_logs_agent_ip", "agent_ip"),
    )

    id:          Mapped[int]           = mapped_column(Integer, primary_key=True, index=True)
    tenant_id:   Mapped[str]           = mapped_column(String(64), ForeignKey("tenants.id"))
    timestamp:   Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    hostname:    Mapped[Optional[str]] = mapped_column(String(255))
    agent_ip:    Mapped[Optional[str]] = mapped_column(String(50))
    source:      Mapped[str]           = mapped_column(String(100), default="agent")
    raw_log:     Mapped[str]           = mapped_column(Text)
    parsed_data: Mapped[Optional[Dict]]= mapped_column(JSONB)
    rule_id:     Mapped[Optional[str]] = mapped_column(String(50))
    rule_level:  Mapped[int]           = mapped_column(Integer, default=0)
    log_hash:    Mapped[Optional[str]] = mapped_column(String(64))


# ── IoC — CTI / STIX ─────────────────────────────────────────────────────────

class IoC(Base):
    """
    Cyber Threat Intelligence Indicator of Compromise.
    Compatible with STIX 2.1 / MISP attribute types.
    """
    __tablename__ = "iocs"
    __table_args__ = (
        Index("ix_iocs_tenant_type", "tenant_id", "ioc_type"),
        Index("ix_iocs_value", "value"),
        Index("ix_iocs_score", "score"),
    )

    id:          Mapped[int]      = mapped_column(Integer, primary_key=True, index=True)
    tenant_id:   Mapped[str]      = mapped_column(String(64), ForeignKey("tenants.id"))
    ioc_type:    Mapped[IoCType]  = mapped_column(SAEnum(IoCType))
    value:       Mapped[str]      = mapped_column(Text, index=True)
    score:       Mapped[float]    = mapped_column(Float, default=50.0)  # 0-100 maliciousness
    confidence:  Mapped[float]    = mapped_column(Float, default=0.7)   # 0-1
    source:      Mapped[IoCSource]= mapped_column(SAEnum(IoCSource), default=IoCSource.MANUAL)
    source_ref:  Mapped[Optional[str]] = mapped_column(String(500))    # MISP event ID, OTX pulse, etc.
    tags:        Mapped[Optional[List]]= mapped_column(JSONB)           # ["ransomware","APT28"]
    tlp:         Mapped[str]      = mapped_column(String(10), default="WHITE")  # TLP: WHITE/GREEN/AMBER/RED
    stix_id:     Mapped[Optional[str]] = mapped_column(String(100))    # indicator--uuid
    description: Mapped[Optional[str]] = mapped_column(Text)
    first_seen:  Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_seen:   Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    expiry:      Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    is_active:   Mapped[bool]     = mapped_column(Boolean, default=True)
    hit_count:   Mapped[int]      = mapped_column(Integer, default=0)
    created_by:  Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"))
    created_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="iocs")


# ── Sigma Rule ────────────────────────────────────────────────────────────────

class SigmaRule(Base):
    __tablename__ = "sigma_rules"

    id:              Mapped[int]   = mapped_column(Integer, primary_key=True, index=True)
    tenant_id:       Mapped[str]   = mapped_column(String(64), ForeignKey("tenants.id"))
    rule_id:         Mapped[str]   = mapped_column(String(50), unique=True)
    name:            Mapped[str]   = mapped_column(String(255))
    description:     Mapped[str]   = mapped_column(Text)
    severity:        Mapped[str]   = mapped_column(String(20))
    score_weight:    Mapped[float] = mapped_column(Float, default=10.0)
    mitre_tactic:    Mapped[Optional[str]] = mapped_column(String(100))
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(50))
    mitre_name:      Mapped[Optional[str]] = mapped_column(String(200))
    rule_definition: Mapped[Dict]  = mapped_column(JSONB)
    is_active:       Mapped[bool]  = mapped_column(Boolean, default=True)
    hit_count:       Mapped[int]   = mapped_column(Integer, default=0)
    false_positive_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at:      Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at:      Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


# ── Blocked IP ────────────────────────────────────────────────────────────────

class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id:          Mapped[int]  = mapped_column(Integer, primary_key=True, index=True)
    tenant_id:   Mapped[str]  = mapped_column(String(64), ForeignKey("tenants.id"))
    ip_address:  Mapped[str]  = mapped_column(String(50), unique=True, index=True)
    reason:      Mapped[str]  = mapped_column(Text)
    incident_id: Mapped[Optional[int]] = mapped_column(Integer)
    blocked_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    unblocked_at:Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    is_active:   Mapped[bool] = mapped_column(Boolean, default=True)
    blocked_by:  Mapped[str]  = mapped_column(String(50), default="AUTO")


# ── SOAR — Playbook Execution ──────────────────────────────────────────────────

class PlaybookExecution(Base):
    """Records each run of an automated or manual SOAR playbook."""
    __tablename__ = "playbook_executions"
    __table_args__ = (Index("ix_pb_incident", "incident_id"),)

    id:          Mapped[int]  = mapped_column(Integer, primary_key=True)
    tenant_id:   Mapped[str]  = mapped_column(String(64), ForeignKey("tenants.id"))
    incident_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("incidents.id"))
    playbook_id: Mapped[str]  = mapped_column(String(100))
    playbook_name:Mapped[str] = mapped_column(String(255))
    triggered_by:Mapped[str]  = mapped_column(String(100))  # "AUTO" or username
    status:      Mapped[str]  = mapped_column(String(20), default="RUNNING")  # RUNNING/SUCCESS/FAILED
    steps_log:   Mapped[Optional[List]] = mapped_column(JSONB)  # [{ts, level, msg}]
    target:      Mapped[Optional[str]]  = mapped_column(String(255))
    result:      Mapped[Optional[Dict]] = mapped_column(JSONB)
    started_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    incident: Mapped[Optional["Incident"]] = relationship("Incident", back_populates="playbook_runs")
