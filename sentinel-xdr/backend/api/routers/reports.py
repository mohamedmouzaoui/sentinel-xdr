"""
Sentinel XDR Pro — Reporting Router
======================================
PDF/JSON reports: incident export, weekly SOC report, executive summary.
Uses ReportLab for PDF generation.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Optional
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession
from backend.core.database import get_db
from backend.core.models import Incident, Alert, AuditLog, User, IncidentStatus
from backend.auth.security import require_analyst_l2, get_current_user

router = APIRouter(prefix="/reports", tags=["Reporting"])


@router.get("/incident/{incident_id}/pdf")
async def export_incident_pdf(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l2),
):
    """Export a single incident as a formatted PDF."""
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id, Incident.tenant_id == current_user.tenant_id)
    )
    inc = result.scalar_one_or_none()
    if not inc:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Incident not found")

    pdf_bytes = _generate_incident_pdf(inc, current_user)
    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=incident_{incident_id}_{datetime.now().strftime('%Y%m%d')}.pdf"}
    )


@router.get("/weekly/pdf")
async def export_weekly_report(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l2),
):
    """Weekly SOC executive summary PDF."""
    since = datetime.now(timezone.utc) - timedelta(days=7)

    total_incidents = (await db.execute(
        select(func.count(Incident.id)).where(
            Incident.tenant_id == current_user.tenant_id,
            Incident.created_at >= since
        )
    )).scalar()

    total_alerts = (await db.execute(
        select(func.count(Alert.id)).where(
            Alert.tenant_id == current_user.tenant_id,
            Alert.timestamp >= since
        )
    )).scalar()

    resolved_incidents = (await db.execute(
        select(func.count(Incident.id)).where(
            Incident.tenant_id == current_user.tenant_id,
            Incident.created_at >= since,
            Incident.status == IncidentStatus.RESOLVED
        )
    )).scalar()

    avg_mttr = (await db.execute(
        select(func.avg(Incident.mttr_seconds)).where(
            Incident.tenant_id == current_user.tenant_id,
            Incident.created_at >= since,
            Incident.mttr_seconds != None
        )
    )).scalar()

    stats = {
        "total_incidents": total_incidents,
        "total_alerts": total_alerts,
        "resolved_incidents": resolved_incidents,
        "avg_mttr_minutes": round(avg_mttr / 60, 1) if avg_mttr else None,
        "since": since.isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    pdf_bytes = _generate_weekly_pdf(stats, current_user)
    filename = f"soc_weekly_report_{datetime.now().strftime('%Y_%m_%d')}.pdf"
    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/weekly/json")
async def export_weekly_json(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_l2),
):
    """Weekly SOC stats as JSON — for frontend dashboard charts."""
    since = datetime.now(timezone.utc) - timedelta(days=7)
    total_inc = (await db.execute(select(func.count(Incident.id)).where(Incident.tenant_id == current_user.tenant_id, Incident.created_at >= since))).scalar()
    total_al  = (await db.execute(select(func.count(Alert.id)).where(Alert.tenant_id == current_user.tenant_id, Alert.timestamp >= since))).scalar()
    resolved  = (await db.execute(select(func.count(Incident.id)).where(Incident.tenant_id == current_user.tenant_id, Incident.created_at >= since, Incident.status == IncidentStatus.RESOLVED))).scalar()
    avg_mttr  = (await db.execute(select(func.avg(Incident.mttr_seconds)).where(Incident.tenant_id == current_user.tenant_id, Incident.created_at >= since, Incident.mttr_seconds != None))).scalar()
    avg_mttd  = (await db.execute(select(func.avg(Incident.mttd_seconds)).where(Incident.tenant_id == current_user.tenant_id, Incident.created_at >= since, Incident.mttd_seconds != None))).scalar()
    sla_breached = (await db.execute(select(func.count(Incident.id)).where(Incident.tenant_id == current_user.tenant_id, Incident.created_at >= since, Incident.sla_breached == True))).scalar()

    return {
        "period": {"from": since.isoformat(), "to": datetime.now(timezone.utc).isoformat()},
        "incidents": {"total": total_inc, "resolved": resolved, "resolution_rate": round(resolved / total_inc * 100, 1) if total_inc else 0},
        "alerts": {"total": total_al},
        "sla": {"breached": sla_breached, "breach_rate": round(sla_breached / total_inc * 100, 1) if total_inc else 0},
        "performance": {
            "avg_mttd_minutes": round(avg_mttd / 60, 1) if avg_mttd else None,
            "avg_mttr_minutes": round(avg_mttr / 60, 1) if avg_mttr else None,
        },
    }


# ── PDF Generation (ReportLab) ────────────────────────────────────────────────

def _generate_incident_pdf(inc: Incident, user: User) -> bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.enums import TA_LEFT, TA_CENTER

        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
        styles = getSampleStyleSheet()

        sev_color = {"CRITICAL": colors.HexColor("#ff5c7c"), "HIGH": colors.HexColor("#ff9544"),
                     "MEDIUM": colors.HexColor("#fbbf24"), "LOW": colors.HexColor("#3ddc97")}.get(inc.severity, colors.grey)

        story = [
            Paragraph("SENTINEL XDR PRO", ParagraphStyle("brand", fontSize=10, textColor=colors.HexColor("#22d3ee"), spaceAfter=4)),
            Paragraph(f"INCIDENT REPORT — #{inc.id}", ParagraphStyle("title", fontSize=20, fontName="Helvetica-Bold", spaceAfter=6)),
            Paragraph(inc.title or "Untitled", ParagraphStyle("subtitle", fontSize=13, textColor=colors.HexColor("#555"), spaceAfter=12)),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e0e0e0"), spaceAfter=12),
            Table([
                ["Severity",     inc.severity or "—",              "Status",        (inc.status.value if inc.status else "—")],
                ["Score",        f"{inc.score:.1f}/100",            "Kill Chain",    inc.kill_chain_phase or "—"],
                ["Source IP",    inc.source_ip or "—",             "Target Host",   inc.target_hostname or "—"],
                ["Created",      inc.created_at.strftime("%Y-%m-%d %H:%M UTC") if inc.created_at else "—",
                 "Resolved",     inc.resolved_at.strftime("%Y-%m-%d %H:%M UTC") if inc.resolved_at else "Ongoing"],
                ["MTTR",         f"{round(inc.mttr_seconds/60, 1)} min" if inc.mttr_seconds else "—",
                 "MTTD",         f"{round(inc.mttd_seconds/60, 1)} min" if inc.mttd_seconds else "—"],
            ], colWidths=[3.5*cm, 6*cm, 3.5*cm, 6*cm]),
            Spacer(1, 12),
            Paragraph("Description", ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=12, spaceAfter=4)),
            Paragraph(inc.description or "No description.", styles["Normal"]),
            Spacer(1, 8),
        ]

        if inc.prediction:
            story += [
                Paragraph("ML Prediction", ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=12, spaceAfter=4)),
                Paragraph(inc.prediction, styles["Normal"]),
                Spacer(1, 8),
            ]
        if inc.recommended_action:
            story += [
                Paragraph("Recommended Action", ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=12, spaceAfter=4)),
                Paragraph(inc.recommended_action, styles["Normal"]),
                Spacer(1, 8),
            ]

        story += [
            HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey, spaceAfter=8),
            Paragraph(
                f"Report generated by {user.full_name} ({user.role.value}) on "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M UTC')} · Sentinel XDR Pro",
                ParagraphStyle("footer", fontSize=8, textColor=colors.grey)
            ),
        ]

        doc.build(story)
        return buf.getvalue()
    except ImportError:
        # ReportLab not installed — return minimal PDF stub
        return _stub_pdf(f"Incident Report #{inc.id}")


def _generate_weekly_pdf(stats: dict, user: User) -> bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, HRFlowable

        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)

        story = [
            Paragraph("SENTINEL XDR PRO", ParagraphStyle("brand", fontSize=10, textColor=colors.HexColor("#22d3ee"))),
            Paragraph("WEEKLY SOC EXECUTIVE REPORT", ParagraphStyle("title", fontSize=20, fontName="Helvetica-Bold", spaceAfter=6)),
            Paragraph(f"Period: {stats['since'][:10]} — {stats['generated_at'][:10]}", ParagraphStyle("sub", fontSize=10, textColor=colors.grey, spaceAfter=16)),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#22d3ee"), spaceAfter=12),
            Table([
                ["Total Incidents",     str(stats["total_incidents"])],
                ["Total Alerts",        str(stats["total_alerts"])],
                ["Resolved Incidents",  str(stats["resolved_incidents"])],
                ["Avg MTTR",            f"{stats['avg_mttr_minutes']} min" if stats['avg_mttr_minutes'] else "—"],
            ], colWidths=[8*cm, 8*cm]),
            Spacer(1, 20),
            Paragraph(f"Generated by {user.full_name} on {stats['generated_at'][:10]}", ParagraphStyle("footer", fontSize=8, textColor=colors.grey)),
        ]
        doc.build(story)
        return buf.getvalue()
    except ImportError:
        return _stub_pdf("Weekly SOC Report")


def _stub_pdf(title: str) -> bytes:
    """Minimal valid PDF when ReportLab is unavailable."""
    content = f"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]/Contents 4 0 R/Resources<</Font<</F1<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>>>>>>>endobj
4 0 obj<</Length 80>>stream
BT /F1 16 Tf 72 750 Td ({title}) Tj 0 -30 Td (Install reportlab: pip install reportlab) Tj ET
endstream endobj
xref 0 5
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000274 00000 n
trailer<</Size 5/Root 1 0 R>>
startxref 406
%%EOF"""
    return content.encode()
