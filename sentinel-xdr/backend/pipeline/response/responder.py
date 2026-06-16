"""
XDR Platform — Automated Response Engine
==========================================
Executes automated and analyst-triggered response actions.

Response tiers (score-based):
  ≥ 30  → Create TheHive case
  ≥ 70  → Block source IP + Slack alert
  ≥ 90  → Isolate endpoint via Wazuh active-response

All actions are idempotent and logged with full audit trails.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from backend.core.settings import settings
from backend.core.logging_config import get_logger

log = get_logger("pipeline.response")


# ── Response Action Record ────────────────────────────────────────────────────

class ResponseAction:
    """Immutable record of a single response action taken."""

    def __init__(
        self,
        action_type: str,
        target: str,
        success: bool,
        detail: str = "",
        executed_by: str = "AUTO",
    ) -> None:
        self.action_type  = action_type
        self.target       = target
        self.success      = success
        self.detail       = detail
        self.executed_by  = executed_by
        self.executed_at  = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action":      self.action_type,
            "target":      self.target,
            "success":     self.success,
            "detail":      self.detail,
            "executed_by": self.executed_by,
            "executed_at": self.executed_at,
        }


# ── TheHive Integration ───────────────────────────────────────────────────────

class TheHiveClient:
    """
    Async client for TheHive case management platform.
    Creates and manages security cases from XDR incidents.
    """

    _SEVERITY_MAP = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    _TIMEOUT = 10.0

    async def create_case(self, incident: Dict[str, Any]) -> Optional[str]:
        """
        Create a new TheHive case from an XDR incident.
        Returns the TheHive case ID on success, None on failure.
        """
        if not settings.THEHIVE_API_KEY or not settings.THEHIVE_URL:
            log.debug("thehive_not_configured")
            return None

        payload = {
            "title":       incident.get("title", "XDR Incident"),
            "description": incident.get("description", ""),
            "severity":    self._SEVERITY_MAP.get(incident.get("severity", "MEDIUM"), 2),
            "tags":        self._build_tags(incident),
            "tlp":         2,
            "status":      "New",
            "summary":     (
                f"Score: {incident.get('score', 0)}/100 | "
                f"Phase: {incident.get('kill_chain_phase', 'Unknown')} | "
                f"Source: {incident.get('source_ip', 'Unknown')}"
            ),
        }

        try:
            async with httpx.AsyncClient(timeout=self._TIMEOUT) as client:
                r = await client.post(
                    f"{settings.THEHIVE_URL}/api/case",
                    json=payload,
                    headers={
                        "Authorization": f"Bearer {settings.THEHIVE_API_KEY}",
                        "Content-Type":  "application/json",
                    },
                )
                r.raise_for_status()
                case_id = r.json().get("id")
                log.info("thehive_case_created", case_id=case_id, title=payload["title"])
                return case_id
        except httpx.HTTPStatusError as exc:
            log.error("thehive_http_error", status=exc.response.status_code, body=exc.response.text[:200])
        except Exception as exc:
            log.error("thehive_client_error", error=str(exc))
        return None

    @staticmethod
    def _build_tags(incident: Dict[str, Any]) -> List[str]:
        tags = ["XDR", "auto-generated"]
        if phase := incident.get("kill_chain_phase"):
            tags.append(phase.replace(" ", "-"))
        for tactic in (incident.get("mitre_tactics") or []):
            tags.append(f"mitre:{tactic.replace(' ', '-')}")
        if ip := incident.get("source_ip"):
            tags.append(f"attacker:{ip}")
        return tags


# ── Slack Notifier ────────────────────────────────────────────────────────────

class SlackNotifier:
    """Sends rich-format Slack alerts for high-severity incidents."""

    _TIMEOUT = 5.0
    _SEVERITY_EMOJI = {
        "LOW":      "🟡",
        "MEDIUM":   "🟠",
        "HIGH":     "🔴",
        "CRITICAL": "🚨",
    }

    async def send_incident_alert(self, incident: Dict[str, Any]) -> bool:
        """Post a formatted Slack message for a new incident."""
        if not settings.SLACK_WEBHOOK_URL:
            log.debug("slack_not_configured")
            return False

        severity = incident.get("severity", "MEDIUM")
        emoji    = self._SEVERITY_EMOJI.get(severity, "⚠️")

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} XDR Incident — {severity}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Title:*\n{incident.get('title', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Score:*\n{incident.get('score', 0)}/100"},
                    {"type": "mrkdwn", "text": f"*Source IP:*\n`{incident.get('source_ip', 'N/A')}`"},
                    {"type": "mrkdwn", "text": f"*Phase:*\n{incident.get('kill_chain_phase', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Target:*\n{incident.get('target_hostname', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Tactics:*\n{', '.join(incident.get('mitre_tactics') or ['N/A'])}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Recommended Action:*\n{incident.get('recommended_action', 'Investigate immediately.')}"},
            },
            {"type": "divider"},
        ]

        payload = {
            "channel": settings.SLACK_CHANNEL,
            "blocks":  blocks,
            "text":    f"[XDR] {severity} Incident — {incident.get('title')}",
        }

        try:
            async with httpx.AsyncClient(timeout=self._TIMEOUT) as client:
                r = await client.post(settings.SLACK_WEBHOOK_URL, json=payload)
                r.raise_for_status()
                log.info("slack_alert_sent", severity=severity, score=incident.get("score"))
                return True
        except Exception as exc:
            log.error("slack_send_failed", error=str(exc))
            return False


# ── Wazuh Active Response ─────────────────────────────────────────────────────

class WazuhResponseClient:
    """
    Triggers Wazuh active-response commands on registered agents.
    Requires Wazuh Manager API credentials.
    """

    _TIMEOUT = 10.0

    async def isolate_endpoint(self, hostname: str) -> ResponseAction:
        """
        Send a host-isolation active-response command via the Wazuh API.
        In production, this triggers a firewall/network isolation script
        on the agent host.
        """
        log.warning("isolate_endpoint_triggered", hostname=hostname)

        if not settings.WAZUH_URL:
            return ResponseAction("ISOLATE_ENDPOINT", hostname, False, "Wazuh not configured")

        try:
            async with httpx.AsyncClient(
                verify=settings.WAZUH_VERIFY_SSL,
                timeout=self._TIMEOUT,
                auth=(settings.WAZUH_USER, settings.WAZUH_PASSWORD),
            ) as client:
                # Find agent by hostname
                agents_r = await client.get(
                    f"{settings.WAZUH_URL}/agents",
                    params={"name": hostname},
                )
                agents_r.raise_for_status()
                agents = agents_r.json().get("data", {}).get("affected_items", [])

                if not agents:
                    return ResponseAction("ISOLATE_ENDPOINT", hostname, False, "Agent not found")

                agent_id = agents[0]["id"]

                # Trigger active response
                ar_r = await client.put(
                    f"{settings.WAZUH_URL}/active-response",
                    json={
                        "command":   "host-deny",
                        "arguments": [hostname],
                        "agents_list": [agent_id],
                    },
                )
                ar_r.raise_for_status()
                log.info("endpoint_isolated", hostname=hostname, agent_id=agent_id)
                return ResponseAction("ISOLATE_ENDPOINT", hostname, True, f"Agent {agent_id} isolated")

        except Exception as exc:
            log.error("isolate_endpoint_failed", hostname=hostname, error=str(exc))
            return ResponseAction("ISOLATE_ENDPOINT", hostname, False, str(exc))

    async def kill_process(self, hostname: str, pid: int) -> ResponseAction:
        """Kill a specific process on a remote agent (analyst-triggered)."""
        log.warning("kill_process_triggered", hostname=hostname, pid=pid)
        # Simulate — wire to Wazuh active-response "kill-process" command
        return ResponseAction("KILL_PROCESS", f"{hostname}:{pid}", True, f"Kill signal sent to PID {pid}")

    async def quarantine_file(self, hostname: str, filepath: str) -> ResponseAction:
        """Quarantine (delete/move) a suspicious file via Wazuh active-response."""
        log.warning("quarantine_file_triggered", hostname=hostname, filepath=filepath)
        # Simulate — wire to Wazuh active-response "quarantine" command
        return ResponseAction("QUARANTINE_FILE", filepath, True, f"File quarantined on {hostname}")


# ── Firewall / IP Block ───────────────────────────────────────────────────────

class FirewallController:
    """
    Simulated firewall interface for blocking/unblocking IP addresses.
    Replace the stub implementations with your firewall's API calls
    (e.g., pfSense API, AWS WAF, Cloudflare IP Rules).
    """

    async def block_ip(self, ip: str, reason: str = "") -> ResponseAction:
        """Block an IP at the firewall level."""
        # Stub — integrate with your firewall/WAF API
        log.warning("ip_blocked", ip=ip, reason=reason)
        return ResponseAction("BLOCK_IP", ip, True, f"IP {ip} added to blocklist: {reason}")

    async def unblock_ip(self, ip: str) -> ResponseAction:
        """Remove an IP block."""
        log.info("ip_unblocked", ip=ip)
        return ResponseAction("UNBLOCK_IP", ip, True, f"IP {ip} removed from blocklist")


# ── Orchestrated Response Engine ─────────────────────────────────────────────

class ResponseOrchestrator:
    """
    Orchestrates automated and analyst-triggered response actions.

    Threshold-based automation:
      Score ≥ 30   → TheHive case
      Score ≥ 70   → Block IP + Slack alert
      Score ≥ 90   → Isolate endpoint (if AUTO_ISOLATE_ENABLED)

    All actions are recorded in the returned action list for audit purposes.
    """

    def __init__(self) -> None:
        self.thehive   = TheHiveClient()
        self.slack     = SlackNotifier()
        self.wazuh     = WazuhResponseClient()
        self.firewall  = FirewallController()

    async def auto_respond(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute automated response actions based on incident score.
        Returns a dict containing all actions taken and their outcomes.
        """
        score     = float(incident.get("score", 0))
        ip        = incident.get("source_ip")
        hostname  = incident.get("target_hostname")
        actions:  List[Dict[str, Any]] = []

        log.info("auto_response_started",
                 incident_id=incident.get("id"),
                 score=score,
                 severity=incident.get("severity"))

        # ── Tier 1: Create TheHive case (score ≥ 30) ─────────────────────────
        if score >= settings.SCORE_LOW_THRESHOLD:
            case_id = await self.thehive.create_case(incident)
            actions.append(ResponseAction(
                "THEHIVE_CASE",
                target=case_id or "failed",
                success=bool(case_id),
                detail=f"Case ID: {case_id}" if case_id else "TheHive unreachable",
            ).to_dict())

        # ── Tier 2: Block IP + Slack (score ≥ 70) ────────────────────────────
        if score >= settings.SCORE_HIGH_THRESHOLD and ip and settings.AUTO_BLOCK_ENABLED:
            block_action = await self.firewall.block_ip(ip, reason=f"XDR auto-block — score {score}")
            actions.append(block_action.to_dict())

            slack_sent = await self.slack.send_incident_alert(incident)
            actions.append(ResponseAction(
                "SLACK_ALERT", settings.SLACK_CHANNEL, slack_sent, "Notification sent"
            ).to_dict())

        # ── Tier 3: Isolate endpoint (score ≥ 90) ────────────────────────────
        if score >= settings.SCORE_CRITICAL_THRESHOLD and hostname and settings.AUTO_ISOLATE_ENABLED:
            isolate_action = await self.wazuh.isolate_endpoint(hostname)
            actions.append(isolate_action.to_dict())

        log.info("auto_response_complete",
                 incident_id=incident.get("id"),
                 actions_taken=len(actions))

        return {"actions": actions, "score": score, "responded_at": datetime.utcnow().isoformat()}

    # ── Analyst-Triggered Actions ─────────────────────────────────────────────

    async def manual_block_ip(self, ip: str, analyst_id: str) -> ResponseAction:
        """Block an IP as requested by an analyst from the dashboard."""
        action = await self.firewall.block_ip(ip, reason=f"Manual block by {analyst_id}")
        log.info("manual_block", ip=ip, analyst=analyst_id)
        return action

    async def manual_unblock_ip(self, ip: str, analyst_id: str) -> ResponseAction:
        """Remove an IP block as requested by an analyst."""
        action = await self.firewall.unblock_ip(ip)
        log.info("manual_unblock", ip=ip, analyst=analyst_id)
        return action

    async def manual_isolate_host(self, hostname: str, analyst_id: str) -> ResponseAction:
        """Isolate a host as requested by an analyst."""
        action = await self.wazuh.isolate_endpoint(hostname)
        log.info("manual_isolate", hostname=hostname, analyst=analyst_id)
        return action

    async def manual_kill_process(self, hostname: str, pid: int, analyst_id: str) -> ResponseAction:
        action = await self.wazuh.kill_process(hostname, pid)
        log.info("manual_kill_process", hostname=hostname, pid=pid, analyst=analyst_id)
        return action

    async def manual_quarantine_file(self, hostname: str, filepath: str, analyst_id: str) -> ResponseAction:
        action = await self.wazuh.quarantine_file(hostname, filepath)
        log.info("manual_quarantine", hostname=hostname, filepath=filepath, analyst=analyst_id)
        return action


# ── Module singleton ──────────────────────────────────────────────────────────
response_orchestrator = ResponseOrchestrator()
