"""
XDR Platform — Ingestion Pipeline
====================================
Handles all log ingestion entry points:
  - Async UDP socket receiver (Wazuh agents)
  - REST API ingestion endpoint
  - Log normalisation and deduplication

Architecture: Producer side of the Producer-Consumer pattern.
All ingested logs are pushed to a Redis queue for downstream processing.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import socket
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

import aioredis

from backend.core.settings import settings
from backend.core.logging_config import get_logger

log = get_logger("pipeline.ingestion")

# ── MITRE ATT&CK Rule Map ──────────────────────────────────────────────────────
# Wazuh rule ID → MITRE mapping (extended from original)
WAZUH_TO_MITRE: Dict[str, Dict[str, Any]] = {
    # Credential Access — Brute Force
    "5710": {"technique": "T1110", "name": "Brute Force",             "tactic": "Credential Access",   "score": 30, "sigma_rule": "XDR-001"},
    "5711": {"technique": "T1110", "name": "Brute Force",             "tactic": "Credential Access",   "score": 30, "sigma_rule": "XDR-001"},
    "5712": {"technique": "T1110", "name": "Brute Force",             "tactic": "Credential Access",   "score": 35, "sigma_rule": "XDR-001"},
    # Initial Access — Valid Accounts
    "5503": {"technique": "T1078", "name": "Valid Accounts",          "tactic": "Initial Access",      "score": 60, "sigma_rule": "XDR-002"},
    "5501": {"technique": "T1078", "name": "Valid Accounts",          "tactic": "Initial Access",      "score": 40, "sigma_rule": "XDR-002"},
    # Lateral Movement
    "5706": {"technique": "T1021", "name": "Remote Services",         "tactic": "Lateral Movement",    "score": 45, "sigma_rule": "XDR-003"},
    "5707": {"technique": "T1021", "name": "Remote Services",         "tactic": "Lateral Movement",    "score": 45, "sigma_rule": "XDR-003"},
    # Execution
    "554":  {"technique": "T1059", "name": "Command Line Interface",  "tactic": "Execution",           "score": 40, "sigma_rule": "XDR-005"},
    "550":  {"technique": "T1059", "name": "Command Line Interface",  "tactic": "Execution",           "score": 35, "sigma_rule": "XDR-005"},
    # Defense Evasion
    "87":   {"technique": "T1055", "name": "Process Injection",       "tactic": "Defense Evasion",     "score": 65, "sigma_rule": "XDR-006"},
    "510":  {"technique": "T1014", "name": "Rootkit",                 "tactic": "Defense Evasion",     "score": 75, "sigma_rule": "XDR-006"},
    # Persistence
    "2502": {"technique": "T1053", "name": "Scheduled Task",          "tactic": "Persistence",         "score": 45, "sigma_rule": "XDR-004"},
    "2503": {"technique": "T1053", "name": "Scheduled Task",          "tactic": "Persistence",         "score": 45, "sigma_rule": "XDR-004"},
    # Discovery
    "40101":{"technique": "T1046", "name": "Network Service Scan",    "tactic": "Discovery",           "score": 25, "sigma_rule": "XDR-007"},
    # Initial Access — Web
    "31101":{"technique": "T1190", "name": "Exploit Public App",      "tactic": "Initial Access",      "score": 60, "sigma_rule": "XDR-008"},
    "31103":{"technique": "T1190", "name": "Exploit Public App",      "tactic": "Initial Access",      "score": 60, "sigma_rule": "XDR-008"},
    # Exfiltration
    "40700":{"technique": "T1041", "name": "Exfil Over C2",           "tactic": "Exfiltration",        "score": 80, "sigma_rule": "XDR-009"},
    # Privilege Escalation
    "5401": {"technique": "T1548", "name": "Sudo Abuse",              "tactic": "Privilege Escalation","score": 65, "sigma_rule": "XDR-010"},
    "5402": {"technique": "T1548", "name": "Sudo Abuse",              "tactic": "Privilege Escalation","score": 65, "sigma_rule": "XDR-010"},
}

# ── Log Patterns for Pattern-Based Detection ────────────────────────────────────
_SSH_FAILED  = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)")
_SSH_SUCCESS = re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+) port (\d+)")
_SSH_INVALID = re.compile(r"Invalid user (\S+) from ([\d.]+)")
_SUDO_CMD    = re.compile(r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)")
_CRON_EVENT  = re.compile(r"CRON\[(\d+)\].*CMD \((.*)\)")


class LogNormalizer:
    """
    Transforms raw log strings into structured, normalised dictionaries.
    Supports auth.log, syslog, and Wazuh JSON alert formats.
    """

    @staticmethod
    def normalise(raw: str, agent_ip: str, hostname: Optional[str] = None) -> Dict[str, Any]:
        """
        Parse a raw log line into a structured event dict.

        Returns a dict with at minimum:
            timestamp, raw, type, agent_ip, hostname, source_ip, user, rule_id, mitre
        """
        result: Dict[str, Any] = {
            "timestamp":  datetime.utcnow().isoformat(),
            "raw":        raw.strip(),
            "agent_ip":   agent_ip,
            "hostname":   hostname or agent_ip,
            "type":       "generic",
            "user":       None,
            "source_ip":  None,
            "port":       None,
            "rule_id":    None,
            "mitre":      None,
        }

        # ── SSH Failed Auth ─────────────────────────────────────────────────
        m = _SSH_FAILED.search(raw)
        if m:
            result.update({
                "type":      "ssh_failed",
                "user":      m.group(1),
                "source_ip": m.group(2),
                "port":      m.group(3),
                "rule_id":   "5710",
            })

        # ── SSH Success ─────────────────────────────────────────────────────
        m = _SSH_SUCCESS.search(raw)
        if m:
            result.update({
                "type":      "ssh_success",
                "user":      m.group(1),
                "source_ip": m.group(2),
                "port":      m.group(3),
                "rule_id":   "5503",
            })

        # ── SSH Invalid User ────────────────────────────────────────────────
        m = _SSH_INVALID.search(raw)
        if m and not result.get("source_ip"):
            result.update({
                "type":      "ssh_invalid_user",
                "user":      m.group(1),
                "source_ip": m.group(2),
                "rule_id":   "5710",
            })

        # ── Sudo Command ────────────────────────────────────────────────────
        m = _SUDO_CMD.search(raw)
        if m:
            result.update({
                "type":    "sudo_command",
                "user":    m.group(1),
                "command": m.group(2).strip(),
                "rule_id": "5401",
            })

        # ── Cron Job ────────────────────────────────────────────────────────
        m = _CRON_EVENT.search(raw)
        if m:
            result.update({
                "type":    "cron_execution",
                "command": m.group(2).strip(),
                "rule_id": "2502",
            })

        # ── Attach MITRE mapping if rule found ──────────────────────────────
        if result["rule_id"]:
            result["mitre"] = WAZUH_TO_MITRE.get(result["rule_id"])

        # ── Compute deduplication hash ──────────────────────────────────────
        dedup_str = f"{agent_ip}:{result.get('rule_id')}:{result.get('source_ip')}:{raw[:100]}"
        result["log_hash"] = hashlib.sha256(dedup_str.encode()).hexdigest()

        return result

    @staticmethod
    def normalise_wazuh_json(payload: Dict[str, Any], agent_ip: str) -> Dict[str, Any]:
        """
        Parse a structured Wazuh JSON alert (as received from ossec-logtest
        or the Wazuh API) into the normalised event format.
        """
        rule = payload.get("rule", {})
        agent = payload.get("agent", {})
        data = payload.get("data", {})

        rule_id = str(rule.get("id", ""))
        raw = payload.get("full_log", json.dumps(payload))

        result: Dict[str, Any] = {
            "timestamp":   payload.get("timestamp", datetime.utcnow().isoformat()),
            "raw":         raw,
            "agent_ip":    agent_ip,
            "hostname":    agent.get("name", agent_ip),
            "type":        "wazuh_alert",
            "user":        data.get("dstuser") or data.get("srcuser"),
            "source_ip":   data.get("srcip") or payload.get("src_ip"),
            "rule_id":     rule_id,
            "rule_level":  rule.get("level", 0),
            "mitre":       WAZUH_TO_MITRE.get(rule_id),
        }

        # Dedup hash
        dedup_str = f"{agent_ip}:{rule_id}:{result.get('source_ip')}:{raw[:100]}"
        result["log_hash"] = hashlib.sha256(dedup_str.encode()).hexdigest()

        return result


# ── Redis Queue Producer ───────────────────────────────────────────────────────


class LogQueueProducer:
    """
    Pushes normalised log events onto a Redis list (LPUSH).
    The Detection/Correlation consumers read from the other end (BRPOP).
    """

    def __init__(self) -> None:
        self._redis: Optional[aioredis.Redis] = None
        self._queue_key = settings.REDIS_QUEUE_LOGS

    async def connect(self) -> None:
        """Establish connection to Redis. Called at application startup."""
        self._redis = await aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
        log.info("redis_producer_connected", queue=self._queue_key)

    async def disconnect(self) -> None:
        if self._redis:
            await self._redis.close()

    async def push(self, event: Dict[str, Any]) -> None:
        """
        Serialise and push a single log event to the queue.
        Silently no-ops if Redis is unavailable (graceful degradation).
        """
        if not self._redis:
            log.warning("redis_not_connected_skipping_push")
            return
        try:
            await self._redis.lpush(self._queue_key, json.dumps(event))
        except Exception as exc:
            log.error("redis_push_failed", error=str(exc))

    async def queue_depth(self) -> int:
        """Return the current number of events waiting in the queue."""
        if not self._redis:
            return 0
        try:
            return await self._redis.llen(self._queue_key)
        except Exception:
            return -1


# ── Async UDP Receiver ─────────────────────────────────────────────────────────


class AsyncUDPReceiver(asyncio.DatagramProtocol):
    """
    Async UDP server that receives log datagrams from Wazuh agents.
    Each received datagram is normalised and pushed to Redis.

    Replaces the blocking threading.Thread + socket.recvfrom approach
    in the original implementation with a fully async protocol handler.
    """

    def __init__(self, producer: LogQueueProducer) -> None:
        self._producer = producer
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._stats = {"received": 0, "errors": 0, "bytes": 0}

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport
        log.info("udp_receiver_started", host=settings.UDP_HOST, port=settings.UDP_PORT)

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Called on every incoming UDP datagram. Schedules async processing."""
        asyncio.get_event_loop().create_task(
            self._process_datagram(data, addr),
            name=f"ingest-{addr[0]}",
        )
        self._stats["received"] += 1
        self._stats["bytes"] += len(data)

    def error_received(self, exc: Exception) -> None:
        self._stats["errors"] += 1
        log.warning("udp_error", error=str(exc))

    def connection_lost(self, exc: Optional[Exception]) -> None:
        log.info("udp_receiver_stopped", stats=self._stats)

    async def _process_datagram(self, data: bytes, addr: Tuple[str, int]) -> None:
        """
        Parse raw UDP bytes into a structured event and push to queue.
        Handles both raw syslog strings and structured Wazuh JSON payloads.
        """
        agent_ip = addr[0]
        try:
            raw = data.decode("utf-8", errors="replace").strip()
            if not raw:
                return

            # Attempt JSON decode first (Wazuh structured alerts)
            try:
                payload = json.loads(raw)
                event = LogNormalizer.normalise_wazuh_json(payload, agent_ip)
            except json.JSONDecodeError:
                # Fall back to regex-based plain text parsing
                event = LogNormalizer.normalise(raw, agent_ip)

            await self._producer.push(event)
            log.debug("log_ingested", agent_ip=agent_ip, type=event.get("type"), rule_id=event.get("rule_id"))

        except Exception as exc:
            self._stats["errors"] += 1
            log.error("datagram_processing_error", agent_ip=agent_ip, error=str(exc))

    def get_stats(self) -> Dict[str, int]:
        return dict(self._stats)


async def start_udp_receiver(producer: LogQueueProducer) -> asyncio.DatagramTransport:
    """
    Bind the async UDP receiver to the configured host/port.
    Returns the transport so the caller can stop it on shutdown.
    """
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: AsyncUDPReceiver(producer),
        local_addr=(settings.UDP_HOST, settings.UDP_PORT),
    )
    return transport
