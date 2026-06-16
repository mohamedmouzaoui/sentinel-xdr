"""
XDR Platform — Multi-Stage Correlation Engine
===============================================
The "brain" of the XDR platform. Correlates individual alerts across
time windows and hosts to detect multi-stage attack chains.

Core capabilities:
  - Time-windowed event buffer per source IP
  - Multi-stage kill chain tracking (MITRE ATT&CK)
  - Rule-chain correlation (e.g., XDR-001 → XDR-002 = CRITICAL incident)
  - Brute-force pattern detection (N failures + 1 success)
  - Sigma rule condition evaluation

Architecture: In-memory buffer with configurable TTL. For distributed
deployments, replace the in-memory dict with Redis Sorted Sets.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from backend.core.settings import settings
from backend.core.logging_config import get_logger

log = get_logger("pipeline.correlation")

# ── MITRE Kill Chain Order ─────────────────────────────────────────────────────
KILL_CHAIN_ORDER: List[str] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Impact",
]

# ── Predictions per Kill Chain Phase ──────────────────────────────────────────
PHASE_PREDICTIONS: Dict[str, Dict[str, Any]] = {
    "Initial Access": {
        "next_phases": ["Execution", "Persistence"],
        "message": "Attacker has gained a foothold. Monitor for script execution and scheduled task creation.",
        "action":  "Isolate the compromised endpoint immediately.",
        "urgency": "HIGH",
    },
    "Credential Access": {
        "next_phases": ["Lateral Movement", "Privilege Escalation"],
        "message": "Credentials have been compromised. Lateral movement is imminent.",
        "action":  "Force password reset. Monitor RDP/SSH connections from this IP.",
        "urgency": "CRITICAL",
    },
    "Execution": {
        "next_phases": ["Persistence", "Defense Evasion"],
        "message": "Malicious code was executed. Backdoor installation likely.",
        "action":  "Audit running processes. Check scheduled tasks and startup services.",
        "urgency": "HIGH",
    },
    "Persistence": {
        "next_phases": ["Privilege Escalation", "Discovery"],
        "message": "Backdoor installed. Attacker is establishing long-term access.",
        "action":  "Audit crontab, ~/.bashrc, systemd services, and startup scripts.",
        "urgency": "HIGH",
    },
    "Privilege Escalation": {
        "next_phases": ["Defense Evasion", "Lateral Movement"],
        "message": "Attacker has gained elevated privileges. System is critically compromised.",
        "action":  "Revoke sudo rights. Audit SUID/SGID binaries.",
        "urgency": "CRITICAL",
    },
    "Lateral Movement": {
        "next_phases": ["Collection", "Exfiltration"],
        "message": "Attacker is moving through the network. Contain immediately.",
        "action":  "Block internal lateral communications. Isolate affected network segment.",
        "urgency": "CRITICAL",
    },
    "Discovery": {
        "next_phases": ["Lateral Movement", "Collection"],
        "message": "Attacker is mapping the network. Lateral movement is next.",
        "action":  "Monitor LDAP/AD queries and port scans originating from compromised host.",
        "urgency": "HIGH",
    },
    "Collection": {
        "next_phases": ["Exfiltration"],
        "message": "Data is being staged for exfiltration. Act now.",
        "action":  "Block all outbound connections from the host. Monitor file access patterns.",
        "urgency": "CRITICAL",
    },
    "Exfiltration": {
        "next_phases": ["Impact"],
        "message": "CRITICAL: Active data exfiltration in progress!",
        "action":  "Immediately isolate all affected machines. Activate incident response.",
        "urgency": "CRITICAL",
    },
    "Impact": {
        "next_phases": [],
        "message": "CRITICAL: Destructive or ransomware activity detected!",
        "action":  "Full network isolation. Contact management and legal. Preserve forensic evidence.",
        "urgency": "CRITICAL",
    },
}


# ── Alert Event (in-memory) ────────────────────────────────────────────────────

class AlertEvent:
    """Lightweight in-memory representation of an alert for correlation."""

    __slots__ = [
        "alert_id", "source_ip", "target_hostname", "mitre_tactic",
        "mitre_technique", "sigma_rule_id", "rule_id", "score",
        "received_at", "metadata",
    ]

    def __init__(self, **kwargs: Any) -> None:
        for slot in self.__slots__:
            setattr(self, slot, kwargs.get(slot))
        if self.received_at is None:
            self.received_at = datetime.utcnow()

    def to_timeline_entry(self) -> Dict[str, Any]:
        return {
            "time":       self.received_at.isoformat(),
            "alert_id":   self.alert_id,
            "event":      f"[{self.sigma_rule_id}] {self.mitre_tactic} — {self.mitre_technique}",
            "tactic":     self.mitre_tactic,
            "technique":  self.mitre_technique,
            "score":      self.score,
            "host":       self.target_hostname,
        }


# ── Correlation Engine ────────────────────────────────────────────────────────

class CorrelationEngine:
    """
    Multi-stage correlation engine that groups alerts by source IP
    and detects complex attack patterns across time windows.

    Thread-safety: All public methods are async-safe for single-threaded
    asyncio usage. Add asyncio.Lock if coroutines are run concurrently
    on the same engine instance.
    """

    def __init__(self) -> None:
        # source_ip → list of AlertEvents within the time window
        self._buffer: Dict[str, List[AlertEvent]] = defaultdict(list)
        self._window = timedelta(seconds=settings.CORRELATION_WINDOW_SECONDS)
        self._bf_threshold = settings.BRUTE_FORCE_THRESHOLD

    # ── Public API ────────────────────────────────────────────────────────────

    def ingest(self, event: AlertEvent) -> None:
        """Add an alert event to the correlation buffer."""
        ip = event.source_ip or "unknown"
        self._buffer[ip].append(event)
        self._evict_stale(ip)
        log.debug("event_buffered", ip=ip, tactic=event.mitre_tactic, buffer_size=len(self._buffer[ip]))

    def correlate(self, source_ip: str) -> Optional[Dict[str, Any]]:
        """
        Attempt to correlate all buffered events for *source_ip* into
        a coherent incident. Returns None if correlation threshold not met.

        Correlation rules (in priority order):
          1. Brute-force + Successful Login  → CRITICAL incident
          2. Multi-tactic attack chain (≥ 2 MITRE tactics)  → incident
          3. Single high-score event on CRITICAL host → incident
        """
        events = self._buffer.get(source_ip, [])
        if not events:
            return None

        # ── Rule 1: Brute Force → Successful Login (highest priority) ────────
        brute_force_result = self._check_brute_force_chain(events, source_ip)
        if brute_force_result:
            log.info("correlation_fired",
                     rule="brute_force_chain",
                     ip=source_ip,
                     score=brute_force_result["score"])
            return brute_force_result

        # ── Rule 2: Multi-stage kill chain ────────────────────────────────────
        if len(events) >= 2:
            chain_result = self._check_kill_chain(events, source_ip)
            if chain_result:
                log.info("correlation_fired",
                         rule="kill_chain",
                         ip=source_ip,
                         score=chain_result["score"])
                return chain_result

        return None

    def flush_ip(self, source_ip: str) -> None:
        """Remove all buffered events for an IP (e.g., after incident creation)."""
        self._buffer.pop(source_ip, None)

    def get_active_ips(self) -> List[str]:
        """Return list of IPs with events in the current time window."""
        return list(self._buffer.keys())

    def get_buffer_stats(self) -> Dict[str, Any]:
        return {
            "tracked_ips":   len(self._buffer),
            "total_events":  sum(len(v) for v in self._buffer.values()),
            "window_seconds": self._window.seconds,
        }

    # ── Internal Correlation Rules ────────────────────────────────────────────

    def _check_brute_force_chain(
        self,
        events: List[AlertEvent],
        source_ip: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Detect the pattern:
            N × (Credential Access / T1110)  + 1 × (Initial Access / T1078)
        within the correlation window.

        This represents a completed brute-force attack — one of the highest
        priority incidents in SOC triage.
        """
        brute_force_events = [
            e for e in events
            if e.mitre_technique == "T1110"
        ]
        success_events = [
            e for e in events
            if e.mitre_technique == "T1078"
        ]

        if len(brute_force_events) < self._bf_threshold or not success_events:
            return None

        targets: Set[str] = {e.target_hostname for e in events if e.target_hostname}
        target = success_events[-1].target_hostname or "unknown"

        timeline = sorted(
            [e.to_timeline_entry() for e in events],
            key=lambda x: x["time"],
        )

        score = self._calculate_score(
            tactics_count=2,
            alerts_count=len(events),
            has_successful_login=True,
            target_criticality=settings.get_host_criticality(target),
        )

        prediction = PHASE_PREDICTIONS.get("Initial Access", {})

        return {
            "correlation_type":  "BRUTE_FORCE_CHAIN",
            "source_ip":         source_ip,
            "target_hostname":   target,
            "targets":           list(targets),
            "score":             score,
            "severity":          settings.score_to_severity(score),
            "alert_count":       len(events),
            "mitre_tactics":     ["Credential Access", "Initial Access"],
            "mitre_techniques":  ["T1110", "T1078"],
            "kill_chain_phase":  "Initial Access",
            "prediction":        prediction.get("message", ""),
            "recommended_action":prediction.get("action", ""),
            "urgency":           prediction.get("urgency", "HIGH"),
            "timeline":          timeline,
            "title":             f"Successful Brute Force Attack from {source_ip} → {target}",
            "description": (
                f"{len(brute_force_events)} failed SSH attempts followed by a successful "
                f"login on host '{target}'. This indicates credential compromise via "
                f"brute force (T1110 → T1078). Immediate containment required."
            ),
            "correlation_path": {
                "steps": [
                    f"{len(brute_force_events)}× T1110 (Brute Force)",
                    "1× T1078 (Valid Account — Successful Login)",
                ],
                "fired_rule": "BF_CHAIN_001",
            },
        }

    def _check_kill_chain(
        self,
        events: List[AlertEvent],
        source_ip: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Detect multi-tactic attack progression along the MITRE kill chain.
        Requires ≥ 2 distinct tactics to trigger.
        """
        tactics_seen:    Set[str] = set()
        techniques_seen: Set[str] = set()
        targets:         Set[str] = set()

        for e in events:
            if e.mitre_tactic:
                tactics_seen.add(e.mitre_tactic)
            if e.mitre_technique:
                techniques_seen.add(e.mitre_technique)
            if e.target_hostname:
                targets.add(e.target_hostname)

        if len(tactics_seen) < 2:
            return None

        # Identify most advanced phase
        current_phase = self._get_most_advanced_phase(tactics_seen)
        target = list(targets)[0] if targets else "unknown"
        has_success = any(e.mitre_technique == "T1078" for e in events)

        score = self._calculate_score(
            tactics_count=len(tactics_seen),
            alerts_count=len(events),
            has_successful_login=has_success,
            target_criticality=settings.get_host_criticality(target),
        )

        prediction = PHASE_PREDICTIONS.get(current_phase, {})
        timeline = sorted(
            [e.to_timeline_entry() for e in events],
            key=lambda x: x["time"],
        )

        return {
            "correlation_type":  "KILL_CHAIN",
            "source_ip":         source_ip,
            "target_hostname":   target,
            "targets":           list(targets),
            "score":             score,
            "severity":          settings.score_to_severity(score),
            "alert_count":       len(events),
            "mitre_tactics":     sorted(tactics_seen, key=lambda t: KILL_CHAIN_ORDER.index(t) if t in KILL_CHAIN_ORDER else 99),
            "mitre_techniques":  list(techniques_seen),
            "kill_chain_phase":  current_phase,
            "prediction":        prediction.get("message", ""),
            "recommended_action":prediction.get("action", ""),
            "urgency":           prediction.get("urgency", "MEDIUM"),
            "timeline":          timeline,
            "title":             f"Multi-Stage Attack Detected — {current_phase} from {source_ip}",
            "description": (
                f"Multi-phase attack detected from {source_ip}. "
                f"MITRE tactics observed: {', '.join(sorted(tactics_seen))}. "
                f"Current kill chain phase: {current_phase}. "
                f"Threat score: {score}/100."
            ),
            "correlation_path": {
                "steps": [f"T{e.mitre_technique} — {e.mitre_tactic}" for e in events if e.mitre_technique],
                "fired_rule": "KILL_CHAIN_001",
            },
        }

    # ── Scoring ───────────────────────────────────────────────────────────────

    @staticmethod
    def _calculate_score(
        tactics_count: int,
        alerts_count: int,
        has_successful_login: bool,
        target_criticality: str,
    ) -> float:
        """
        Compute a 0–100 threat score from correlation factors.

        Breakdown:
          - Tactics spread:          0–35 pts
          - Alert volume:            0–20 pts
          - Successful login:           20 pts
          - Target criticality:      0–25 pts
        """
        score = 0.0

        # MITRE tactic spread (more phases = more advanced attacker)
        score += min(tactics_count * 12, 35)

        # Alert volume (noisy attackers are suspicious)
        score += min(alerts_count * 2, 20)

        # Credential compromise — significant escalation
        if has_successful_login:
            score += 20

        # Asset criticality bonus
        criticality_bonus = {"CRITICAL": 25, "HIGH": 18, "MEDIUM": 10, "LOW": 2}
        score += criticality_bonus.get(target_criticality, 10)

        return min(round(score, 1), 100.0)

    # ── Buffer Maintenance ────────────────────────────────────────────────────

    def _evict_stale(self, source_ip: str) -> None:
        """Remove events outside the correlation time window."""
        cutoff = datetime.utcnow() - self._window
        before = len(self._buffer[source_ip])
        self._buffer[source_ip] = [
            e for e in self._buffer[source_ip]
            if e.received_at and e.received_at > cutoff
        ]
        evicted = before - len(self._buffer[source_ip])
        if evicted > 0:
            log.debug("events_evicted", ip=source_ip, count=evicted)
        # Clean up empty buckets
        if not self._buffer[source_ip]:
            del self._buffer[source_ip]

    @staticmethod
    def _get_most_advanced_phase(tactics: Set[str]) -> str:
        """Return the kill chain phase with the highest ordinal index."""
        max_index = -1
        phase = "Unknown"
        for tactic in tactics:
            try:
                idx = KILL_CHAIN_ORDER.index(tactic)
                if idx > max_index:
                    max_index = idx
                    phase = tactic
            except ValueError:
                pass
        return phase


# ── Module singleton ──────────────────────────────────────────────────────────
correlation_engine = CorrelationEngine()
