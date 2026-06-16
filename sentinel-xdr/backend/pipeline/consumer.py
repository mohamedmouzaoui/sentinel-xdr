"""
XDR Platform — Async Pipeline Consumer
========================================
The Consumer is the "processing spine" of the XDR platform.

It pulls normalised log events from the Redis queue and orchestrates
the full detection pipeline in order:

  Log Event → Persist → ML Score → Detect → Enrich → Correlate → Respond

Architecture: Multiple consumer worker tasks run concurrently using
asyncio.gather(), providing horizontal throughput without threads.
Batch processing is used to amortise DB round-trips.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

import aioredis
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.database import AsyncSessionLocal
from backend.core.models import Alert, BlockedIP, Incident, Log
from backend.ml.detector import anomaly_detector, feature_extractor, severity_classifier
from backend.pipeline.correlation.engine import AlertEvent, correlation_engine
from backend.pipeline.enrichment.enricher import enrichment_orchestrator
from backend.pipeline.response.responder import response_orchestrator
from backend.core.logging_config import get_logger
from backend.core.settings import settings

log = get_logger("pipeline.consumer")


# ── Pipeline Consumer ──────────────────────────────────────────────────────────

class PipelineConsumer:
    """
    Async Redis queue consumer that processes log events end-to-end.

    Each call to ``run()`` starts *concurrency* worker coroutines.
    Workers pull from the same Redis list and process events independently,
    providing natural load distribution without inter-process locking.
    """

    def __init__(self, concurrency: int = 4) -> None:
        self._concurrency  = concurrency
        self._redis:  Optional[aioredis.Redis] = None
        self._running: bool = False
        self._stats: Dict[str, int] = {
            "processed": 0, "alerts_created": 0,
            "incidents_created": 0, "errors": 0,
        }

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Connect to Redis and launch worker coroutines."""
        self._redis = await aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
        self._running = True
        log.info("consumer_started",
                 concurrency=self._concurrency,
                 queue=settings.REDIS_QUEUE_LOGS)

        # Launch N concurrent workers
        await asyncio.gather(*[
            self._worker(worker_id=i)
            for i in range(self._concurrency)
        ])

    async def stop(self) -> None:
        """Signal all workers to stop after their current batch."""
        self._running = False
        if self._redis:
            await self._redis.close()
        log.info("consumer_stopped", stats=self._stats)

    def get_stats(self) -> Dict[str, Any]:
        return {**self._stats, "running": self._running}

    # ── Worker Loop ───────────────────────────────────────────────────────────

    async def _worker(self, worker_id: int) -> None:
        """
        Single worker coroutine. Polls the Redis queue using BRPOP
        (blocking right-pop) with a 1-second timeout to yield to other
        coroutines when the queue is empty.
        """
        log.info("worker_started", worker_id=worker_id)
        while self._running:
            try:
                # BRPOP returns (queue_name, value) or None on timeout
                result = await self._redis.brpop(
                    settings.REDIS_QUEUE_LOGS,
                    timeout=1,
                )
                if not result:
                    continue  # Timeout — loop and check _running

                _, raw_json = result
                event = json.loads(raw_json)
                await self._process_event(event, worker_id)
                self._stats["processed"] += 1

            except json.JSONDecodeError as exc:
                log.warning("malformed_json_in_queue", error=str(exc))
                self._stats["errors"] += 1
            except Exception as exc:
                log.error("worker_error", worker_id=worker_id, error=str(exc))
                self._stats["errors"] += 1
                await asyncio.sleep(0.5)  # Brief backoff on repeated errors

        log.info("worker_stopped", worker_id=worker_id)

    # ── Full Pipeline Execution ───────────────────────────────────────────────

    async def _process_event(self, event: Dict[str, Any], worker_id: int) -> None:
        """
        Execute the full detection pipeline for a single log event.
        Each stage is independent; a failure in one stage does not block
        the subsequent stages.

        Stages:
          1. Persist raw log to database
          2. ML anomaly scoring
          3. Alert creation (if MITRE rule matched)
          4. Enrichment (GeoIP + Threat Intel + Host context)
          5. Correlation (multi-stage incident detection)
          6. Incident creation + auto-response
        """
        async with AsyncSessionLocal() as db:
            try:
                # ── Stage 1: Persist raw log ──────────────────────────────────
                db_log = await self._persist_log(db, event)

                # ── Stage 2: ML scoring ───────────────────────────────────────
                # Record this event in the ML feature extractor's IP buffer
                feature_extractor.record(
                    ip=event.get("agent_ip", ""),
                    rule_id=event.get("rule_id"),
                )
                ml_result   = anomaly_detector.predict(event)
                ml_severity = severity_classifier.predict_severity(event)

                # ── Stage 3: Alert creation ───────────────────────────────────
                mitre = event.get("mitre")
                if not mitre:
                    # No MITRE mapping — skip alert creation
                    await db.commit()
                    return

                source_ip = event.get("source_ip")
                if not source_ip:
                    await db.commit()
                    return

                # Compute final threat score (base + ML boost)
                base_score = float(mitre.get("score", 0))
                final_score = anomaly_detector.score_boost(base_score, ml_result)

                severity = settings.score_to_severity(final_score)

                db_alert = Alert(
                    title=f"{mitre['name']} detected from {source_ip}",
                    description=(
                        f"Rule {event.get('rule_id')} triggered — "
                        f"{mitre['technique']} ({mitre['tactic']}). "
                        f"{'[ML ANOMALY] ' if ml_result['is_anomaly'] else ''}"
                        f"Threat score: {final_score}/100."
                    ),
                    severity=severity,
                    score=final_score,
                    source_ip=source_ip,
                    target_hostname=event.get("hostname"),
                    sigma_rule_id=mitre.get("sigma_rule"),
                    rule_id=event.get("rule_id"),
                    mitre_technique=mitre["technique"],
                    mitre_tactic=mitre["tactic"],
                    mitre_name=mitre["name"],
                    raw_data=event,
                    ml_features={
                        "anomaly": ml_result,
                        "severity_prediction": ml_severity,
                    },
                )
                db.add(db_alert)
                await db.flush()  # Get db_alert.id without full commit

                log.info("alert_created",
                         alert_id=db_alert.id,
                         source_ip=source_ip,
                         severity=severity,
                         score=final_score,
                         is_anomaly=ml_result["is_anomaly"])
                self._stats["alerts_created"] += 1

                # ── Stage 4: Enrichment ───────────────────────────────────────
                enrichment = await enrichment_orchestrator.enrich_alert(
                    source_ip=source_ip,
                    target_hostname=event.get("hostname"),
                )
                db_alert.enrichment = enrichment
                await db.flush()

                # ── Stage 5: Feed Correlation Engine ─────────────────────────
                corr_event = AlertEvent(
                    alert_id=db_alert.id,
                    source_ip=source_ip,
                    target_hostname=event.get("hostname"),
                    mitre_tactic=mitre["tactic"],
                    mitre_technique=mitre["technique"],
                    sigma_rule_id=mitre.get("sigma_rule"),
                    rule_id=event.get("rule_id"),
                    score=final_score,
                )
                correlation_engine.ingest(corr_event)

                # Try to correlate buffered events for this IP
                correlation = correlation_engine.correlate(source_ip)

                # ── Stage 6: Incident creation + auto-response ────────────────
                if correlation and correlation["score"] >= settings.SCORE_MEDIUM_THRESHOLD:
                    await self._handle_correlation(db, db_alert, correlation)

                await db.commit()
                log.debug("pipeline_complete",
                          worker_id=worker_id,
                          alert_id=db_alert.id,
                          source_ip=source_ip)

            except Exception as exc:
                await db.rollback()
                log.error("pipeline_stage_failed", error=str(exc), event_type=event.get("type"))
                self._stats["errors"] += 1

    async def _persist_log(self, db: AsyncSession, event: Dict[str, Any]) -> Log:
        """Stage 1: Write the raw log record to the database."""
        db_log = Log(
            hostname=event.get("hostname"),
            agent_ip=event.get("agent_ip"),
            source=event.get("source", "agent"),
            raw_log=event.get("raw", ""),
            parsed_data={k: v for k, v in event.items() if k != "raw"},
            rule_id=event.get("rule_id"),
            rule_level=int(event.get("rule_level", 0) or 0),
            log_hash=event.get("log_hash"),
        )
        db.add(db_log)
        await db.flush()
        return db_log

    async def _handle_correlation(
        self,
        db: AsyncSession,
        db_alert: Alert,
        correlation: Dict[str, Any],
    ) -> None:
        """Stage 6: Persist incident and trigger auto-response."""
        from sqlalchemy import select

        # Check for existing open incident from this IP
        stmt = select(Incident).where(
            Incident.source_ip == correlation["source_ip"],
            Incident.status == "OPEN",
        )
        result = await db.execute(stmt)
        existing_incident = result.scalar_one_or_none()

        if existing_incident:
            # Update existing incident (append alert, refresh score)
            existing_incident.score = max(existing_incident.score, correlation["score"])
            existing_incident.severity = settings.score_to_severity(existing_incident.score)
            existing_incident.kill_chain_phase = correlation["kill_chain_phase"]
            existing_incident.prediction = correlation["prediction"]
            existing_incident.mitre_tactics = correlation["mitre_tactics"]
            existing_incident.mitre_techniques = correlation["mitre_techniques"]
            existing_incident.timeline = correlation["timeline"]
            existing_incident.updated_at = datetime.utcnow()
            db_alert.incident_id = existing_incident.id
            log.info("incident_updated",
                     incident_id=existing_incident.id,
                     new_score=existing_incident.score)
            return

        # Create new incident
        host_criticality = settings.get_host_criticality(
            correlation.get("target_hostname", "")
        )
        db_incident = Incident(
            title=correlation["title"],
            description=correlation["description"],
            severity=correlation["severity"],
            score=correlation["score"],
            source_ip=correlation["source_ip"],
            target_hostname=correlation.get("target_hostname"),
            host_criticality=host_criticality,
            mitre_tactics=correlation["mitre_tactics"],
            mitre_techniques=correlation["mitre_techniques"],
            kill_chain_phase=correlation["kill_chain_phase"],
            prediction=correlation["prediction"],
            recommended_action=correlation.get("recommended_action"),
            timeline=correlation["timeline"],
            correlation_path=correlation.get("correlation_path"),
        )
        db.add(db_incident)
        await db.flush()

        db_alert.incident_id = db_incident.id

        log.info("incident_created",
                 incident_id=db_incident.id,
                 score=db_incident.score,
                 severity=db_incident.severity,
                 phase=db_incident.kill_chain_phase,
                 correlation_type=correlation.get("correlation_type"))
        self._stats["incidents_created"] += 1

        # Auto-respond asynchronously (don't block the pipeline)
        asyncio.create_task(
            self._auto_respond(db_incident),
            name=f"respond-{db_incident.id}",
        )

    async def _auto_respond(self, incident: Incident) -> None:
        """Execute automated response actions and persist the results."""
        try:
            response = await response_orchestrator.auto_respond({
                "id":               incident.id,
                "title":            incident.title,
                "description":      incident.description,
                "severity":         incident.severity,
                "score":            incident.score,
                "source_ip":        incident.source_ip,
                "target_hostname":  incident.target_hostname,
                "kill_chain_phase": incident.kill_chain_phase,
                "recommended_action": incident.recommended_action,
                "mitre_tactics":    incident.mitre_tactics,
                "mitre_techniques": incident.mitre_techniques,
            })

            # Update incident with response actions
            async with AsyncSessionLocal() as db:
                from sqlalchemy import select
                stmt = select(Incident).where(Incident.id == incident.id)
                result = await db.execute(stmt)
                db_incident = result.scalar_one_or_none()
                if db_incident:
                    db_incident.auto_response = response
                    await db.commit()

        except Exception as exc:
            log.error("auto_respond_failed", incident_id=incident.id, error=str(exc))


# ── Module singleton ──────────────────────────────────────────────────────────
pipeline_consumer = PipelineConsumer(concurrency=4)
