"""
XDR Platform — Heuristic ML Detection
=======================================
Provides unsupervised anomaly detection (IsolationForest) and a
RandomForest classifier for alert severity prediction.

Feature Engineering (per alert):
  - hour_of_day          : 0–23 (unusual hours = higher suspicion)
  - log_frequency        : events from this IP in the last 5 min
  - entropy_of_command   : Shannon entropy of command string (if present)
  - rule_level           : Wazuh rule severity level
  - base_score           : MITRE score from rule mapping
  - is_root              : 1 if user == root
  - is_ssh               : 1 if source is SSH
  - is_after_hours       : 1 if 22:00–06:00
  - tactic_ordinal       : Position in MITRE kill chain (0–12)
  - unique_rules_from_ip : distinct rule IDs from this IP in window
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler

from backend.pipeline.correlation.engine import KILL_CHAIN_ORDER
from backend.core.logging_config import get_logger

log = get_logger("pipeline.ml")

# ── Feature names (must stay in sync with extract_features) ──────────────────
FEATURE_NAMES = [
    "hour_of_day",
    "log_frequency",
    "entropy_of_command",
    "rule_level",
    "base_score",
    "is_root",
    "is_ssh",
    "is_after_hours",
    "tactic_ordinal",
    "unique_rules_from_ip",
]

SEVERITY_LABELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _shannon_entropy(text: Optional[str]) -> float:
    """
    Compute Shannon entropy of a string.
    High entropy commands (random-looking) are typical of encoded payloads.
    """
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


class FeatureExtractor:
    """
    Stateful feature extractor that tracks per-IP activity windows
    to compute frequency and diversity features.
    """

    def __init__(self) -> None:
        # ip → list of (timestamp, rule_id) tuples
        self._ip_events: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
        self._window = timedelta(minutes=5)

    def record(self, ip: str, rule_id: Optional[str], ts: Optional[datetime] = None) -> None:
        """Track an event from *ip* for frequency computation."""
        ts = ts or datetime.utcnow()
        self._ip_events[ip].append((ts, rule_id or ""))
        # Keep window clean
        cutoff = datetime.utcnow() - self._window
        self._ip_events[ip] = [(t, r) for t, r in self._ip_events[ip] if t > cutoff]

    def extract(self, alert: Dict[str, Any]) -> np.ndarray:
        """
        Convert an alert dict into a fixed-length numpy feature vector.

        Parameters
        ----------
        alert : dict with keys: rule_level, score, user, source, command,
                                source_ip, rule_id, mitre (dict)

        Returns
        -------
        np.ndarray of shape (1, len(FEATURE_NAMES))
        """
        now = datetime.utcnow()
        ip  = alert.get("source_ip", "")

        # Time features
        hour        = now.hour
        after_hours = 1.0 if (hour >= 22 or hour < 6) else 0.0

        # Frequency features
        cutoff          = now - self._window
        recent          = [(t, r) for t, r in self._ip_events.get(ip, []) if t > cutoff]
        log_frequency   = float(len(recent))
        unique_rules    = float(len({r for _, r in recent}))

        # Command entropy (payload obfuscation indicator)
        command         = alert.get("command") or alert.get("raw", "")
        entropy         = _shannon_entropy(command[:200])  # cap at 200 chars

        # Wazuh rule features
        rule_level  = float(alert.get("rule_level", 0) or 0)
        base_score  = float((alert.get("mitre") or {}).get("score", 0))

        # User / source features
        is_root = 1.0 if str(alert.get("user", "")).lower() == "root" else 0.0
        is_ssh  = 1.0 if "ssh" in str(alert.get("source", "")).lower() else 0.0

        # MITRE tactic ordinal
        tactic = (alert.get("mitre") or {}).get("tactic", "")
        try:
            tactic_ordinal = float(KILL_CHAIN_ORDER.index(tactic))
        except ValueError:
            tactic_ordinal = 0.0

        features = np.array([[
            float(hour),
            log_frequency,
            entropy,
            rule_level,
            base_score,
            is_root,
            is_ssh,
            after_hours,
            tactic_ordinal,
            unique_rules,
        ]])

        return features


class AnomalyDetector:
    """
    Unsupervised anomaly detection using IsolationForest.
    Detects alerts that deviate statistically from the baseline profile.

    Training: Requires ≥ 20 samples. Retrain periodically (e.g., nightly)
    using the last N alerts from the database.
    """

    MIN_SAMPLES_TO_TRAIN = 20

    def __init__(self, feature_extractor: FeatureExtractor) -> None:
        self.extractor   = feature_extractor
        self._model      = IsolationForest(
            contamination=0.08,   # Expect ~8% anomalies
            n_estimators=200,
            random_state=42,
            n_jobs=-1,
        )
        self._scaler     = StandardScaler()
        self.is_trained  = False

    def train(self, historical_alerts: List[Dict[str, Any]]) -> bool:
        """
        Fit the IsolationForest on historical alert data.
        Returns True if training succeeded.
        """
        if len(historical_alerts) < self.MIN_SAMPLES_TO_TRAIN:
            log.warning("ml_insufficient_samples",
                        have=len(historical_alerts),
                        need=self.MIN_SAMPLES_TO_TRAIN)
            return False

        X = np.vstack([self.extractor.extract(a) for a in historical_alerts])
        X_scaled = self._scaler.fit_transform(X)
        self._model.fit(X_scaled)
        self.is_trained = True
        log.info("anomaly_model_trained", samples=len(historical_alerts))
        return True

    def predict(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Score a single alert for anomalousness.

        Returns a dict with:
          - is_anomaly (bool)
          - anomaly_score (float 0–1, higher = more anomalous)
          - features (dict, for explainability)
          - message (str)
        """
        if not self.is_trained:
            return {
                "is_anomaly":    False,
                "anomaly_score": 0.0,
                "message":       "Model not yet trained — using rule-based detection only.",
                "features":      {},
            }

        features = self.extractor.extract(alert)
        features_scaled = self._scaler.transform(features)

        prediction  = self._model.predict(features_scaled)[0]     # 1 = normal, -1 = anomaly
        raw_score   = self._model.score_samples(features_scaled)[0]

        is_anomaly      = prediction == -1
        anomaly_score   = round(float(1 - (raw_score + 0.5)), 3)  # Normalise to ~0–1
        anomaly_score   = max(0.0, min(1.0, anomaly_score))

        feature_dict = dict(zip(FEATURE_NAMES, features.flatten().tolist()))

        return {
            "is_anomaly":    is_anomaly,
            "anomaly_score": anomaly_score,
            "message":       "Anomalous behaviour detected by ML model." if is_anomaly else "Normal behaviour profile.",
            "features":      feature_dict,
        }

    def score_boost(self, base_score: float, anomaly_result: Dict[str, Any]) -> float:
        """
        Boost the base threat score if ML flags an anomaly.
        Caps at 100.
        """
        if not anomaly_result.get("is_anomaly"):
            return base_score
        boost = anomaly_result["anomaly_score"] * 15  # Up to +15 pts
        return min(base_score + boost, 100.0)


class SeverityClassifier:
    """
    Supervised RandomForest classifier for predicting alert severity.
    Trained on labelled historical alerts where severity is known.

    This complements the rule-based scoring with a data-driven perspective.
    """

    MIN_SAMPLES_TO_TRAIN = 40  # Need at least 10 per class

    def __init__(self, feature_extractor: FeatureExtractor) -> None:
        self.extractor   = feature_extractor
        self._model      = RandomForestClassifier(
            n_estimators=100,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        self._encoder    = LabelEncoder()
        self._scaler     = StandardScaler()
        self.is_trained  = False

    def train(self, labelled_alerts: List[Dict[str, Any]]) -> bool:
        """
        Fit the classifier on alerts that have a known severity label.

        Expected dict keys: all alert fields + 'severity' (LOW/MEDIUM/HIGH/CRITICAL).
        """
        if len(labelled_alerts) < self.MIN_SAMPLES_TO_TRAIN:
            log.warning("classifier_insufficient_samples",
                        have=len(labelled_alerts),
                        need=self.MIN_SAMPLES_TO_TRAIN)
            return False

        X = np.vstack([self.extractor.extract(a) for a in labelled_alerts])
        y = [a.get("severity", "MEDIUM") for a in labelled_alerts]

        X_scaled = self._scaler.fit_transform(X)
        y_enc    = self._encoder.fit_transform(y)

        self._model.fit(X_scaled, y_enc)
        self.is_trained = True
        log.info("severity_classifier_trained", samples=len(labelled_alerts))
        return True

    def predict_severity(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict severity and return class probabilities for explainability.
        Falls back to None if not trained.
        """
        if not self.is_trained:
            return {"ml_severity": None, "ml_confidence": 0.0}

        features    = self.extractor.extract(alert)
        features_sc = self._scaler.transform(features)

        pred_idx    = self._model.predict(features_sc)[0]
        proba       = self._model.predict_proba(features_sc)[0]

        predicted_label  = self._encoder.inverse_transform([pred_idx])[0]
        confidence       = round(float(max(proba)), 3)

        class_proba = dict(zip(self._encoder.classes_, proba.tolist()))

        return {
            "ml_severity":   predicted_label,
            "ml_confidence": confidence,
            "class_proba":   class_proba,
        }


# ── Module-level singletons ───────────────────────────────────────────────────

_feature_extractor    = FeatureExtractor()
anomaly_detector      = AnomalyDetector(_feature_extractor)
severity_classifier   = SeverityClassifier(_feature_extractor)
feature_extractor     = _feature_extractor  # Expose for external recording
