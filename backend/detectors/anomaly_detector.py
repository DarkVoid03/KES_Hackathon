"""
Anomaly Detector — Isolation Forest on user behaviour features.
Requires a pre-trained model or will train a quick demo model on startup.
"""

import os
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from datetime import datetime


class AnomalyDetector:

    def __init__(self):
        model_path = "models/anomaly_iforest.pkl"
        if os.path.exists(model_path):
            self._model = joblib.load(model_path)
        else:
            # Train a quick demo model with synthetic normal behaviour
            self._model = self._train_demo_model()

    def predict(self, log_data: list) -> dict:
        """
        log_data: list of event dicts with keys:
            timestamp, user_id, ip_address, device_id,
            action, resource, geo_lat, geo_lon
        """
        if not log_data:
            return {"score": 0.0, "confidence": 0.5, "reason": "No data"}

        features = self._extract_features(log_data)
        feature_vector = np.array(list(features.values())).reshape(1, -1)

        # Isolation Forest anomaly score: -1 = anomaly, +1 = normal
        raw_score = self._model.decision_function(feature_vector)[0]
        # Convert to 0–1 probability (lower decision = more anomalous)
        normalised_score = max(0.0, min(1.0, (0.5 - raw_score)))

        return {
            "score": round(normalised_score, 3),
            "confidence": 0.80,
            "features": features,
            "deviation_summary": self._build_summary(features),
            "detector": "anomaly_iforest",
        }

    def _extract_features(self, log_data: list) -> dict:
        """Compute session-level features from raw event log."""
        timestamps = [self._parse_ts(e.get("timestamp", "")) for e in log_data if e.get("timestamp")]
        actions = [e.get("action", "") for e in log_data]
        ips = list({e.get("ip_address", "") for e in log_data})
        devices = list({e.get("device_id", "") for e in log_data})

        hour = datetime.utcnow().hour
        is_off_hours = int(hour < 7 or hour > 22)

        return {
            "event_count":        len(log_data),
            "unique_ips":         len(ips),
            "unique_devices":     len(devices),
            "unique_actions":     len(set(actions)),
            "hour_of_day":        hour,
            "is_off_hours":       is_off_hours,
            "session_duration_s": max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0,
            "events_per_minute":  len(log_data) / max((max(timestamps) - min(timestamps)) / 60, 1) if len(timestamps) > 1 else 0,
        }

    def _parse_ts(self, ts_str: str) -> float:
        try:
            return datetime.fromisoformat(ts_str).timestamp()
        except Exception:
            return datetime.utcnow().timestamp()

    def _build_summary(self, features: dict) -> list:
        summary = []
        if features["unique_ips"] > 1:
            summary.append(f"Login from {features['unique_ips']} different IP addresses in same session")
        if features["is_off_hours"]:
            summary.append(f"Activity at unusual hour ({features['hour_of_day']}:00 UTC)")
        if features["events_per_minute"] > 10:
            summary.append(f"High activity rate: {features['events_per_minute']:.1f} events/min")
        if features["unique_devices"] > 1:
            summary.append(f"Multiple devices used: {features['unique_devices']}")
        return summary

    def _train_demo_model(self) -> IsolationForest:
        """Quick-train on synthetic normal behaviour for demo purposes."""
        np.random.seed(42)
        normal_data = np.column_stack([
            np.random.randint(5, 30, 500),      # event_count
            np.ones(500),                        # unique_ips
            np.ones(500),                        # unique_devices
            np.random.randint(2, 8, 500),        # unique_actions
            np.random.randint(8, 18, 500),       # hour_of_day (business hours)
            np.zeros(500),                       # is_off_hours
            np.random.randint(60, 3600, 500),    # session_duration_s
            np.random.uniform(0.1, 2.0, 500),   # events_per_minute
        ])
        model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        model.fit(normal_data)
        return model
