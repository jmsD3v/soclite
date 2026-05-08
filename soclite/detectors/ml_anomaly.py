"""
ML Anomaly Detector — Isolation Forest

Convierte LogEvents en feature vectors numéricos y entrena
un Isolation Forest para detectar comportamiento anómalo.

Features extraídas por evento:
  - hour_of_day         (0-23)
  - is_weekend          (0/1)
  - is_failed_auth      (0/1)
  - is_success_auth     (0/1)
  - logon_type          (0-10)
  - has_source_ip       (0/1)
  - is_private_ip       (0/1)
  - process_suspicious  (0/1) — powershell, cmd, wscript, etc.
  - event_id_bucket     (agrupado por categoría)
  - has_command_line    (0/1)

Flujo:
  1. Ingestar todos los eventos → feature matrix
  2. Fit IsolationForest (unsupervised — no labels needed)
  3. Score cada evento → anomaly_score (negativo = más anómalo)
  4. Threshold: score < -0.1 → generar Alert con severity proporcional

Ventaja: funciona con logs reales sin etiquetas.
Desventaja: tasa de falsos positivos alta — necesita calibración por entorno.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from soclite.types.events import Alert, AlertStatus, LogEvent, Severity

SUSPICIOUS_PROCESSES = {
    "powershell.exe", "powershell", "cmd.exe", "cmd",
    "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "certutil.exe", "bitsadmin.exe", "psexec.exe",
    "mimikatz.exe", "nc.exe", "ncat.exe", "netcat",
}

EVENT_ID_BUCKETS = {
    range(4624, 4630): 1,   # auth success
    range(4625, 4626): 2,   # auth failure
    range(4688, 4689): 3,   # process creation
    range(4698, 4703): 4,   # scheduled tasks
    range(4720, 4730): 5,   # account management
    range(7040, 7050): 6,   # service changes
    range(1100, 1103): 7,   # audit
}


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # assume private if can't parse


def _event_id_bucket(eid: int | None) -> int:
    if eid is None:
        return 0
    for r, bucket in EVENT_ID_BUCKETS.items():
        if eid in r:
            return bucket
    return 8  # other


def _extract_features(event: LogEvent) -> list[float]:
    ts = event.timestamp
    hour = ts.hour
    is_weekend = 1.0 if ts.weekday() >= 5 else 0.0
    is_failed = 1.0 if event.is_failed_auth else 0.0
    is_success = 1.0 if event.is_success_auth else 0.0
    logon_type = float(event.logon_type or 0)
    has_src_ip = 1.0 if event.source_ip else 0.0
    is_private = 1.0 if (event.source_ip and _is_private_ip(event.source_ip)) else 0.0
    proc_lower = (event.process_name or "").lower().split("\\")[-1]
    suspicious_proc = 1.0 if proc_lower in SUSPICIOUS_PROCESSES else 0.0
    eid_bucket = float(_event_id_bucket(event.event_id))
    has_cmdline = 1.0 if event.command_line else 0.0

    return [
        hour, is_weekend, is_failed, is_success,
        logon_type, has_src_ip, is_private,
        suspicious_proc, eid_bucket, has_cmdline,
    ]


class MLAnomalyDetector:
    """
    Trains on all ingested events, then scores each one.
    Higher contamination = more alerts (more FPs, fewer FNs).
    """

    def __init__(self, contamination: float = 0.05, random_state: int = 42) -> None:
        self.contamination = contamination
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self._fitted = False

    def fit(self, events: list[LogEvent]) -> None:
        if len(events) < 20:
            return  # not enough data to train
        X = np.array([_extract_features(e) for e in events], dtype=np.float32)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self._fitted = True

    def score_events(self, events: list[LogEvent]) -> list[tuple[LogEvent, float]]:
        """Return (event, anomaly_score) pairs. Score < 0 = anomalous."""
        if not self._fitted or not events:
            return []
        X = np.array([_extract_features(e) for e in events], dtype=np.float32)
        X_scaled = self.scaler.transform(X)
        scores = self.model.score_samples(X_scaled)
        return list(zip(events, scores.tolist()))

    def detect(self, events: list[LogEvent]) -> list[Alert]:
        """Fit on all events, then return alerts for anomalous ones."""
        self.fit(events)
        scored = self.score_events(events)
        alerts: list[Alert] = []

        for event, score in scored:
            if score >= -0.05:
                continue  # normal

            # Map score to severity
            if score < -0.20:
                severity = Severity.HIGH
            elif score < -0.12:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            desc = _describe_anomaly(event, score)
            alert = Alert(
                rule_name="ML Anomaly Detected",
                rule_id="ml_anomaly",
                rule_source="ml_anomaly",
                description=desc,
                severity=severity,
                timestamp=event.timestamp,
                events=[event],
                mitre_techniques=[],
                mitre_tactics=[],
                status=AlertStatus.NEW,
                score=round(score, 4),
            )
            alerts.append(alert)

        return alerts


def _describe_anomaly(event: LogEvent, score: float) -> str:
    parts = [
        f"Anomaly score {score:.3f} (lower = more unusual).",
        f"Host: {event.hostname}.",
    ]
    if event.username:
        parts.append(f"User: {event.username}.")
    if event.source_ip:
        parts.append(f"Source IP: {event.source_ip}.")
    if event.process_name:
        parts.append(f"Process: {event.process_name}.")
    if event.command_line:
        parts.append(f"Command: {event.command_line[:80]}.")

    hour = event.timestamp.hour
    if hour < 6 or hour > 22:
        parts.append(f"Activity at unusual hour ({hour:02d}:00).")
    if event.is_failed_auth:
        parts.append("Failed authentication.")
    if event.logon_type == 3:
        parts.append("Network logon type — possible lateral movement.")
    if event.logon_type == 10:
        parts.append("Remote interactive logon (RDP).")

    return " ".join(parts)
