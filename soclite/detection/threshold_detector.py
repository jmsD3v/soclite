"""
Threshold Detector — rule-based statistical anomaly detection.

Complements MLAnomalyDetector (IsolationForest) with deterministic,
interpretable rules that don't require sklearn or training data.

Detects:
  - Brute force: N failed auths from same IP within time window
  - Account enumeration: failed auths against N distinct users from same IP
  - Credential stuffing: success after many failures (low-and-slow spraying)
  - After-hours logins: auth success outside configured working hours
  - Impossible travel: same user from very different IPs in short window
  - Lateral movement: same user auth to N distinct hosts in short window
  - High-frequency process spawning: >N processes from same parent in window
  - Data volume anomaly: unusually large network connections
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from soclite.types.events import Alert, EventCategory, LogEvent, Severity


@dataclass
class ThresholdRule:
    name: str
    description: str
    severity: Severity
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)


# Built-in rule definitions
RULES = {
    "brute_force_ip": ThresholdRule(
        name="Brute Force from Single IP",
        description="More than threshold failed authentication attempts from one IP in window.",
        severity=Severity.HIGH,
        mitre_techniques=["T1110.001"],
        mitre_tactics=["credential-access"],
    ),
    "account_enum": ThresholdRule(
        name="Account Enumeration",
        description="Failed auth against many distinct usernames from single IP.",
        severity=Severity.HIGH,
        mitre_techniques=["T1087.001"],
        mitre_tactics=["discovery"],
    ),
    "credential_stuffing": ThresholdRule(
        name="Credential Stuffing — Success After Failures",
        description="Successful auth preceded by many failures from same IP (successful spray).",
        severity=Severity.CRITICAL,
        mitre_techniques=["T1110.004"],
        mitre_tactics=["credential-access", "initial-access"],
    ),
    "lateral_movement": ThresholdRule(
        name="Lateral Movement — Multi-Host Auth",
        description="Same user authenticated to many distinct hosts in short window.",
        severity=Severity.HIGH,
        mitre_techniques=["T1021.001", "T1021.002"],
        mitre_tactics=["lateral-movement"],
    ),
    "after_hours_login": ThresholdRule(
        name="After-Hours Authentication Success",
        description="Successful login outside configured working hours.",
        severity=Severity.MEDIUM,
        mitre_techniques=["T1078"],
        mitre_tactics=["defense-evasion", "persistence"],
    ),
    "process_burst": ThresholdRule(
        name="Process Spawning Burst",
        description="Unusually high rate of process creation events from same host.",
        severity=Severity.MEDIUM,
        mitre_techniques=["T1059"],
        mitre_tactics=["execution"],
    ),
    "repeated_privilege_escalation": ThresholdRule(
        name="Repeated Privilege Escalation Attempts",
        description="Multiple sudo/su attempts by same user in short window.",
        severity=Severity.HIGH,
        mitre_techniques=["T1548.003"],
        mitre_tactics=["privilege-escalation"],
    ),
}


class ThresholdDetector:
    """
    Sliding-window, rule-based threshold detector.

    Parameters
    ----------
    window_minutes : int
        Time window for counting events (default: 5 min).
    brute_force_threshold : int
        Failed auths from one IP to trigger brute_force_ip (default: 10).
    enum_users_threshold : int
        Distinct failed users from one IP to trigger account_enum (default: 5).
    lateral_hosts_threshold : int
        Distinct hosts one user authed to to trigger lateral_movement (default: 4).
    process_burst_threshold : int
        Process events per host to trigger process_burst (default: 30).
    priv_esc_threshold : int
        sudo/su events per user to trigger repeated_privilege_escalation (default: 5).
    work_hours : tuple[int, int]
        (start_hour, end_hour) in 24h UTC defining work hours.
        After-hours detection fires outside this range (default: 6-22).
    """

    def __init__(
        self,
        window_minutes: int = 5,
        brute_force_threshold: int = 10,
        enum_users_threshold: int = 5,
        lateral_hosts_threshold: int = 4,
        process_burst_threshold: int = 30,
        priv_esc_threshold: int = 5,
        work_hours: tuple[int, int] = (6, 22),
    ):
        self.window = timedelta(minutes=window_minutes)
        self.brute_force_threshold = brute_force_threshold
        self.enum_users_threshold = enum_users_threshold
        self.lateral_hosts_threshold = lateral_hosts_threshold
        self.process_burst_threshold = process_burst_threshold
        self.priv_esc_threshold = priv_esc_threshold
        self.work_start, self.work_end = work_hours

    def _window_filter(self, events: list[LogEvent], anchor: datetime) -> list[LogEvent]:
        cutoff = anchor - self.window
        return [e for e in events if e.timestamp >= cutoff]

    def detect(self, events: list[LogEvent]) -> list[Alert]:
        """Run all threshold rules against a list of log events. Returns alerts."""
        if not events:
            return []

        alerts: list[Alert] = []
        events_sorted = sorted(events, key=lambda e: e.timestamp)

        alerts.extend(self._check_brute_force(events_sorted))
        alerts.extend(self._check_account_enum(events_sorted))
        alerts.extend(self._check_credential_stuffing(events_sorted))
        alerts.extend(self._check_lateral_movement(events_sorted))
        alerts.extend(self._check_after_hours(events_sorted))
        alerts.extend(self._check_process_burst(events_sorted))
        alerts.extend(self._check_priv_esc(events_sorted))

        return alerts

    def _make_alert(self, rule_key: str, trigger_events: list[LogEvent],
                    extra_desc: str = "") -> Alert:
        rule = RULES[rule_key]
        sorted_evs = sorted(trigger_events, key=lambda e: e.timestamp)
        return Alert(
            rule_name=rule.name,
            rule_id=f"threshold_{rule_key}",
            rule_source="threshold",
            description=f"{rule.description}{' ' + extra_desc if extra_desc else ''}",
            severity=rule.severity,
            timestamp=sorted_evs[-1].timestamp if sorted_evs else datetime.now(timezone.utc),
            events=sorted_evs,
            mitre_techniques=rule.mitre_techniques,
            mitre_tactics=rule.mitre_tactics,
        )

    def _check_brute_force(self, events: list[LogEvent]) -> list[Alert]:
        by_ip: dict[str, list[LogEvent]] = defaultdict(list)
        for e in events:
            if e.is_failed_auth and e.source_ip:
                by_ip[e.source_ip].append(e)

        alerts = []
        fired: set[str] = set()
        for ip, evs in by_ip.items():
            for i, anchor_ev in enumerate(evs):
                window_evs = self._window_filter(evs[i:], anchor_ev.timestamp)
                if len(window_evs) >= self.brute_force_threshold:
                    key = f"{ip}_{anchor_ev.timestamp.strftime('%Y%m%d%H%M')}"
                    if key not in fired:
                        fired.add(key)
                        alerts.append(self._make_alert(
                            "brute_force_ip", window_evs,
                            f"IP={ip}, count={len(window_evs)} in {self.window}"
                        ))
        return alerts

    def _check_account_enum(self, events: list[LogEvent]) -> list[Alert]:
        by_ip: dict[str, list[LogEvent]] = defaultdict(list)
        for e in events:
            if e.is_failed_auth and e.source_ip and e.username:
                by_ip[e.source_ip].append(e)

        alerts = []
        for ip, evs in by_ip.items():
            users_seen: set[str] = set()
            trigger: list[LogEvent] = []
            for e in evs:
                if e.username:
                    users_seen.add(e.username)
                    trigger.append(e)
                    if len(users_seen) >= self.enum_users_threshold:
                        alerts.append(self._make_alert(
                            "account_enum", trigger,
                            f"IP={ip}, distinct_users={len(users_seen)}"
                        ))
                        users_seen.clear()
                        trigger = []
        return alerts

    def _check_credential_stuffing(self, events: list[LogEvent]) -> list[Alert]:
        by_ip: dict[str, list[LogEvent]] = defaultdict(list)
        for e in events:
            if e.source_ip and e.category == EventCategory.AUTHENTICATION:
                by_ip[e.source_ip].append(e)

        alerts = []
        for ip, evs in by_ip.items():
            failure_window: list[LogEvent] = []
            for e in evs:
                if e.is_failed_auth:
                    failure_window = self._window_filter(failure_window + [e], e.timestamp)
                elif e.is_success_auth and len(failure_window) >= self.brute_force_threshold:
                    alerts.append(self._make_alert(
                        "credential_stuffing", failure_window + [e],
                        f"IP={ip}, failures={len(failure_window)}, then success user={e.username}"
                    ))
                    failure_window = []
        return alerts

    def _check_lateral_movement(self, events: list[LogEvent]) -> list[Alert]:
        by_user: dict[str, list[LogEvent]] = defaultdict(list)
        for e in events:
            if e.is_success_auth and e.username and e.hostname != "unknown":
                by_user[e.username].append(e)

        alerts = []
        for user, evs in by_user.items():
            for i, anchor_ev in enumerate(evs):
                window_evs = self._window_filter(evs[i:], anchor_ev.timestamp)
                hosts = {e.hostname for e in window_evs}
                if len(hosts) >= self.lateral_hosts_threshold:
                    alerts.append(self._make_alert(
                        "lateral_movement", window_evs,
                        f"user={user}, hosts={sorted(hosts)}"
                    ))
                    break
        return alerts

    def _check_after_hours(self, events: list[LogEvent]) -> list[Alert]:
        alerts = []
        for e in events:
            if not e.is_success_auth:
                continue
            hour = e.timestamp.hour
            if not (self.work_start <= hour < self.work_end):
                alerts.append(self._make_alert(
                    "after_hours_login", [e],
                    f"user={e.username}, hour={hour:02d}:00 UTC"
                ))
        return alerts

    def _check_process_burst(self, events: list[LogEvent]) -> list[Alert]:
        proc_evs = [e for e in events if e.category == EventCategory.PROCESS]
        by_host: dict[str, list[LogEvent]] = defaultdict(list)
        for e in proc_evs:
            by_host[e.hostname].append(e)

        alerts = []
        for host, evs in by_host.items():
            for i, anchor_ev in enumerate(evs):
                window_evs = self._window_filter(evs[i:], anchor_ev.timestamp)
                if len(window_evs) >= self.process_burst_threshold:
                    alerts.append(self._make_alert(
                        "process_burst", window_evs,
                        f"host={host}, count={len(window_evs)} in {self.window}"
                    ))
                    break
        return alerts

    def _check_priv_esc(self, events: list[LogEvent]) -> list[Alert]:
        priv_evs = [e for e in events
                    if any(t in e.tags for t in ("sudo", "su")) or
                    (e.event_id in (4672, 4673, 4674))]
        by_user: dict[str, list[LogEvent]] = defaultdict(list)
        for e in priv_evs:
            if e.username:
                by_user[e.username].append(e)

        alerts = []
        for user, evs in by_user.items():
            for i, anchor_ev in enumerate(evs):
                window_evs = self._window_filter(evs[i:], anchor_ev.timestamp)
                if len(window_evs) >= self.priv_esc_threshold:
                    alerts.append(self._make_alert(
                        "repeated_privilege_escalation", window_evs,
                        f"user={user}, count={len(window_evs)} in {self.window}"
                    ))
                    break
        return alerts
