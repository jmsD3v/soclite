from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]

    @property
    def color(self) -> str:
        return {"critical": "red", "high": "dark_orange",
                "medium": "yellow", "low": "cyan", "info": "bright_black"}[self.value]


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    REGISTRY = "registry"
    SYSTEM = "system"
    AUDIT = "audit"
    UNKNOWN = "unknown"


class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class IncidentStatus(str, Enum):
    OPEN = "open"
    CONTAINED = "contained"
    RESOLVED = "resolved"


@dataclass
class LogEvent:
    """Normalized log event — common schema for all log sources."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    source_type: str = ""           # evtx | authlog | syslog | json
    source_file: str = ""
    hostname: str = "unknown"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_id: int | None = None     # Windows Event ID
    channel: str | None = None      # Security, System, Application
    category: EventCategory = EventCategory.UNKNOWN
    username: str | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    process_name: str | None = None
    process_id: int | None = None
    parent_process: str | None = None
    command_line: str | None = None
    logon_type: int | None = None
    status: str | None = None       # success | failure
    message: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    @property
    def is_failed_auth(self) -> bool:
        return (
            self.category == EventCategory.AUTHENTICATION and self.status == "failure"
        ) or self.event_id == 4625

    @property
    def is_success_auth(self) -> bool:
        return (
            self.category == EventCategory.AUTHENTICATION and self.status == "success"
        ) or self.event_id == 4624

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "source_type": self.source_type,
            "hostname": self.hostname, "timestamp": self.timestamp.isoformat(),
            "event_id": self.event_id, "category": self.category.value,
            "username": self.username, "source_ip": self.source_ip,
            "process_name": self.process_name, "command_line": self.command_line,
            "status": self.status, "message": self.message[:300],
        }


@dataclass
class Alert:
    """A detection hit — either from Sigma or ML."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    rule_name: str = ""
    rule_id: str = ""
    rule_source: str = "sigma"      # sigma | ml_anomaly
    description: str = ""
    severity: Severity = Severity.MEDIUM
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    events: list[LogEvent] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    ai_narrative: str | None = None
    status: AlertStatus = AlertStatus.NEW
    score: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "rule_name": self.rule_name, "rule_source": self.rule_source,
            "description": self.description, "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(), "event_count": len(self.events),
            "mitre_techniques": self.mitre_techniques, "mitre_tactics": self.mitre_tactics,
            "ai_narrative": self.ai_narrative, "status": self.status.value,
        }


@dataclass
class Incident:
    """Correlated group of alerts representing an attack chain."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    name: str = ""
    alerts: list[Alert] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    status: IncidentStatus = IncidentStatus.OPEN
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    affected_hosts: list[str] = field(default_factory=list)
    affected_users: list[str] = field(default_factory=list)
    source_ips: list[str] = field(default_factory=list)
    ai_analysis: str = ""
    recommendations: list[str] = field(default_factory=list)

    @property
    def timeline(self) -> list[LogEvent]:
        events = []
        for alert in self.alerts:
            events.extend(alert.events)
        return sorted(events, key=lambda e: e.timestamp)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "severity": self.severity.value,
            "status": self.status.value, "alert_count": len(self.alerts),
            "first_seen": self.first_seen.isoformat(), "last_seen": self.last_seen.isoformat(),
            "affected_hosts": self.affected_hosts, "affected_users": self.affected_users,
            "source_ips": self.source_ips, "ai_analysis": self.ai_analysis,
            "recommendations": self.recommendations,
        }


@dataclass
class ScanResult:
    source_files: list[str] = field(default_factory=list)
    events_processed: int = 0
    alerts: list[Alert] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
    duration_seconds: float = 0.0

    def sorted_alerts(self) -> list[Alert]:
        return sorted(self.alerts, key=lambda a: a.severity.weight, reverse=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_files": self.source_files,
            "events_processed": self.events_processed,
            "alerts": [a.to_dict() for a in self.sorted_alerts()],
            "incidents": [i.to_dict() for i in self.incidents],
            "summary": {
                "total_alerts": len(self.alerts),
                "critical": len([a for a in self.alerts if a.severity == Severity.CRITICAL]),
                "high": len([a for a in self.alerts if a.severity == Severity.HIGH]),
                "medium": len([a for a in self.alerts if a.severity == Severity.MEDIUM]),
                "incidents": len(self.incidents),
            },
        }
