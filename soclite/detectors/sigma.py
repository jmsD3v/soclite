"""
Sigma Rule Engine — Phase 1

Parses Sigma YAML rules and matches them against LogEvent streams.

Supported Sigma grammar subset:
  Field equality:    EventID: 4625
  Field list (OR):   EventID: [4625, 4624]
  Field contains:    Message|contains: 'password'
  Field startswith:  CommandLine|startswith: 'powershell'
  Field endswith:    Image|endswith: 'cmd.exe'
  Field contains|all: [must, have, all]
  NOT modifier:      NOT selection
  AND/OR conditions: selection1 and selection2
  Count threshold:   selection | count() > 5  (time-windowed)

Field mapping (Sigma field name → LogEvent attribute):
  EventID → event_id
  Channel → channel
  Computer/Hostname → hostname
  User/SubjectUserName/TargetUserName → username
  IpAddress/SourceIp → source_ip
  CommandLine → command_line
  Image/NewProcessName/ProcessName → process_name
  ParentImage/ParentProcessName → parent_process
  Message → message
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from soclite.types.events import Alert, AlertStatus, LogEvent, Severity


# Maps Sigma field names to LogEvent attributes
FIELD_MAP: dict[str, list[str]] = {
    "eventid": ["event_id"],
    "channel": ["channel"],
    "computer": ["hostname"],
    "hostname": ["hostname"],
    "user": ["username"],
    "subjectusername": ["username"],
    "targetusername": ["username"],
    "ipaddress": ["source_ip"],
    "sourceip": ["source_ip"],
    "workstationname": ["source_ip"],
    "commandline": ["command_line"],
    "image": ["process_name"],
    "newprocessname": ["process_name"],
    "processname": ["process_name"],
    "parentimage": ["parent_process"],
    "parentprocessname": ["parent_process"],
    "message": ["message"],
    "servicename": ["raw"],
    "taskname": ["raw"],
}

SIGMA_TO_SEVERITY: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
}


@dataclass
class SigmaRule:
    id: str
    title: str
    description: str
    severity: Severity
    tags: list[str]
    mitre_techniques: list[str]
    mitre_tactics: list[str]
    logsource: dict[str, str]
    detection: dict[str, Any]
    raw: dict[str, Any]

    def __str__(self) -> str:
        return f"[{self.severity.value.upper()}] {self.title}"


def _extract_mitre(tags: list[str]) -> tuple[list[str], list[str]]:
    techniques, tactics = [], []
    for tag in tags:
        if tag.startswith("attack.t") and "." in tag[7:]:
            techniques.append(tag[7:].upper())
        elif tag.startswith("attack.t"):
            techniques.append(tag[7:].upper())
        elif tag.startswith("attack."):
            tactics.append(tag[7:].replace("_", " ").title())
    return techniques, tactics


def load_rules(rules_dir: str | Path) -> list[SigmaRule]:
    """Load all .yml files from a directory as Sigma rules."""
    path = Path(rules_dir)
    rules = []
    for yml_file in sorted(path.glob("**/*.yml")):
        try:
            with open(yml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not data or "detection" not in data:
                continue
            tags = data.get("tags", [])
            techniques, tactics = _extract_mitre(tags)
            rule = SigmaRule(
                id=data.get("id", yml_file.stem),
                title=data.get("title", yml_file.stem),
                description=data.get("description", ""),
                severity=SIGMA_TO_SEVERITY.get(
                    data.get("level", "medium").lower(), Severity.MEDIUM
                ),
                tags=tags,
                mitre_techniques=techniques,
                mitre_tactics=tactics,
                logsource=data.get("logsource", {}),
                detection=data.get("detection", {}),
                raw=data,
            )
            rules.append(rule)
        except Exception:
            continue
    return rules


def _get_event_value(event: LogEvent, field_name: str) -> str | int | None:
    """Get a value from LogEvent for a given Sigma field name."""
    attrs = FIELD_MAP.get(field_name.lower(), [])
    for attr in attrs:
        if attr == "raw":
            return str(event.raw)
        val = getattr(event, attr, None)
        if val is not None:
            return val
    return getattr(event, field_name.lower(), None)


def _match_field(event: LogEvent, field_raw: str, expected: Any) -> bool:
    """
    Match a single Sigma field condition against an event.
    Handles: equality, list (OR), contains, startswith, endswith, contains|all.
    """
    parts = field_raw.split("|")
    field_name = parts[0]
    modifiers = [p.lower() for p in parts[1:]]

    actual = _get_event_value(event, field_name)
    if actual is None:
        return False

    actual_str = str(actual).lower()

    if not modifiers:
        # Simple equality
        if isinstance(expected, list):
            return any(str(e).lower() == actual_str for e in expected)
        return str(expected).lower() == actual_str

    if "contains" in modifiers and "all" in modifiers:
        values = expected if isinstance(expected, list) else [expected]
        return all(str(v).lower() in actual_str for v in values)

    if "contains" in modifiers:
        values = expected if isinstance(expected, list) else [expected]
        return any(str(v).lower() in actual_str for v in values)

    if "startswith" in modifiers:
        values = expected if isinstance(expected, list) else [expected]
        return any(actual_str.startswith(str(v).lower()) for v in values)

    if "endswith" in modifiers:
        values = expected if isinstance(expected, list) else [expected]
        return any(actual_str.endswith(str(v).lower()) for v in values)

    if "re" in modifiers:
        pattern = expected if isinstance(expected, str) else str(expected)
        try:
            return bool(re.search(pattern, actual_str, re.IGNORECASE))
        except re.error:
            return False

    return False


def _match_selection(event: LogEvent, selection: dict[str, Any]) -> bool:
    """All fields in a selection must match (AND logic within a selection)."""
    for field_expr, value in selection.items():
        if not _match_field(event, field_expr, value):
            return False
    return True


def _evaluate_condition(
    condition: str,
    selections: dict[str, dict],
    event: LogEvent,
) -> bool:
    """
    Evaluate a Sigma condition expression.
    Supports: and, or, not, selection names, count (simplified).
    Count conditions always return True here — they're handled separately.
    """
    cond = condition.strip().lower()

    # Handle count aggregation — always pass here, evaluated in window
    if "|" in cond and "count" in cond:
        sel_name = cond.split("|")[0].strip()
        sel = selections.get(sel_name, selections.get("selection", {}))
        return _match_selection(event, sel)

    # NOT
    if cond.startswith("not "):
        inner = cond[4:].strip()
        sel = selections.get(inner, {})
        return not _match_selection(event, sel)

    # AND
    if " and " in cond:
        parts = [p.strip() for p in cond.split(" and ")]
        return all(
            _match_selection(event, selections.get(p, {})) if p in selections
            else _evaluate_condition(p, selections, event)
            for p in parts
        )

    # OR
    if " or " in cond:
        parts = [p.strip() for p in cond.split(" or ")]
        return any(
            _match_selection(event, selections.get(p, {})) if p in selections
            else _evaluate_condition(p, selections, event)
            for p in parts
        )

    # Simple selection name
    sel = selections.get(cond)
    if sel:
        return _match_selection(event, sel)

    return False


def _parse_count_condition(condition: str) -> tuple[str, int] | None:
    """Extract selection name and count threshold from count conditions."""
    m = re.match(r"(\w+)\s*\|\s*count\(\)\s*([><=!]+)\s*(\d+)", condition, re.IGNORECASE)
    if m:
        return m.group(1), int(m.group(3))
    return None


class SigmaEngine:
    """
    Runs a stream of LogEvents through all loaded Sigma rules.
    Returns Alert objects for every match.
    """

    def __init__(self, rules: list[SigmaRule], window_minutes: int = 5) -> None:
        self.rules = rules
        self.window = timedelta(minutes=window_minutes)
        # Ring buffer for count-based detection: rule_id → list of matching events
        self._count_buffer: dict[str, list[LogEvent]] = {}

    def process(self, events: list[LogEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        for event in events:
            for rule in self.rules:
                alert = self._check_rule(rule, event, events)
                if alert:
                    alerts.append(alert)
        return alerts

    def _check_rule(
        self,
        rule: SigmaRule,
        event: LogEvent,
        all_events: list[LogEvent],
    ) -> Alert | None:
        detection = rule.detection
        condition = detection.get("condition", "selection")

        # Extract selections (everything except "condition" key)
        selections = {k: v for k, v in detection.items() if k != "condition"}

        # Count-based condition
        count_info = _parse_count_condition(condition)
        if count_info:
            sel_name, threshold = count_info
            sel = selections.get(sel_name, selections.get("selection", {}))
            if _match_selection(event, sel):
                buf_key = f"{rule.id}:{event.hostname}:{event.source_ip}"
                buf = self._count_buffer.setdefault(buf_key, [])
                # Purge events outside the time window
                cutoff = event.timestamp - self.window
                buf = [e for e in buf if e.timestamp >= cutoff]
                buf.append(event)
                self._count_buffer[buf_key] = buf
                if len(buf) >= threshold:
                    alert = self._make_alert(rule, buf)
                    self._count_buffer[buf_key] = []  # reset after alert
                    return alert
            return None

        # Standard condition
        if _evaluate_condition(condition, selections, event):
            return self._make_alert(rule, [event])

        return None

    def _make_alert(self, rule: SigmaRule, events: list[LogEvent]) -> Alert:
        return Alert(
            rule_name=rule.title,
            rule_id=rule.id,
            rule_source="sigma",
            description=rule.description,
            severity=rule.severity,
            timestamp=events[-1].timestamp,
            events=events,
            mitre_techniques=rule.mitre_techniques,
            mitre_tactics=rule.mitre_tactics,
            status=AlertStatus.NEW,
            score=1.0,
        )
