"""
JSON / JSONL Log Ingestor

Supports:
  - JSONL (one JSON object per line) — Docker, Kubernetes, Fluentd, Logstash
  - JSON array files — exported logs from SIEMs, cloud logging services
  - Elastic Common Schema (ECS) field mapping
  - AWS CloudTrail / Azure Activity Log schemas

Auto-detects timestamp fields: @timestamp, timestamp, time, eventTime, TimeCreated
Auto-detects user fields: user.name, username, user, principalId
Auto-detects IP fields: source.ip, sourceIPAddress, client_ip, ip
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from soclite.types.events import EventCategory, LogEvent


_TIMESTAMP_FIELDS = ["@timestamp", "timestamp", "time", "eventTime", "TimeCreated",
                     "created_at", "datetime", "date"]
_USER_FIELDS = ["user.name", "username", "user", "principalId", "actor.login",
                "initiatedBy.user.userPrincipalName"]
_IP_FIELDS = ["source.ip", "sourceIPAddress", "client_ip", "ip", "remote_addr",
              "client.ip", "src_ip"]
_HOST_FIELDS = ["host.name", "hostname", "host", "computer", "device"]
_MSG_FIELDS = ["message", "msg", "log", "description", "eventName", "operationName"]
_CATEGORY_MAP = {
    "authentication": EventCategory.AUTHENTICATION,
    "login": EventCategory.AUTHENTICATION,
    "logon": EventCategory.AUTHENTICATION,
    "auth": EventCategory.AUTHENTICATION,
    "process": EventCategory.PROCESS,
    "network": EventCategory.NETWORK,
    "connection": EventCategory.NETWORK,
    "file": EventCategory.FILE,
    "registry": EventCategory.REGISTRY,
    "system": EventCategory.SYSTEM,
    "audit": EventCategory.AUDIT,
}


def _deep_get(obj: dict, dotted_key: str) -> Any:
    """Support dot-notation keys like 'user.name'."""
    parts = dotted_key.split(".", 1)
    val = obj.get(parts[0])
    if len(parts) == 1 or not isinstance(val, dict):
        return val
    return _deep_get(val, parts[1])


def _first_of(obj: dict, keys: list[str]) -> Any:
    for k in keys:
        v = _deep_get(obj, k)
        if v is not None:
            return v
    return None


def _parse_timestamp(raw: Any) -> datetime:
    if isinstance(raw, (int, float)):
        # epoch seconds or milliseconds
        ts = raw / 1000 if raw > 1e10 else raw
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    if isinstance(raw, str):
        for fmt in [None]:  # try fromisoformat first
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                pass
    return datetime.now(timezone.utc)


def _detect_category(obj: dict) -> EventCategory:
    for key in ["category", "event.category", "event_type", "type", "action"]:
        val = _deep_get(obj, key)
        if isinstance(val, str):
            val_lower = val.lower()
            for keyword, cat in _CATEGORY_MAP.items():
                if keyword in val_lower:
                    return cat
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    val_lower = item.lower()
                    for keyword, cat in _CATEGORY_MAP.items():
                        if keyword in val_lower:
                            return cat
    return EventCategory.UNKNOWN


def _detect_status(obj: dict) -> str | None:
    for key in ["event.outcome", "outcome", "status", "result", "success"]:
        val = _deep_get(obj, key)
        if isinstance(val, str):
            if val.lower() in ("success", "succeeded", "ok", "200"):
                return "success"
            if val.lower() in ("failure", "failed", "error", "denied", "unauthorized"):
                return "failure"
        if isinstance(val, bool):
            return "success" if val else "failure"
    return None


def _json_to_event(obj: dict[str, Any], source_file: str) -> LogEvent:
    ts_raw = _first_of(obj, _TIMESTAMP_FIELDS)
    timestamp = _parse_timestamp(ts_raw) if ts_raw is not None else datetime.now(timezone.utc)

    message_val = _first_of(obj, _MSG_FIELDS)
    message = str(message_val) if message_val is not None else json.dumps(obj)[:300]

    ev = LogEvent(
        source_type="json",
        source_file=source_file,
        hostname=str(_first_of(obj, _HOST_FIELDS) or "unknown"),
        timestamp=timestamp,
        username=_first_of(obj, _USER_FIELDS),
        source_ip=_first_of(obj, _IP_FIELDS),
        category=_detect_category(obj),
        status=_detect_status(obj),
        message=message[:500],
        raw=obj,
    )

    # ECS event.id
    ev_id = _deep_get(obj, "event.id") or obj.get("event_id") or obj.get("id")
    if isinstance(ev_id, int):
        ev.event_id = ev_id

    # process fields
    proc = _deep_get(obj, "process.name") or obj.get("process")
    if isinstance(proc, str):
        ev.process_name = proc

    cmd = _deep_get(obj, "process.command_line") or obj.get("command_line")
    if isinstance(cmd, str):
        ev.command_line = cmd

    # dest ip
    dest = _deep_get(obj, "destination.ip") or obj.get("dest_ip")
    if isinstance(dest, str):
        ev.dest_ip = dest

    # tags
    tags = obj.get("tags") or obj.get("labels")
    if isinstance(tags, list):
        ev.tags.extend(str(t) for t in tags)
    elif isinstance(tags, dict):
        ev.tags.extend(f"{k}:{v}" for k, v in tags.items())

    return ev


def _is_security_relevant(obj: dict) -> bool:
    text = json.dumps(obj).lower()
    keywords = ["auth", "login", "logon", "fail", "error", "deny", "block",
                "attack", "malware", "suspicious", "anomal", "threat", "exploit",
                "privilege", "escalat", "lateral", "exfil", "command", "execution"]
    return any(kw in text for kw in keywords)


class JsonLogIngestor:
    """Ingest JSON and JSONL log files from Docker, Kubernetes, ECS, CloudTrail, etc."""

    name = "jsonlog"

    def parse(self, file_path: str | Path, security_only: bool = False) -> Iterator[LogEvent]:
        """Parse JSON or JSONL log file and yield LogEvent objects.

        Args:
            file_path: Path to .json or .jsonl file
            security_only: If True, skip events with no security relevance
        """
        path = Path(file_path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
        except FileNotFoundError:
            raise FileNotFoundError(f"Log file not found: {path}")
        except Exception as exc:
            raise RuntimeError(f"Failed to read '{path}': {exc}") from exc

        source = str(path)

        # Try JSONL first (newline-delimited)
        if "\n" in text and not text.startswith("["):
            for lineno, line in enumerate(text.splitlines(), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if not isinstance(obj, dict):
                        continue
                    if security_only and not _is_security_relevant(obj):
                        continue
                    yield _json_to_event(obj, source)
                except json.JSONDecodeError:
                    continue
            return

        # Try JSON array
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Invalid JSON in '{path}': {exc}") from exc

        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                if security_only and not _is_security_relevant(item):
                    continue
                yield _json_to_event(item, source)
        elif isinstance(data, dict):
            # Single event or wrapped array
            records = data.get("Records") or data.get("events") or data.get("logs")
            if isinstance(records, list):
                for item in records:
                    if not isinstance(item, dict):
                        continue
                    if security_only and not _is_security_relevant(item):
                        continue
                    yield _json_to_event(item, source)
            else:
                yield _json_to_event(data, source)
