"""
Linux Auth Log Ingestor

Parses /var/log/auth.log, /var/log/secure, and syslog files.

Detects:
  - SSH brute force (repeated "Failed password")
  - Successful SSH logins
  - sudo usage (privilege escalation)
  - New user creation
  - su attempts
  - PAM failures

Works with:
  - Ubuntu/Debian auth.log
  - CentOS/RHEL /var/log/secure
  - Historical log files from CTF challenges
  - CyberDefenders log datasets
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from soclite.types.events import EventCategory, LogEvent


# Compiled regex patterns for log line parsing
_SYSLOG_HEADER = re.compile(
    r"^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<proc>[^:]+):\s*(?P<msg>.+)$"
)
_ISO_HEADER = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+(?P<host>\S+)\s+(?P<proc>[^:]+):\s*(?P<msg>.+)$"
)

PATTERNS = [
    # SSH failures
    (re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"),
     EventCategory.AUTHENTICATION, "failure", "ssh_failed"),
    # SSH success
    (re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)"),
     EventCategory.AUTHENTICATION, "success", "ssh_success"),
    # SSH invalid user
    (re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"),
     EventCategory.AUTHENTICATION, "failure", "ssh_invalid_user"),
    # sudo
    (re.compile(r"sudo:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<cmd>.+)$"),
     EventCategory.PROCESS, "success", "sudo"),
    # su
    (re.compile(r"su\[.*\]: (?:Successful|Failed) su for (?P<user>\S+)"),
     EventCategory.AUTHENTICATION, None, "su"),
    # PAM failure
    (re.compile(r"pam_unix.*: authentication failure.*user=(?P<user>\S+)"),
     EventCategory.AUTHENTICATION, "failure", "pam_failure"),
    # New user
    (re.compile(r"useradd.*: new user: name=(?P<user>\S+)"),
     EventCategory.SYSTEM, "success", "user_created"),
    # CRON
    (re.compile(r"CRON.*CMD\s+\((?P<user>[^)]+)\)\s+(?P<cmd>.+)"),
     EventCategory.PROCESS, "success", "cron"),
]

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_timestamp(match: re.Match, year: int = 2024) -> datetime:
    try:
        month = MONTH_MAP.get(match.group("month"), 1)
        day = int(match.group("day"))
        h, m, s = match.group("time").split(":")
        return datetime(year, month, day, int(h), int(m), int(s), tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def _parse_line(line: str, source_file: str, year: int = 2024) -> LogEvent | None:
    line = line.strip()
    if not line:
        return None

    host = "unknown"
    message = line
    timestamp = datetime.now(timezone.utc)

    # Try syslog format first
    m = _SYSLOG_HEADER.match(line)
    if m:
        host = m.group("host")
        message = m.group("msg")
        timestamp = _parse_timestamp(m, year)
    else:
        # Try ISO timestamp
        m = _ISO_HEADER.match(line)
        if m:
            host = m.group("host")
            message = m.group("msg")
            try:
                timestamp = datetime.fromisoformat(m.group("ts").replace("Z", "+00:00"))
            except Exception:
                pass

    ev = LogEvent(
        source_type="authlog",
        source_file=source_file,
        hostname=host,
        timestamp=timestamp,
        message=message,
        raw={"line": line},
    )

    # Match against known patterns
    for pattern, category, status, tag in PATTERNS:
        pm = pattern.search(message)
        if pm:
            ev.category = category
            if status:
                ev.status = status
            ev.tags.append(tag)

            groups = pm.groupdict()
            if "user" in groups:
                ev.username = groups["user"]
            if "ip" in groups:
                ev.source_ip = groups["ip"]
            if "cmd" in groups:
                ev.command_line = groups["cmd"]
                ev.process_name = groups["cmd"].split()[0] if groups["cmd"] else None

            # su success/failure
            if tag == "su" and "Successful" in message:
                ev.status = "success"
            elif tag == "su":
                ev.status = "failure"

            return ev

    # Generic line — return only if it looks security-relevant
    sec_keywords = ["error", "fail", "invalid", "unauthorized", "denied",
                    "attack", "blocked", "auth", "session opened", "session closed"]
    msg_lower = message.lower()
    if any(kw in msg_lower for kw in sec_keywords):
        ev.category = EventCategory.SYSTEM
        return ev

    return None


class AuthLogIngestor:
    name = "authlog"

    def parse(self, file_path: str | Path, year: int = 2024) -> Iterator[LogEvent]:
        """Parse auth.log or secure log file and yield LogEvent objects."""
        path = Path(file_path)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    ev = _parse_line(line, str(path), year)
                    if ev:
                        yield ev
        except FileNotFoundError:
            raise FileNotFoundError(f"Log file not found: {path}")
        except Exception as exc:
            raise RuntimeError(f"Failed to parse auth.log '{path}': {exc}") from exc
