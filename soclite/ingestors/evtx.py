"""
Windows Event Log Ingestor (EVTX)

Parses .evtx files using python-evtx.
Maps key Event IDs to normalized LogEvent fields.

Key Event IDs handled:
  4624  Successful logon
  4625  Failed logon
  4648  Logon with explicit credentials (lateral movement indicator)
  4672  Special privileges at logon (admin rights)
  4688  Process creation (T1059)
  4698  Scheduled task created (T1053)
  4720  User account created (T1136)
  4726  User account deleted
  4732  Member added to privileged group (T1098)
  4776  NTLM auth attempt
  7045  Service installed (T1543)
  1102  Audit log cleared (T1070.001)

Usage against CTF/CyberDefenders EVTX files:
  evtx_parser = EvtxIngestor()
  events = list(evtx_parser.parse("Security.evtx"))
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from soclite.types.events import EventCategory, LogEvent

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

AUTH_SUCCESS_IDS = {4624, 4648, 4768, 4769, 4776}
AUTH_FAILURE_IDS = {4625}
PROCESS_IDS = {4688}
PRIVILEGE_IDS = {4672, 4732}
ACCOUNT_IDS = {4720, 4726, 4738}
SCHEDULED_TASK_IDS = {4698, 4702}
SERVICE_IDS = {7045}
AUDIT_IDS = {1102, 1100}


def _parse_system(sys_elem: ET.Element) -> dict:
    out: dict = {}
    eid = sys_elem.find(f"{NS}EventID")
    if eid is not None and eid.text:
        try:
            out["event_id"] = int(eid.text)
        except ValueError:
            pass
    tc = sys_elem.find(f"{NS}TimeCreated")
    if tc is not None:
        st = tc.get("SystemTime", "")
        if st:
            try:
                if st.endswith("Z"):
                    st = st[:-1] + "+00:00"
                out["timestamp"] = datetime.fromisoformat(st.replace("0000000Z", "Z").rstrip("0").rstrip("+") + "+00:00")
            except Exception:
                pass
    comp = sys_elem.find(f"{NS}Computer")
    if comp is not None and comp.text:
        out["hostname"] = comp.text
    chan = sys_elem.find(f"{NS}Channel")
    if chan is not None and chan.text:
        out["channel"] = chan.text
    return out


def _parse_eventdata(data_elem: ET.Element) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in data_elem.findall(f"{NS}Data"):
        name = item.get("Name", "")
        val = item.text or ""
        if name:
            out[name] = val
    return out


def _build_event(xml_text: str, source_file: str) -> LogEvent | None:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    sys_elem = root.find(f"{NS}System")
    if sys_elem is None:
        return None

    sys_info = _parse_system(sys_elem)
    event_id: int = sys_info.get("event_id", 0)

    data_elem = root.find(f"{NS}EventData")
    data: dict[str, str] = _parse_eventdata(data_elem) if data_elem is not None else {}

    ev = LogEvent(
        source_type="evtx",
        source_file=source_file,
        hostname=sys_info.get("hostname", "unknown"),
        timestamp=sys_info.get("timestamp", datetime.now(timezone.utc)),
        event_id=event_id,
        channel=sys_info.get("channel"),
        raw=data,
    )

    if event_id in AUTH_SUCCESS_IDS:
        ev.category = EventCategory.AUTHENTICATION
        ev.status = "success"
        ev.username = data.get("TargetUserName") or data.get("SubjectUserName")
        ev.source_ip = data.get("IpAddress") or data.get("WorkstationName")
        ev.logon_type = int(data.get("LogonType", "0") or "0")
        ev.message = f"Logon success: {ev.username} from {ev.source_ip} (type {ev.logon_type})"

    elif event_id in AUTH_FAILURE_IDS:
        ev.category = EventCategory.AUTHENTICATION
        ev.status = "failure"
        ev.username = data.get("TargetUserName")
        ev.source_ip = data.get("IpAddress") or data.get("WorkstationName")
        ev.logon_type = int(data.get("LogonType", "0") or "0")
        failure_reason = data.get("FailureReason", "")
        ev.message = f"Logon FAILED: {ev.username} from {ev.source_ip} — {failure_reason}"

    elif event_id in PROCESS_IDS:
        ev.category = EventCategory.PROCESS
        ev.username = data.get("SubjectUserName")
        ev.process_name = data.get("NewProcessName", "")
        ev.parent_process = data.get("ParentProcessName", "")
        ev.command_line = data.get("CommandLine", "")
        try:
            ev.process_id = int(data.get("NewProcessId", "0"), 16)
        except ValueError:
            pass
        ev.message = f"Process created: {ev.process_name} by {ev.username}"

    elif event_id in PRIVILEGE_IDS:
        ev.category = EventCategory.AUTHENTICATION
        ev.status = "success"
        ev.username = data.get("SubjectUserName") or data.get("MemberName")
        ev.message = f"Privilege assigned to {ev.username}: {data.get('PrivilegeList', data.get('GroupName', ''))}"
        ev.tags.append("privilege_escalation")

    elif event_id in ACCOUNT_IDS:
        ev.category = EventCategory.SYSTEM
        ev.username = data.get("TargetUserName")
        ev.message = f"Account action (EID {event_id}): {ev.username}"

    elif event_id in SCHEDULED_TASK_IDS:
        ev.category = EventCategory.SYSTEM
        ev.username = data.get("SubjectUserName")
        task_name = data.get("TaskName", "")
        ev.message = f"Scheduled task created: {task_name} by {ev.username}"
        ev.tags.append("persistence")

    elif event_id in SERVICE_IDS:
        ev.category = EventCategory.SYSTEM
        service_name = data.get("ServiceName", "")
        service_file = data.get("ImagePath", "")
        ev.message = f"Service installed: {service_name} → {service_file}"
        ev.tags.append("persistence")

    elif event_id in AUDIT_IDS:
        ev.category = EventCategory.AUDIT
        ev.username = data.get("SubjectUserName")
        ev.message = f"Audit log cleared by {ev.username}"
        ev.tags.append("defense_evasion")
        ev.status = "cleared"

    else:
        ev.category = EventCategory.UNKNOWN
        ev.message = f"Event {event_id} on {ev.hostname}"

    return ev


class EvtxIngestor:
    name = "evtx"

    def parse(self, file_path: str | Path) -> Iterator[LogEvent]:
        """Parse an EVTX file and yield LogEvent objects."""
        path = str(file_path)
        try:
            import Evtx.Evtx as evtx
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        xml_text = record.xml()
                        ev = _build_event(xml_text, path)
                        if ev:
                            yield ev
                    except Exception:
                        continue
        except ImportError:
            # python-evtx not installed — yield nothing, log warning
            import warnings
            warnings.warn("python-evtx not installed. Run: pip install python-evtx")
        except Exception as exc:
            raise RuntimeError(f"Failed to parse EVTX file '{path}': {exc}") from exc
