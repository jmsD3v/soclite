"""
AI Analyzer — Gemini generates incident narratives (free API).

analyze_all(result) fills:
  - incident.ai_analysis
  - incident.recommendations
  - alert.ai_narrative (if analyze_alerts=True)
"""

from __future__ import annotations

import asyncio
import os
import re

from soclite.types.events import Alert, Incident, ScanResult


async def _call_gemini(prompt: str) -> str:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        return "AI analysis skipped: GEMINI_API_KEY not set."
    try:
        import google.generativeai as genai  # type: ignore[import]
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = await asyncio.to_thread(model.generate_content, prompt)
        return response.text
    except Exception as exc:
        return f"AI analysis unavailable: {exc}"


def _build_alert_prompt(alert: Alert) -> str:
    events_summary = "\n".join(
        f"  [{e.timestamp.strftime('%H:%M:%S')}] {e.category.value}"
        f" | user={e.username or '?'} | ip={e.source_ip or '?'}"
        + (f" | cmd={e.command_line[:60]}" if e.command_line else "")
        for e in alert.events[:15]
    )
    mitre = ", ".join(alert.mitre_techniques) if alert.mitre_techniques else "unknown"
    return (
        f"You are a Tier 2 SOC analyst writing an incident note.\n\n"
        f"Alert: {alert.rule_name}\n"
        f"Source: {alert.rule_source}\n"
        f"Severity: {alert.severity.value.upper()}\n"
        f"MITRE ATT&CK: {mitre}\n"
        f"Description: {alert.description}\n\n"
        f"Event timeline:\n{events_summary}\n\n"
        f"Write a concise incident note (3-5 sentences): what happened, "
        f"why it is suspicious, what the attacker may be attempting, "
        f"and one immediate recommended action. Plain text only."
    )


def _build_incident_prompt(incident: Incident) -> str:
    events_summary = "\n".join(
        f"  [{e.timestamp.strftime('%H:%M:%S')}] {e.category.value}"
        f" user={e.username or '?'} ip={e.source_ip or '?'}"
        for e in incident.timeline[:25]
    )
    techniques = sorted({t for a in incident.alerts for t in a.mitre_techniques})
    tactics = sorted({t for a in incident.alerts for t in a.mitre_tactics})
    rule_names = sorted({a.rule_name for a in incident.alerts})

    return (
        f"You are a senior SOC analyst writing an incident investigation report.\n\n"
        f"Incident: {incident.name}\n"
        f"Severity: {incident.severity.value.upper()}\n"
        f"Alerts: {len(incident.alerts)} ({', '.join(rule_names[:4])})\n"
        f"Affected users: {', '.join(incident.affected_users) or 'unknown'}\n"
        f"Source IPs: {', '.join(incident.source_ips) or 'unknown'}\n"
        f"MITRE techniques: {', '.join(techniques) or 'unknown'}\n"
        f"MITRE tactics: {', '.join(tactics) or 'unknown'}\n\n"
        f"Event timeline:\n{events_summary}\n\n"
        f"Write a structured incident analysis:\n"
        f"SUMMARY (2 sentences): What happened overall\n"
        f"ATTACK PATH (2-3 sentences): The likely sequence of attacker actions\n"
        f"IMPACT (1-2 sentences): Potential damage if not contained\n"
        f"IMMEDIATE ACTIONS (3 numbered items): What the team should do right now\n\n"
        f"Plain text, use section labels exactly as shown."
    )


async def analyze_incident(incident: Incident) -> None:
    text = await _call_gemini(_build_incident_prompt(incident))
    incident.ai_analysis = text
    actions = re.findall(r"^\d+\.\s+(.+)$", text, re.MULTILINE)
    incident.recommendations = actions[:5]


async def analyze_alert(alert: Alert) -> str:
    return await _call_gemini(_build_alert_prompt(alert))


async def analyze_all(result: ScanResult, analyze_alerts: bool = False) -> None:
    """Analyze all incidents and optionally all alerts."""
    sem = asyncio.Semaphore(3)

    async def _analyze_incident(inc: Incident) -> None:
        async with sem:
            await analyze_incident(inc)

    async def _analyze_alert(alert: Alert) -> None:
        async with sem:
            alert.ai_narrative = await analyze_alert(alert)

    tasks = [_analyze_incident(inc) for inc in result.incidents]
    if analyze_alerts:
        tasks += [_analyze_alert(a) for a in result.alerts[:20]]

    if tasks:
        await asyncio.gather(*tasks)
