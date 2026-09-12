"""
AI Analyzer — an LLM generates incident narratives (provider-agnostic).

Supports Anthropic Claude, Google Gemini, or OpenAI — whichever API key is
found in the environment first (see _detect_provider for priority order).

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

# Priority order when more than one provider's key is set.
_PROVIDER_ENV_VARS = [
    ("ANTHROPIC_API_KEY", "anthropic"),
    ("GEMINI_API_KEY", "gemini"),
    ("OPENAI_API_KEY", "openai"),
]


def _detect_provider() -> tuple[str, str] | None:
    """Return (provider, api_key) for the first configured provider.

    Priority: Anthropic Claude > Google Gemini > OpenAI.
    """
    for env_var, provider in _PROVIDER_ENV_VARS:
        key = os.getenv(env_var, "").strip()
        if key:
            return provider, key
    return None


def _call_anthropic_sync(prompt: str, api_key: str) -> str:
    import anthropic  # type: ignore[import]
    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(
        model="claude-3-5-haiku-20241022",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in response.content if hasattr(block, "text"))


def _call_gemini_sync(prompt: str, api_key: str) -> str:
    import google.generativeai as genai  # type: ignore[import]
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(prompt)
    return response.text


def _call_openai_sync(prompt: str, api_key: str) -> str:
    import openai  # type: ignore[import]
    client = openai.OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content or ""


async def _call_ai(prompt: str) -> str:
    """Call whichever AI provider has a configured API key."""
    detected = _detect_provider()
    if not detected:
        return (
            "AI analysis skipped: no AI API key set "
            "(ANTHROPIC_API_KEY, GEMINI_API_KEY, or OPENAI_API_KEY)."
        )
    provider, api_key = detected
    try:
        if provider == "anthropic":
            return await asyncio.to_thread(_call_anthropic_sync, prompt, api_key)
        if provider == "openai":
            return await asyncio.to_thread(_call_openai_sync, prompt, api_key)
        return await asyncio.to_thread(_call_gemini_sync, prompt, api_key)
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
    text = await _call_ai(_build_incident_prompt(incident))
    incident.ai_analysis = text
    actions = re.findall(r"^\d+\.\s+(.+)$", text, re.MULTILINE)
    incident.recommendations = actions[:5]


async def analyze_alert(alert: Alert) -> str:
    return await _call_ai(_build_alert_prompt(alert))


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
