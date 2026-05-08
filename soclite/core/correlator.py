"""
Alert Correlator

Agrupa alerts relacionadas en Incidents usando:
  - Mismo host en ventana de tiempo
  - Mismo usuario en ventana de tiempo
  - Misma IP de origen
  - Mismo MITRE tactic (ej: múltiples alerts de Discovery → un incident)

Algoritmo simple y efectivo:
  1. Ordenar alerts por timestamp
  2. Para cada alert, buscar un incident existente que comparta
     host, usuario, o IP dentro de la ventana
  3. Si existe → agregar al incident (actualizar last_seen)
  4. Si no → crear nuevo incident
  5. Calcular severity del incident = max severity de sus alerts

Ventana por defecto: 30 minutos
"""

from __future__ import annotations

from datetime import timedelta

from soclite.types.events import Alert, Incident, Severity


CORRELATION_WINDOW = timedelta(minutes=30)

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _max_severity(alerts: list[Alert]) -> Severity:
    weights = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return min(alerts, key=lambda a: weights[a.severity]).severity


def _alert_indicators(alert: Alert) -> set[str]:
    """Extract correlation indicators from an alert."""
    indicators: set[str] = set()
    for ev in alert.events:
        if ev.hostname and ev.hostname != "unknown":
            indicators.add(f"host:{ev.hostname}")
        if ev.username:
            indicators.add(f"user:{ev.username}")
        if ev.source_ip:
            indicators.add(f"ip:{ev.source_ip}")
    return indicators


def _incident_indicators(incident: Incident) -> set[str]:
    indicators: set[str] = set()
    for h in incident.affected_hosts:
        indicators.add(f"host:{h}")
    for u in incident.affected_users:
        indicators.add(f"user:{u}")
    for ip in incident.source_ips:
        indicators.add(f"ip:{ip}")
    return indicators


def _update_incident(incident: Incident, alert: Alert) -> None:
    """Add an alert to an existing incident and update metadata."""
    incident.alerts.append(alert)
    incident.last_seen = max(incident.last_seen, alert.timestamp)
    incident.severity = _max_severity(incident.alerts)

    for ev in alert.events:
        if ev.hostname and ev.hostname not in incident.affected_hosts:
            incident.affected_hosts.append(ev.hostname)
        if ev.username and ev.username not in incident.affected_users:
            incident.affected_users.append(ev.username)
        if ev.source_ip and ev.source_ip not in incident.source_ips:
            incident.source_ips.append(ev.source_ip)


def _name_incident(incident: Incident) -> str:
    """Generate a descriptive incident name from its alerts."""
    tactics = set()
    for alert in incident.alerts:
        tactics.update(alert.mitre_tactics)

    if tactics:
        tactic_str = " + ".join(sorted(tactics)[:2])
        host = incident.affected_hosts[0] if incident.affected_hosts else "unknown"
        return f"{tactic_str} — {host}"

    # Fall back to rule names
    rule_names = list({a.rule_name for a in incident.alerts})
    base = rule_names[0] if rule_names else "Unknown Activity"
    if len(incident.alerts) > 1:
        base += f" (+{len(incident.alerts)-1} more)"
    return base


def correlate(alerts: list[Alert], window: timedelta = CORRELATION_WINDOW) -> list[Incident]:
    """
    Correlate a flat list of alerts into incidents.
    Returns a list of Incident objects, each containing related alerts.
    """
    if not alerts:
        return []

    sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)
    incidents: list[Incident] = []

    for alert in sorted_alerts:
        alert_inds = _alert_indicators(alert)
        matched = None

        for incident in incidents:
            # Must be within correlation window
            if (alert.timestamp - incident.last_seen) > window:
                continue
            # Must share at least one indicator
            inc_inds = _incident_indicators(incident)
            if alert_inds & inc_inds:
                matched = incident
                break

        if matched:
            _update_incident(matched, alert)
        else:
            # Create new incident
            inc = Incident(
                alerts=[alert],
                severity=alert.severity,
                first_seen=alert.timestamp,
                last_seen=alert.timestamp,
            )
            for ev in alert.events:
                if ev.hostname and ev.hostname not in inc.affected_hosts:
                    inc.affected_hosts.append(ev.hostname)
                if ev.username and ev.username not in inc.affected_users:
                    inc.affected_users.append(ev.username)
                if ev.source_ip and ev.source_ip not in inc.source_ips:
                    inc.source_ips.append(ev.source_ip)
            incidents.append(inc)

    # Name all incidents and filter singletons with low severity
    result = []
    for inc in incidents:
        inc.name = _name_incident(inc)
        # Only report incidents with HIGH+ or multiple alerts
        if len(inc.alerts) >= 2 or inc.severity.weight >= Severity.HIGH.weight:
            result.append(inc)

    return sorted(result, key=lambda i: i.severity.weight, reverse=True)
