# CLAUDE.md — SOC-Lite

Lee esto antes de tocar cualquier archivo.

---

## Qué es este proyecto

**SOC-Lite** es el proyecto D-01 del portfolio de ciberseguridad de Juanma.
Es un SIEM liviano con tres capas de detección: Sigma rules, ML anomaly detection, y análisis con Claude.
Procesa logs reales de Windows (.evtx) y Linux (auth.log, syslog).

**Portfolio completo:**
- P-01 ReconAI ✓ | P-02 WebHunter ✓ | P-03 PhishSim ✓
- D-01 SOC-Lite ← este proyecto
- D-02 ThreatFeed | D-03 HoneyGrid | F-01 DFIR-Auto | F-02 MalwareScope | F-03 PCAPForge

---

## Estado actual — Fase 1 completa

```
soclite/
├── pyproject.toml
├── sigma_rules/
│   ├── auth/
│   │   ├── brute_force_ssh.yml
│   │   └── successful_login_after_failures.yml
│   ├── privilege/
│   │   └── sudo_to_root.yml
│   └── windows/
│       ├── win_failed_logon_spike.yml
│       ├── win_suspicious_process.yml
│       ├── win_audit_log_cleared.yml
│       └── win_scheduled_task_created.yml
├── sample_logs/
│   └── demo_auth.log
└── soclite/
    ├── types/events.py       ← LogEvent, Alert, Incident, ScanResult
    ├── ingestors/
    │   ├── evtx.py           ← Windows EVTX parser (python-evtx)
    │   └── authlog.py        ← Linux auth.log/syslog parser
    ├── detectors/
    │   ├── sigma.py          ← Sigma YAML rule engine
    │   └── ml_anomaly.py     ← Isolation Forest anomaly detector
    ├── core/
    │   ├── pipeline.py       ← orchestrates ingest → detect → correlate → AI
    │   ├── correlator.py     ← groups alerts into incidents
    │   └── ai_analyzer.py    ← Claude API: incident narratives + recommendations
    └── cli/main.py           ← CLI: analyze, demo, rules, watch
```

---

## Setup

```bash
pip install -e .
cp .env.example .env     # agregar ANTHROPIC_API_KEY

# Verificar que todo importa correctamente
python -c "from soclite.core.pipeline import run_pipeline; print('OK')"

# Primer run — demo con logs sintéticos (no necesita archivos externos)
soclite demo

# Demo sin AI (más rápido, sin API key)
soclite demo --no-ai

# Ver reglas Sigma cargadas
soclite rules

# Analizar logs reales
soclite analyze sample_logs/demo_auth.log

# Analizar EVTX de CTF (CyberDefenders, Blue Team Labs Online)
soclite analyze Security.evtx --no-ml

# Análisis completo con output JSON
soclite analyze Security.evtx auth.log --output report.json
```

---

## Flujo del pipeline

```
Files → Ingestor → [LogEvent...] → Sigma Engine → [Alert...]
                                 → ML Detector  → [Alert...]
                                 ↓
                             Correlator → [Incident...]
                                 ↓
                           AI Analyzer → narratives + recommendations
                                 ↓
                           ScanResult → CLI dashboard + JSON
```

---

## Cómo agregar una Sigma rule

1. Crear un `.yml` en `sigma_rules/` (cualquier subdirectorio)
2. El motor la levanta automáticamente — sin tocar código

```yaml
title: Mi regla custom
id: custom-001
status: stable
description: Descripción de qué detecta
level: high   # critical | high | medium | low | informational
logsource:
  product: linux   # linux | windows
  service: auth
detection:
  selection:
    status: failure
    tags|contains: ssh_failed   # campo|modificador: valor
  condition: selection | count() > 5   # o simplemente: selection
tags:
  - attack.credential_access
  - attack.t1110
```

**Campos Sigma → LogEvent mapping:**

| Sigma field | LogEvent attribute |
|---|---|
| EventID | event_id |
| Computer/Hostname | hostname |
| User/SubjectUserName/TargetUserName | username |
| IpAddress/SourceIp | source_ip |
| CommandLine | command_line |
| Image/NewProcessName | process_name |
| ParentImage | parent_process |
| Message | message |

**Modificadores soportados:** `contains`, `startswith`, `endswith`, `contains\|all`, `re`

---

## Cómo agregar un ingestor

```python
# soclite/ingestors/json_log.py
from soclite.types.events import LogEvent, EventCategory
from pathlib import Path
from typing import Iterator

class JSONLogIngestor:
    name = "json"

    def parse(self, file_path: str | Path) -> Iterator[LogEvent]:
        import json
        with open(file_path) as f:
            for line in f:
                data = json.loads(line)
                ev = LogEvent(
                    source_type="json",
                    source_file=str(file_path),
                    hostname=data.get("host", "unknown"),
                    message=data.get("message", ""),
                    # ... mapear campos
                )
                yield ev
```

Luego en `core/pipeline.py`, agregar en `_detect_log_type()` y `_ingest()`.

---

## Log sources para práctica real

### Linux auth.log
```bash
# Tu propia máquina Linux/WSL
soclite analyze /var/log/auth.log

# Generar actividad de prueba
ssh nonexistent@localhost   # genera failed attempts
sudo ls                      # genera sudo event
```

### Windows EVTX — CTF datasets
- **CyberDefenders.org** — descargar CTF challenges, tienen EVTX reales
- **Blue Team Labs Online** — labs con logs de incidentes reales
- **DFIR.training** — colección de logs de incidentes
- **Splunk Boss of the SOC** — dataset completo de SOC exercise

### Generar EVTX en lab propio
```powershell
# En una VM Windows
# Generar failed logons (Event 4625)
net user nonexistent WrongPassword /domain

# Generar process creation (Event 4688)
# (necesita audit policy habilitada)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

---

## MITRE ATT&CK en Sigma rules

Formato de tags:
```yaml
tags:
  - attack.t1110         # Técnica principal (T1110 = Brute Force)
  - attack.t1110.001     # Sub-técnica (Password Guessing)
  - attack.credential_access  # Táctica
```

Tácticas principales:
```
initial_access | execution | persistence | privilege_escalation
defense_evasion | credential_access | discovery | lateral_movement
collection | command_and_control | exfiltration | impact
```

---

## Fase 2 — Pendiente (hacer en Claude Code)

| Feature | Descripción |
|---|---|
| `ingestors/syslog.py` | Parser genérico syslog RFC 5424 |
| `ingestors/json_log.py` | Parser JSON/JSONL (Elastic, Splunk export) |
| `cli/watch.py` | inotify/watchdog para monitoreo en tiempo real |
| Supabase persistence | Guardar alerts/incidents entre runs |
| FastAPI dashboard | REST API + WebSocket para dashboard en vivo |
| Next.js frontend | Dashboard con alertas color-coded en tiempo real |
| More Sigma rules | Mimikatz, LSASS dump, net commands, PowerShell encoded |

---

## Variables de entorno

```bash
ANTHROPIC_API_KEY=sk-ant-...   # requerida para AI analysis
```

---

## Comandos útiles en Claude Code

```bash
# Setup completo
pip install -e .

# Test imports
python -c "from soclite.core.pipeline import run_pipeline; print('OK')"
python -c "from soclite.detectors.sigma import load_rules; r = load_rules('sigma_rules'); print(f'{len(r)} rules')"
python -c "from soclite.ingestors.authlog import AuthLogIngestor; evs = list(AuthLogIngestor().parse('sample_logs/demo_auth.log')); print(f'{len(evs)} events')"

# Demo completo
soclite demo --no-ai

# Analizar con archivo real
soclite analyze sample_logs/demo_auth.log --no-ai

# Ver todas las reglas
soclite rules

# Output JSON para inspección
soclite analyze sample_logs/demo_auth.log --no-ai --output /tmp/out.json && python -m json.tool /tmp/out.json | head -60
```

---

## Footer obligatorio

```
Copyright © {año actual, calculado dinámicamente — nunca hardcodear} Desarrollado desde Las Breñas con 💜 por @jmsDev All rights reserved
```
`@jmsDev` → https://www.linkedin.com/in/jmsilva83
