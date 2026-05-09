# 🛡️ SOC-Lite — AI-Powered Lightweight SIEM

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![SIEM](https://img.shields.io/badge/SIEM-Lightweight-0077b6?style=for-the-badge)
![ML](https://img.shields.io/badge/ML-IsolationForest-ff6b6b?style=for-the-badge&logo=scikitlearn&logoColor=white)
![Gemini](https://img.shields.io/badge/Gemini_AI-Free_Tier-4285F4?style=for-the-badge&logo=google&logoColor=white)
![Portfolio](https://img.shields.io/badge/Portfolio-D--01_Defensive-0077b6?style=for-the-badge)

**Log ingestion, Sigma rule detection, ML anomaly detection, and AI incident triage in a single CLI**

*D-01 of 9 · Cybersecurity Portfolio by [@jmsDev](https://www.linkedin.com/in/jmsilva83)*

</div>

---

## What it does

SOC-Lite ingests log files (JSON, JSONL, Windows Event Log) and runs them through a **three-layer detection pipeline**: Sigma-style rule matching, threshold-based behavioral detection, and ML anomaly detection (IsolationForest). Suspicious activity is escalated to **Google Gemini** for incident triage and analyst recommendations.

```bash
soclite analyze /var/log/auth.log --format syslog
soclite analyze security.jsonl --format json --ai
soclite monitor /var/log/  --watch --interval 30
```

---

## Detection Layers

### Layer 1 — Sigma Rules
YAML-based detection rules covering common attack patterns. Rules ship with the tool and are evaluated against every ingested event.

| Rule Category | Examples |
|---|---|
| Credential Access | Mimikatz keywords, LSASS access, credential dumping |
| Lateral Movement | PsExec, WMI remote execution, admin share access |
| Persistence | New scheduled task, Run key modification, new service |
| Defense Evasion | Log clearing (Event ID 1102/104), AMSI bypass strings |
| Privilege Escalation | Token impersonation, UAC bypass patterns |
| C2 Communication | PowerShell download cradles, Certutil abuse |

### Layer 2 — Threshold Detection
Sliding-window behavioral rules with configurable thresholds:

| Rule | Default Threshold | Window |
|---|---|---|
| `brute_force_ip` | ≥ 10 failures from same IP | 5 min |
| `account_enum` | ≥ 20 unique users | 10 min |
| `credential_stuffing` | ≥ 5 IPs, ≥ 50 failures | 10 min |
| `lateral_movement` | ≥ 3 hosts, admin ports | 15 min |
| `after_hours_login` | Success outside 08:00–20:00 | — |
| `process_burst` | ≥ 50 new processes | 1 min |
| `repeated_priv_esc` | ≥ 3 privilege events | 5 min |

### Layer 3 — ML Anomaly Detection
`IsolationForest` trained on baseline log patterns. Flags statistical outliers in:
- Login frequency per user/IP
- Process creation rates
- Network connection patterns
- Time-of-day access distribution

---

## Features

- **Multi-format ingestion** — JSONL, JSON arrays, ECS, CloudTrail, Azure AD logs, syslog
- **Auto-field detection** — dot-notation field lookup handles arbitrary log schemas
- **Three detection layers** — rules + thresholds + ML, all independent
- **Real-time monitoring** — `--watch` mode with configurable polling interval
- **AI incident triage** — Gemini correlates alerts into incidents with priority and recommended actions
- **Rich terminal dashboard** — live alert table, severity counters, incident panels
- **HTML/PDF reports** — professional dark-theme report with incident timeline

---

## Installation

```bash
git clone https://github.com/jmsdev83/soclite
cd soclite
pip install -e .

cp .env.example .env
# Add GEMINI_API_KEY to .env (optional)
```

---

## Usage

```bash
# Analyze a log file
soclite analyze auth.jsonl

# Analyze with AI triage
soclite analyze auth.jsonl --ai

# Watch a directory for new events (real-time mode)
soclite monitor /var/log/ --watch --interval 30

# Generate HTML report
soclite report alerts.json --output report.html

# Run detection against specific log types
soclite analyze events.evtx --format evtx --ai

# List loaded Sigma rules
soclite rules

# Test a single log line against all rules
soclite test '{"event_type":"login","user":"admin","ip":"192.168.1.5","status":"failed"}'
```

---

## Architecture

```
soclite analyze <file>
       │
       ▼
  LogIngestor          ← parse JSONL/JSON/syslog, normalize to LogEvent
       │
       ▼
  DetectionPipeline    ← three parallel layers
  ┌────┴────────────────────────────────────────────┐
  │  SigmaEngine        ← YAML rule matching         │
  │  ThresholdDetector  ← sliding-window behavioral  │
  │  MLDetector         ← IsolationForest outliers   │
  └────┬────────────────────────────────────────────┘
       │
       ▼
  AlertAggregator      ← deduplicate, correlate, assign severity
       │
       ▼
  GeminiAnalyzer       ← incident triage + analyst recommendations
       │
       ▼
  Rich dashboard / HTML report
```

---

## Supported Log Formats

| Format | Flag | Example Sources |
|---|---|---|
| JSON Lines | `--format json` | Suricata, Zeek, custom apps |
| JSON Array | `--format json` | CloudTrail, Azure AD |
| ECS | `--format json` | Elastic Stack |
| Syslog | `--format syslog` | `/var/log/auth.log`, `/var/log/syslog` |
| Windows EVTX | `--format evtx` | Windows Security/System logs |

---

## Severity Levels

| Level | Meaning | Alert Examples |
|---|---|---|
| 🔴 **CRITICAL** | Active compromise indicator | Mimikatz detected, LSASS dump |
| 🟠 **HIGH** | Strong attack signal | Brute force success, lateral movement |
| 🟡 **MEDIUM** | Suspicious activity | Multiple failed logins, after-hours access |
| 🔵 **LOW** | Weak anomaly signal | ML outlier, unusual process count |
| ⚪ **INFO** | Baseline deviation | Off-hours login, new user agent |

---

## Project Structure

```
soclite/
├── soclite/
│   ├── ingestors/
│   │   ├── base.py             # BaseIngestor ABC
│   │   ├── jsonlog.py          # JSON/JSONL/ECS/CloudTrail
│   │   └── syslog.py           # Syslog format parser
│   ├── detection/
│   │   ├── sigma_engine.py     # YAML Sigma rule evaluator
│   │   ├── threshold_detector.py # Sliding-window rules
│   │   └── ml_detector.py      # IsolationForest anomaly detection
│   ├── rules/                  # Built-in Sigma YAML rules
│   │   ├── credential_access.yml
│   │   ├── lateral_movement.yml
│   │   ├── persistence.yml
│   │   └── defense_evasion.yml
│   ├── core/
│   │   ├── pipeline.py         # Three-layer detection orchestration
│   │   └── ai_analyzer.py      # Gemini incident triage
│   ├── types/
│   │   └── events.py           # LogEvent, Alert, Incident
│   ├── report/
│   │   ├── generator.py
│   │   └── template.html
│   └── cli/
│       └── main.py
└── pyproject.toml
```

---

## Environment Variables

```env
GEMINI_API_KEY=your-key-here      # AI incident triage (optional)
SOC_RULES_DIR=/path/to/rules      # Custom Sigma rules directory
SOC_BASELINE_HOURS=168            # Hours of baseline for ML (default 7 days)
```

---

## Portfolio

| # | Category | Project | Status |
|---|---|---|---|
| P-01 | Offensive | ReconAI — Recon Orchestrator | ✅ |
| P-02 | Offensive | WebHunter — OWASP Top 10 Scanner | ✅ |
| P-03 | Offensive | PhishSim — Red Team Phishing | ✅ |
| D-01 | Defensive | **SOC-Lite** ← you are here | ✅ |
| D-02 | Defensive | ThreatFeed — CTI Aggregator | ✅ |
| D-03 | Defensive | HoneyGrid — SSH/HTTP Honeypot | ✅ |
| F-01 | Forensics | DFIR-Auto — Forensic Triage | ✅ |
| F-02 | Forensics | MalwareScope — Malware Analyzer | ✅ |
| F-03 | Forensics | PCAPForge — Network Forensics | ✅ |

---

<div align="center">

Copyright © 2025 Desarrollado desde Las Breñas con 💜 por [@jmsDev](https://www.linkedin.com/in/jmsilva83) · All rights reserved

</div>
