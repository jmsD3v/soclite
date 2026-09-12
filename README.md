# SOC-Lite

SIEM liviano de línea de comandos (D-01) que combina reglas Sigma, detección por umbrales y un modelo de anomalías (Isolation Forest) para analizar logs de autenticación de Windows y Linux, y usa Gemini para redactar el análisis de cada incidente en lenguaje natural.

## Qué hace

SOC-Lite ingiere logs (`.evtx` de Windows, `auth.log`/`secure` de Linux, o JSON/JSONL de Docker/K8s/CloudTrail), los normaliza a un esquema común (`LogEvent`) y los corre en paralelo por tres motores de detección: un motor de reglas Sigma (subset propio del formato: `contains`, `startswith`, `endswith`, `contains|all`, `and`/`or`/`not`, `count()` por ventana de tiempo), un detector de umbrales hecho a mano (fuerza bruta, enumeración de cuentas, credential stuffing, movimiento lateral, logins fuera de horario, ráfagas de procesos, escalada de privilegios repetida) y un Isolation Forest de scikit-learn entrenado on-the-fly sobre 10 features por evento (hora del día, tipo de logon, IP privada/pública, proceso sospechoso, etc.). Las alertas resultantes se correlacionan en incidentes (mismo host/usuario/IP dentro de una ventana de 30 min) y, si hay una API key de Gemini configurada, cada incidente recibe un resumen narrativo (qué pasó, ruta de ataque probable, impacto, acciones recomendadas) generado por IA. Todo corre 100% local salvo la llamada a Gemini, que es opcional y se puede desactivar con `--no-ai`.

## Características

- **3 capas de detección independientes**: Sigma (7 reglas incluidas, cubren SSH brute force, sudo-to-root, audit log limpiado, tareas programadas, LOLBins), umbrales determinísticos, y ML no supervisado (Isolation Forest).
- **3 ingestores**: EVTX de Windows (parseo XML directo, sin dependencias de Windows), auth.log/syslog de Linux, JSON/JSONL genérico con auto-detección de campos (ECS, CloudTrail, Docker).
- **Correlación de incidentes**: agrupa alertas relacionadas por host/usuario/IP compartido dentro de una ventana temporal en vez de mostrar una lista plana.
- **Análisis con IA (Gemini 1.5 Flash)**: narrativa de incidente + recomendaciones accionables; se puede correr también por alerta individual (`--analyze-alerts`). Si no hay `GEMINI_API_KEY`, el análisis se omite con un mensaje claro (no rompe el pipeline).
- **Reportes HTML** (vía Jinja2) y PDF opcional (vía WeasyPrint, si está instalado).
- **Modo `watch`**: monitorea un directorio y analiza automáticamente cada archivo de log nuevo que aparezca.
- **Reglas Sigma extensibles**: cualquier `.yml` que se agregue a `sigma_rules/` se carga automáticamente, sin tocar código.
- **Modo demo sin archivos externos**: genera un escenario sintético de brute force + escalada + movimiento lateral y corre el pipeline completo sobre eso.

## Requisitos

- Python **3.11+** (probado en este repo con 3.14.6 sobre Windows).
- Variable de entorno opcional: **`GEMINI_API_KEY`** (Google AI Studio, tiene tier gratuito) — solo necesaria para el análisis con IA. Sin ella, todo lo demás (Sigma, umbrales, ML, reportes) funciona igual.

## Instalación

```bash
cd soclite
python -m venv .venv
source .venv/Scripts/activate      # Windows: .venv\Scripts\activate
pip install -e .

cp .env.example .env
# editar .env y completar GEMINI_API_KEY (opcional, solo para análisis IA)
```

Instalación verificada localmente: `pip install -e .` resuelve sin conflictos (typer, rich, scikit-learn, numpy, python-evtx, pyyaml, python-dotenv, watchdog, google-generativeai, jinja2).

## Uso

```bash
# Demo con logs sintéticos, sin necesitar archivos ni API key
soclite demo --no-ai

# Ver las reglas Sigma cargadas
soclite rules

# Analizar un log real, sin IA ni ML (rápido)
soclite analyze sample_logs/demo_auth.log --no-ai --no-ml

# Análisis completo (Sigma + umbrales + ML + IA si hay API key) con salida JSON
soclite analyze sample_logs/demo_auth.log --output report.json

# Analizar un .evtx de un CTF (CyberDefenders, Blue Team Labs Online)
soclite analyze Security.evtx --no-ml

# Generar reporte HTML
soclite report sample_logs/demo_auth.log --no-ai -o soclite-report.html

# Monitorear un directorio y analizar cada log nuevo automáticamente
soclite watch /var/log --pattern "*.log"
```

Flags principales de `analyze`: `--sigma-dir` (reglas custom), `--no-ai`, `--no-ml`, `--analyze-alerts` (narrativa IA por alerta, no solo por incidente), `--output/-o`, `--ml-sensitivity` (contamination del Isolation Forest, 0.01–0.20), `--quiet/-q`.

## Estructura del proyecto

```
soclite/
├── pyproject.toml
├── .env.example
├── sigma_rules/            # reglas Sigma (.yml), organizadas por categoría
│   ├── auth/
│   ├── privilege/
│   └── windows/
├── sample_logs/
│   └── demo_auth.log
└── soclite/
    ├── types/events.py         # LogEvent, Alert, Incident, ScanResult
    ├── ingestors/
    │   ├── evtx.py             # parser de Windows EVTX
    │   ├── authlog.py          # parser de auth.log/syslog Linux
    │   └── jsonlog.py          # parser JSON/JSONL genérico
    ├── detectors/
    │   ├── sigma.py            # motor de reglas Sigma
    │   └── ml_anomaly.py       # Isolation Forest
    ├── detection/threshold_detector.py   # reglas de umbral hechas a mano
    ├── core/
    │   ├── pipeline.py         # orquesta ingest → detect → correlate → IA
    │   ├── correlator.py       # agrupa alerts en incidents
    │   └── ai_analyzer.py      # llamadas a Gemini
    ├── report/
    │   ├── generator.py        # HTML (Jinja2) + PDF (WeasyPrint opcional)
    │   └── template.html
    └── cli/main.py             # comandos: analyze, rules, demo, report, watch
```

## Aviso legal

Proyecto educativo / de portfolio. Pensado para analizar logs propios, de laboratorios de práctica o de datasets públicos de CTF (CyberDefenders, Blue Team Labs Online, DFIR.training). No está pensado para producción sin revisión adicional, y el análisis de IA es asistivo — no reemplaza el criterio de un analista.

<div align="center">

Copyright © 2025 Desarrollado desde Las Breñas con 💜 por [@jmsDev](https://www.linkedin.com/in/jmsilva83) · All rights reserved

</div>
