"""
SOC-Lite detection pipeline — orchestrates the full analysis run.

Flow:
  1. Detect file type → select ingestor (evtx | authlog | syslog)
  2. Parse all events → list[LogEvent]
  3. Sigma engine → list[Alert]  (rule-based)
  4. ML detector  → list[Alert]  (anomaly-based)
  5. Deduplicate and merge alerts
  6. Correlate into Incidents
  7. AI analysis on incidents (optional)
  8. Return ScanResult
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from soclite.core.correlator import correlate
from soclite.detectors.ml_anomaly import MLAnomalyDetector
from soclite.detectors.sigma import SigmaEngine, load_rules
from soclite.ingestors.authlog import AuthLogIngestor
from soclite.ingestors.evtx import EvtxIngestor
from soclite.types.events import Alert, ScanResult

console = Console()

DEFAULT_SIGMA_DIR = Path(__file__).parent.parent.parent / "sigma_rules"


def _detect_log_type(path: Path) -> str:
    suffix = path.suffix.lower()
    name = path.name.lower()
    if suffix == ".evtx":
        return "evtx"
    if "auth" in name or "secure" in name or suffix == ".log":
        return "authlog"
    if suffix in (".json", ".jsonl"):
        return "json"
    return "authlog"  # default fallback


def _ingest(file_path: Path) -> list:
    log_type = _detect_log_type(file_path)
    if log_type == "evtx":
        return list(EvtxIngestor().parse(file_path))
    else:
        return list(AuthLogIngestor().parse(file_path))


def _dedup_alerts(alerts: list[Alert]) -> list[Alert]:
    """Remove duplicate alerts (same rule + same event timestamp + same host)."""
    seen: set[str] = set()
    unique: list[Alert] = []
    for a in alerts:
        host = a.events[0].hostname if a.events else "?"
        key = f"{a.rule_id}:{host}:{a.timestamp.isoformat()[:16]}"
        if key not in seen:
            seen.add(key)
            unique.append(a)
    return unique


async def run_pipeline(
    files: list[str | Path],
    sigma_dir: str | Path | None = None,
    use_ml: bool = True,
    use_ai: bool = True,
    analyze_alerts: bool = False,
    ml_contamination: float = 0.05,
) -> ScanResult:
    result = ScanResult(source_files=[str(f) for f in files])
    start = time.perf_counter()

    # Load Sigma rules
    rules_path = Path(sigma_dir) if sigma_dir else DEFAULT_SIGMA_DIR
    rules = load_rules(rules_path) if rules_path.exists() else []

    sigma_engine = SigmaEngine(rules)
    ml_detector = MLAnomalyDetector(contamination=ml_contamination)

    all_events = []
    all_alerts: list[Alert] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:

        # Ingest
        t_ingest = progress.add_task("[cyan]Ingesting log files...", total=None)
        for f in files:
            try:
                events = _ingest(Path(f))
                all_events.extend(events)
                progress.update(
                    t_ingest,
                    description=f"[cyan]Ingested {Path(f).name} — {len(events)} events"
                )
            except Exception as exc:
                console.print(f"[red]Failed to ingest {f}: {exc}[/red]")
        progress.update(t_ingest, description=f"[green]Ingestion complete — {len(all_events)} events", completed=1, total=1)

        result.events_processed = len(all_events)

        # Sigma detection
        if rules:
            t_sigma = progress.add_task(f"[cyan]Running {len(rules)} Sigma rules...", total=None)
            sigma_alerts = sigma_engine.process(all_events)
            sigma_alerts = _dedup_alerts(sigma_alerts)
            all_alerts.extend(sigma_alerts)
            progress.update(t_sigma, description=f"[green]Sigma — {len(sigma_alerts)} alerts", completed=1, total=1)
        else:
            console.print("[yellow]No Sigma rules found. Add .yml files to sigma_rules/[/yellow]")

        # ML detection
        if use_ml and len(all_events) >= 20:
            t_ml = progress.add_task("[cyan]ML anomaly detection...", total=None)
            ml_alerts = ml_detector.detect(all_events)
            all_alerts.extend(ml_alerts)
            progress.update(t_ml, description=f"[green]ML — {len(ml_alerts)} anomalies", completed=1, total=1)

        # Correlate
        t_corr = progress.add_task("[cyan]Correlating alerts into incidents...", total=None)
        incidents = correlate(all_alerts)
        result.alerts = all_alerts
        result.incidents = incidents
        progress.update(t_corr, description=f"[green]Correlated — {len(incidents)} incidents", completed=1, total=1)

        # AI analysis
        if use_ai and (incidents or all_alerts):
            t_ai = progress.add_task("[purple]Claude AI analysis...", total=None)
            from soclite.core.ai_analyzer import analyze_all
            await analyze_all(result, analyze_alerts=analyze_alerts)
            progress.update(t_ai, description="[green]AI analysis complete", completed=1, total=1)

    result.duration_seconds = time.perf_counter() - start
    return result
