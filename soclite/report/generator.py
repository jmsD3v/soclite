"""HTML (+ optional PDF) report generator for SOC-Lite scan results."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from soclite.types.events import ScanResult

_TEMPLATE_DIR = Path(__file__).parent
_VERSION = "0.1.0"


def _duration_str(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s}s"


def _build_context(result: ScanResult) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    alerts_data = []
    for a in result.sorted_alerts():
        d = a.to_dict()
        d["description"] = a.description
        d["event_count"] = len(a.events)
        d["timestamp"] = a.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        alerts_data.append(d)

    incidents_data = []
    for inc in result.incidents:
        d = inc.to_dict()
        d["first_seen"] = inc.first_seen.strftime("%Y-%m-%d %H:%M")
        d["last_seen"] = inc.last_seen.strftime("%Y-%m-%d %H:%M")
        incidents_data.append(d)

    summary = {
        "total_alerts": len(result.alerts),
        "critical": sum(1 for a in result.alerts if a.severity.value == "critical"),
        "high": sum(1 for a in result.alerts if a.severity.value == "high"),
        "medium": sum(1 for a in result.alerts if a.severity.value == "medium"),
        "low": sum(1 for a in result.alerts if a.severity.value == "low"),
        "info": sum(1 for a in result.alerts if a.severity.value == "info"),
    }

    source_names = [Path(f).name for f in result.source_files] or ["(no files)"]

    return {
        "scan_time": now,
        "duration": _duration_str(result.duration_seconds),
        "events_processed": result.events_processed,
        "source_files": source_names,
        "alerts": alerts_data,
        "incidents": incidents_data,
        "summary": summary,
        "version": _VERSION,
    }


def generate_html(result: ScanResult, output_path: str | Path) -> Path:
    """Render scan result to HTML report. Returns path to written file."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("template.html")
    html = template.render(**_build_context(result))
    output.write_text(html, encoding="utf-8")
    return output


def generate_pdf(result: ScanResult, output_path: str | Path) -> Path:
    """Render scan result to PDF via WeasyPrint. Falls back to HTML if unavailable."""
    output = Path(output_path)

    try:
        import weasyprint  # type: ignore
    except ImportError:
        html_path = output.with_suffix(".html")
        generate_html(result, html_path)
        return html_path

    html_path = output.with_suffix(".html")
    generate_html(result, html_path)
    weasyprint.HTML(filename=str(html_path)).write_pdf(str(output))
    return output
