"""
SOC-Lite CLI

Commands:
  soclite analyze   -- run full analysis on one or more log files
  soclite watch     -- monitor a directory for new log files
  soclite rules     -- list loaded Sigma rules
  soclite demo      -- generate and analyze sample logs (no real files needed)

Usage:
  soclite analyze Security.evtx --no-ml
  soclite analyze /var/log/auth.log
  soclite analyze Security.evtx auth.log --output report.json
  soclite analyze Security.evtx --sigma-dir ./my_rules
  soclite rules
  soclite demo
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

load_dotenv()

app = typer.Typer(
    name="soclite",
    help="AI-powered lightweight SIEM — Sigma + ML + Claude.",
    add_completion=False,
)
console = Console()


def _banner() -> None:
    console.print(
        Panel(
            "[bold red]SOC-Lite[/bold red]  [bright_black]v0.1.0 — Sigma + ML + Claude[/bright_black]\n"
            "[bright_black]D-01 — Defensive portfolio project[/bright_black]",
            border_style="bright_black",
            padding=(0, 2),
        )
    )


def _print_results(result) -> None:
    from soclite.types.events import Severity

    # Alerts table
    if result.alerts:
        table = Table(
            title=f"Alerts — {len(result.alerts)} total", show_header=True, header_style="bold"
        )
        table.add_column("Severity", width=10)
        table.add_column("Source", width=8)
        table.add_column("Rule", width=38)
        table.add_column("Host", width=16)
        table.add_column("Time", width=8)

        for alert in result.sorted_alerts()[:30]:
            sev_color = alert.severity.color
            host = alert.events[0].hostname if alert.events else "?"
            ts = alert.timestamp.strftime("%H:%M:%S")
            table.add_row(
                f"[{sev_color}]{alert.severity.value.upper()}[/{sev_color}]",
                alert.rule_source[:7],
                alert.rule_name[:38],
                host[:16],
                ts,
            )
        console.print(table)

    # Incidents
    if result.incidents:
        console.print()
        inc_table = Table(
            title=f"Incidents — {len(result.incidents)} detected",
            show_header=True, header_style="bold"
        )
        inc_table.add_column("ID", width=12)
        inc_table.add_column("Severity", width=10)
        inc_table.add_column("Name", width=42)
        inc_table.add_column("Alerts", width=7, justify="right")
        inc_table.add_column("Hosts")

        for inc in result.incidents:
            sev_color = inc.severity.color
            inc_table.add_row(
                inc.id,
                f"[{sev_color}]{inc.severity.value.upper()}[/{sev_color}]",
                inc.name[:42],
                str(len(inc.alerts)),
                ", ".join(inc.affected_hosts[:2]),
            )
        console.print(inc_table)

        # AI analysis for top incident
        top = result.incidents[0]
        if top.ai_analysis:
            console.print()
            console.print(Panel(
                top.ai_analysis,
                title=f"[purple]AI Analysis — {top.name}[/purple]",
                border_style="purple",
            ))
            if top.recommendations:
                console.print("[bold]Recommendations:[/bold]")
                for rec in top.recommendations:
                    console.print(f"  [cyan]->[/cyan] {rec}")

    # Summary
    stats = result.to_dict()["summary"]
    console.print(
        f"\n[bright_black]"
        f"{result.events_processed} events processed — "
        f"{stats['total_alerts']} alerts — "
        f"{stats['critical']} critical, {stats['high']} high — "
        f"{stats['incidents']} incidents — "
        f"{result.duration_seconds:.1f}s"
        f"[/bright_black]"
    )


@app.command()
def analyze(
    files: list[Path] = typer.Argument(..., help="Log files to analyze (.evtx, auth.log, syslog)"),
    sigma_dir: Optional[Path] = typer.Option(None, "--sigma-dir", help="Custom Sigma rules directory"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip Claude AI analysis"),
    no_ml: bool = typer.Option(False, "--no-ml", help="Skip ML anomaly detection"),
    analyze_alerts: bool = typer.Option(False, "--analyze-alerts", help="Run AI on individual alerts too"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save JSON report"),
    ml_sensitivity: float = typer.Option(0.05, "--ml-sensitivity", help="ML contamination 0.01–0.20"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Analyze log files with Sigma rules, ML anomaly detection, and Claude AI."""
    if not quiet:
        _banner()

    for f in files:
        if not f.exists():
            console.print(f"[red]File not found: {f}[/red]")
            raise typer.Exit(1)

    from soclite.core.pipeline import run_pipeline

    result = asyncio.run(
        run_pipeline(
            files=files,
            sigma_dir=sigma_dir,
            use_ml=not no_ml,
            use_ai=not no_ai,
            analyze_alerts=analyze_alerts,
            ml_contamination=ml_sensitivity,
        )
    )

    if not quiet:
        _print_results(result)

    if output:
        output.write_text(json.dumps(result.to_dict(), indent=2, default=str))
        console.print(f"\n[green]Report saved -> {output}[/green]")


@app.command()
def rules(
    sigma_dir: Optional[Path] = typer.Option(None, "--sigma-dir"),
) -> None:
    """List all loaded Sigma rules."""
    from soclite.core.pipeline import DEFAULT_SIGMA_DIR
    from soclite.detectors.sigma import load_rules

    path = sigma_dir or DEFAULT_SIGMA_DIR
    loaded = load_rules(path)

    if not loaded:
        console.print(f"[yellow]No rules found in {path}[/yellow]")
        console.print("Add Sigma .yml files to sigma_rules/ or use --sigma-dir")
        return

    table = Table(title=f"Sigma rules ({len(loaded)} loaded)", show_header=True)
    table.add_column("Severity", width=10)
    table.add_column("Title", width=45)
    table.add_column("MITRE", width=20)

    for rule in sorted(loaded, key=lambda r: r.severity.weight, reverse=True):
        sev_color = rule.severity.color
        mitre = ", ".join(rule.mitre_techniques[:2])
        table.add_row(
            f"[{sev_color}]{rule.severity.value.upper()}[/{sev_color}]",
            rule.title[:45],
            mitre[:20],
        )
    console.print(table)


@app.command()
def demo(
    no_ai: bool = typer.Option(False, "--no-ai"),
) -> None:
    """
    Generate synthetic logs simulating a brute-force + lateral movement attack,
    then run the full pipeline on them. No external files needed.
    """
    import tempfile
    from datetime import datetime, timezone, timedelta
    from soclite.core.pipeline import run_pipeline

    console.print("[cyan]Generating synthetic attack scenario...[/cyan]")

    # Build a realistic auth.log with brute force + success + lateral movement
    base_time = datetime(2024, 6, 15, 2, 30, 0, tzinfo=timezone.utc)
    lines = []

    def ts(offset_s: int) -> str:
        t = base_time + timedelta(seconds=offset_s)
        return t.strftime("%b %d %H:%M:%S")

    host = "webserver01"
    attacker_ip = "185.220.101.42"
    victim_ip = "10.0.0.15"

    # Phase 1: SSH brute force (20 failures from same IP)
    users = ["admin", "root", "ubuntu", "deploy", "backup", "test", "admin"]
    for i, user in enumerate(users * 3):
        lines.append(f"{ts(i*3)} {host} sshd[1234]: Failed password for {user} from {attacker_ip} port 55{i:03d} ssh2")

    # Phase 2: Successful login after brute force
    lines.append(f"{ts(70)} {host} sshd[1234]: Accepted password for deploy from {attacker_ip} port 55999 ssh2")

    # Phase 3: sudo usage (privilege escalation)
    lines.append(f"{ts(90)} {host} sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")
    lines.append(f"{ts(95)} {host} sudo: deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/chmod +x /tmp/backdoor.sh")

    # Phase 4: Lateral movement attempt
    lines.append(f"{ts(120)} {host} sshd[1234]: Accepted password for root from {victim_ip} port 22")
    lines.append(f"{ts(130)} {host} sshd[1234]: Accepted password for admin from {victim_ip} port 22")

    # Phase 5: Audit log cleared
    lines.append(f"{ts(200)} {host} kernel: audit: type=1307 audit(1718433200.000:123): auid=0 uid=0 ses=1 subj=unconfined msg='unlink /var/log/auth.log'")

    log_content = "\n".join(lines)

    with tempfile.NamedTemporaryFile(mode="w", suffix="-demo-auth.log",
                                     delete=False, encoding="utf-8") as f:
        f.write(log_content)
        tmp_path = f.name

    console.print(f"[bright_black]Generated {len(lines)} log lines -> {tmp_path}[/bright_black]\n")

    result = asyncio.run(
        run_pipeline(
            files=[tmp_path],
            use_ml=True,
            use_ai=not no_ai,
            ml_contamination=0.15,
        )
    )

    _print_results(result)


@app.command()
def watch(
    directory: Path = typer.Argument(..., help="Directory to monitor for new log files."),
    sigma_dir: Optional[Path] = typer.Option(None, "--sigma-dir"),
    no_ai: bool = typer.Option(False, "--no-ai"),
    no_ml: bool = typer.Option(False, "--no-ml"),
    pattern: str = typer.Option("*.log *.evtx", "--pattern", help="Space-separated glob patterns."),
) -> None:
    """Monitor a directory for new log files and analyze them automatically."""
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        console.print("[red]watchdog not installed: pip install watchdog[/red]")
        raise typer.Exit(1)

    _banner()
    console.print(f"[cyan]Watching {directory} for new log files...[/cyan]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    patterns = pattern.split()
    import fnmatch

    class LogHandler(FileSystemEventHandler):
        def on_created(self, event):
            if event.is_directory:
                return
            path = Path(event.src_path)
            if any(fnmatch.fnmatch(path.name, p) for p in patterns):
                console.print(f"[yellow]New file detected: {path.name}[/yellow]")
                from soclite.core.pipeline import run_pipeline
                result = asyncio.run(run_pipeline(
                    files=[path],
                    sigma_dir=sigma_dir,
                    use_ml=not no_ml,
                    use_ai=not no_ai,
                ))
                _print_results(result)

    observer = Observer()
    observer.schedule(LogHandler(), str(directory), recursive=False)
    observer.start()
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    app()
