"""CLI entry point for AI Context Firewall.

Provides the ``acf`` command with sub-commands to start, stop, and query
the proxy server.  Configuration is loaded from :class:`AppConfig`
(environment variables with the ``ACF_`` prefix).
"""

from __future__ import annotations

import json
import os
import platform
import signal
import subprocess
import sys
import time
from collections import Counter
from datetime import date, datetime
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from acf import __version__
from acf.audit.logger import AuditLogger
from acf.config.settings import AppConfig
from acf.detection.engine import DetectionEngine
from acf.models.types import AuditEvent
from acf.proxy.file_filter import FileFilter
from acf.proxy.intercept import InterceptAddon
from acf.proxy.server import ProxyServer
from acf.redaction.redactor import Redactor

_PID_DIR = Path.home() / ".acf"
_PID_FILE = _PID_DIR / "acf.pid"


# ── PID helpers ────────────────────────────────────────────────────────


def _read_pid() -> int | None:
    """Return the stored PID if the process is still alive, else ``None``."""
    if not _PID_FILE.exists():
        return None
    try:
        pid = int(_PID_FILE.read_text().strip())
        os.kill(pid, 0)  # signal 0 = existence check
        return pid
    except (ValueError, ProcessLookupError, PermissionError, OSError):
        _PID_FILE.unlink(missing_ok=True)
        return None


def _write_pid() -> None:
    """Persist the current process PID."""
    _PID_DIR.mkdir(parents=True, exist_ok=True)
    _PID_FILE.write_text(str(os.getpid()))


def _write_pid_for(pid: int) -> None:
    """Persist a specific *pid* (used by daemon mode for the child process)."""
    _PID_DIR.mkdir(parents=True, exist_ok=True)
    _PID_FILE.write_text(str(pid))


def _remove_pid() -> None:
    """Delete the PID file (idempotent)."""
    _PID_FILE.unlink(missing_ok=True)


# ── CLI group ──────────────────────────────────────────────────────────


@click.group()
@click.version_option(version=__version__, prog_name="acf")
def main() -> None:
    """AI Context Firewall — intercept, inspect, and sanitize AI context windows."""


# ── start ──────────────────────────────────────────────────────────────


@main.command()
@click.option(
    "--port",
    type=int,
    default=None,
    help="Port to listen on (overrides ACF_PROXY_PORT).",
)
@click.option(
    "--daemon",
    is_flag=True,
    default=False,
    help="Run the proxy in the background.",
)
def start(port: int | None, daemon: bool) -> None:
    """Start the proxy server."""
    cfg = AppConfig()
    listen_port = port if port is not None else cfg.proxy_port

    existing = _read_pid()
    if existing is not None:
        click.echo(f"Proxy already running (PID {existing}).")
        raise SystemExit(1)

    click.echo(f"Starting ACF proxy on {cfg.proxy_host}:{listen_port}...")

    if daemon:
        # Spawn a detached subprocess running the same command without --daemon.
        log_file = _PID_DIR / "acf-daemon.log"
        _PID_DIR.mkdir(parents=True, exist_ok=True)

        args = [sys.executable, "-m", "acf", "start", "--port", str(listen_port)]

        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]

        with open(log_file, "a", encoding="utf-8") as lf:
            proc = subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=lf,
                stderr=lf,
                creationflags=creationflags,
                start_new_session=os.name != "nt",
            )

        click.echo(f"Proxy started (PID {proc.pid}) in daemon mode.")
        click.echo(f"Logging to: {log_file}")
        return

    # Wire up the real mitmproxy server with the full ACF pipeline.
    log_path = cfg.resolved_log_dir / "audit.jsonl"
    audit_logger = AuditLogger(log_path)
    file_filter = FileFilter()
    engine = DetectionEngine(cfg)
    redactor = Redactor()
    addon = InterceptAddon(file_filter, engine, redactor, audit_logger)
    server = ProxyServer(cfg, addon)
    _write_pid()
    click.echo(f"Proxy started (PID {os.getpid()}).")

    # Start the proxy in a background thread; block the main thread
    # until SIGINT / SIGTERM or the server stops unexpectedly.
    try:
        server.start()
        while server.is_running:
            time.sleep(0.5)
    except KeyboardInterrupt:
        click.echo("")  # newline after ^C
    finally:
        server.stop()
        _remove_pid()


# ── stop ───────────────────────────────────────────────────────────────


@main.command()
def stop() -> None:
    """Stop the proxy server."""
    pid = _read_pid()
    if pid is None:
        click.echo("Proxy is not running.")
        raise SystemExit(1)

    click.echo(f"Stopping ACF proxy (PID {pid})...")
    try:
        if os.name == "nt":
            # Windows: os.kill with SIGTERM does not reliably terminate
            # processes created with CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS.
            # Use taskkill /F to force-terminate the daemon / proxy process.
            subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)],
                capture_output=True,
                check=False,
            )
        else:
            os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    _remove_pid()
    click.echo("Proxy stopped.")


# ── status ─────────────────────────────────────────────────────────────


@main.command()
def status() -> None:
    """Show proxy status (running/stopped, port, PID)."""
    cfg = AppConfig()
    pid = _read_pid()
    if pid is not None:
        click.echo("Status: running")
        click.echo(f"PID:    {pid}")
        click.echo(f"Port:   {cfg.proxy_port}")
        click.echo(f"Host:   {cfg.proxy_host}")
    else:
        click.echo("Status: stopped")


# ── scan ───────────────────────────────────────────────────────────────

_SCAN_SKIP_EXTENSIONS: frozenset[str] = frozenset({
    ".pyc", ".pyo", ".so", ".dll", ".exe", ".bin", ".dat",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".whl",
    ".pdf", ".doc", ".docx",
})

_SCAN_MAX_FILE_BYTES: int = 5 * 1024 * 1024  # 5 MB per-file ceiling


def _iter_scannable_files(path: Path) -> list[Path]:
    """Return a sorted list of files under *path* that are safe to scan."""
    if path.is_file():
        return [path]
    results: list[Path] = []
    for entry in sorted(path.rglob("*")):
        if not entry.is_file():
            continue
        if entry.suffix.lower() in _SCAN_SKIP_EXTENSIONS:
            continue
        if entry.stat().st_size > _SCAN_MAX_FILE_BYTES:
            continue
        results.append(entry)
    return results


@main.command()
@click.argument("target", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--pretty",
    is_flag=True,
    default=False,
    help="Pretty-print the JSON output.",
)
def scan(target: Path, pretty: bool) -> None:
    """Offline scan of a file or directory for secrets.

    Runs the DetectionEngine on each scannable file and emits findings
    as a JSON array to stdout.
    """
    cfg = AppConfig()
    engine = DetectionEngine(cfg)
    files = _iter_scannable_files(target)

    all_findings: list[dict] = []
    for fpath in files:
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError) as exc:
            click.echo(f"warning: skipping {fpath}: {exc}", err=True)
            continue

        findings = engine.scan(text)
        for f in findings:
            record = f.model_dump()
            record["file"] = str(fpath)
            all_findings.append(record)

    indent = 2 if pretty else None
    click.echo(json.dumps(all_findings, indent=indent))


# ── config ─────────────────────────────────────────────────────────────


@main.group()
def config() -> None:
    """Manage ACF configuration."""


@config.command("show")
def config_show() -> None:
    """Display the current configuration."""
    cfg = AppConfig()
    click.echo("ACF Configuration")
    click.echo("=" * 40)
    click.echo(f"proxy_host:             {cfg.proxy_host}")
    click.echo(f"proxy_port:             {cfg.proxy_port}")
    click.echo(f"log_dir:                {cfg.log_dir}")
    click.echo(f"log_level:              {cfg.log_level}")
    click.echo(f"file_filter_enabled:    {cfg.file_filter_enabled}")
    click.echo(f"entropy_enabled:        {cfg.entropy_enabled}")
    click.echo(f"entropy_base64_threshold: {cfg.entropy_base64_threshold}")
    click.echo(f"entropy_hex_threshold:  {cfg.entropy_hex_threshold}")
    click.echo(f"entropy_min_length:     {cfg.entropy_min_length}")
    click.echo(f"max_body_size_mb:       {cfg.max_body_size_mb}")


# ── audit ──────────────────────────────────────────────────────────────

_AUDIT_LOG_NAME = "audit.jsonl"


def _parse_date(val: str | None) -> date | None:
    """Parse an ISO-8601 date string, or return ``None``."""
    if val is None:
        return None
    try:
        return date.fromisoformat(val)
    except (ValueError, TypeError):
        raise click.BadParameter(f"Invalid date: {val!r}.  Use ISO-8601 format (e.g. 2026-06-01).")


def _load_audit_events(
    log_path: Path,
    since: date | None,
    until: date | None,
) -> list[AuditEvent]:
    """Load and optionally filter audit events from *log_path*.

    Returns events whose timestamp date falls within the
    ``[since, until]`` range (inclusive).  ``None`` bounds are
    treated as open-ended.
    """
    logger = AuditLogger(log_path)
    events = logger.read_events()

    if since is None and until is None:
        return events

    filtered: list[AuditEvent] = []
    for ev in events:
        try:
            ev_date = datetime.fromisoformat(ev.timestamp).date()
        except (ValueError, TypeError):
            # malformed timestamp — skip
            continue
        if since is not None and ev_date < since:
            continue
        if until is not None and ev_date > until:
            continue
        filtered.append(ev)
    return filtered


def _build_summary(events: list[AuditEvent]) -> dict:
    """Aggregate audit events by severity, type, rule (source), and date."""
    total = len(events)
    by_severity: Counter[str] = Counter()
    by_type: Counter[str] = Counter()
    by_source: Counter[str] = Counter()
    by_date: Counter[str] = Counter()
    by_finding_type: Counter[str] = Counter()
    by_block_rule_type: Counter[str] = Counter()

    earliest: str | None = None
    latest: str | None = None

    for ev in events:
        by_severity[ev.severity.value] += 1
        by_type[ev.event_type.value] += 1
        by_source[ev.source] += 1

        # date
        try:
            d = datetime.fromisoformat(ev.timestamp).date().isoformat()
            by_date[d] += 1
            if earliest is None or d < earliest:
                earliest = d
            if latest is None or d > latest:
                latest = d
        except (ValueError, TypeError):
            by_date["unknown"] += 1

        # finding types
        for f in ev.findings:
            by_finding_type[f.type] += 1

        # file-block rule types
        for b in ev.file_blocks:
            by_block_rule_type[b.rule_type.value] += 1

    return {
        "total_events": total,
        "date_range": {"earliest": earliest, "latest": latest},
        "by_severity": dict(by_severity.most_common()),
        "by_event_type": dict(by_type.most_common()),
        "by_source": dict(by_source.most_common()),
        "by_finding_type": dict(by_finding_type.most_common(10)),
        "by_block_rule_type": dict(by_block_rule_type.most_common()),
        "by_date": dict(sorted(by_date.items())),
    }


def _display_summary_table(summary: dict) -> None:
    """Print a rich table of the aggregated summary."""
    console = Console()

    t_total = Table(show_header=False, box=None)
    t_total.add_column("key", style="bold")
    t_total.add_column("value")
    t_total.add_row("Total events", str(summary["total_events"]))
    dr = summary["date_range"]
    if dr["earliest"] and dr["latest"]:
        t_total.add_row("Date range", f"{dr['earliest']} — {dr['latest']}")
    console.print(t_total)
    console.print()

    # Severity breakdown
    t = Table(title="By severity", box=None)
    t.add_column("Severity", style="bold")
    t.add_column("Count")
    for sev, cnt in summary["by_severity"].items():
        t.add_row(sev, str(cnt))
    console.print(t)
    console.print()

    # Event type breakdown
    t = Table(title="By event type", box=None)
    t.add_column("Event type", style="bold")
    t.add_column("Count")
    for typ, cnt in summary["by_event_type"].items():
        t.add_row(typ, str(cnt))
    console.print(t)
    console.print()

    # Source breakdown
    t = Table(title="By source", box=None)
    t.add_column("Source", style="bold")
    t.add_column("Count")
    for src, cnt in summary["by_source"].items():
        t.add_row(src, str(cnt))
    console.print(t)
    console.print()

    # Finding types (top 10)
    if summary["by_finding_type"]:
        t = Table(title="Top finding types", box=None)
        t.add_column("Finding type", style="bold")
        t.add_column("Count")
        for ft, cnt in summary["by_finding_type"].items():
            t.add_row(ft, str(cnt))
        console.print(t)
        console.print()

    # Block rule types
    if summary["by_block_rule_type"]:
        t = Table(title="By block rule type", box=None)
        t.add_column("Block rule type", style="bold")
        t.add_column("Count")
        for rt, cnt in summary["by_block_rule_type"].items():
            t.add_row(rt, str(cnt))
        console.print(t)
        console.print()

    # Daily breakdown
    t = Table(title="Events per day", box=None)
    t.add_column("Date", style="bold")
    t.add_column("Count")
    for d, cnt in summary["by_date"].items():
        t.add_row(d, str(cnt))
    console.print(t)


def _display_events_table(events: list[AuditEvent]) -> None:
    """Print a rich table of raw audit events."""
    console = Console()
    table = Table(title=f"Audit events ({len(events)} total)")
    table.add_column("Timestamp", style="dim")
    table.add_column("Severity")
    table.add_column("Type")
    table.add_column("URL")
    table.add_column("Source")
    table.add_column("Findings")
    table.add_column("Blocks")

    for ev in events:
        findings_str = str(ev.findings_count)
        blocks_str = str(len(ev.file_blocks))
        # Truncate long URLs for display
        url = ev.url if len(ev.url) <= 80 else ev.url[:77] + "..."

        # Color-code severity
        sev_style = {
            "CRITICAL": "red bold",
            "WARNING": "yellow",
            "INFO": "green",
        }.get(ev.severity.value, "")

        table.add_row(
            ev.timestamp,
            f"[{sev_style}]{ev.severity.value}[/]",
            ev.event_type.value,
            url,
            ev.source,
            findings_str,
            blocks_str,
        )

    console.print(table)


def _print_events(events: list[AuditEvent], fmt: str) -> None:
    """Display raw events in the requested format."""
    if fmt == "json":
        data = [ev.model_dump() for ev in events]
        _print_json(data)
    else:
        _display_events_table(events)


def _print_summary(events: list[AuditEvent], fmt: str) -> None:
    """Build and display the aggregated summary in the requested format."""
    summary = _build_summary(events)
    if fmt == "json":
        _print_json(summary)
    else:
        _display_summary_table(summary)


def _print_json(data: object) -> None:
    """Pretty-print *data* as JSON to stdout."""
    click.echo(json.dumps(data, indent=2, default=str))


@main.command()
@click.option(
    "--summary",
    is_flag=True,
    default=False,
    help="Show aggregated summary instead of raw events.",
)
@click.option(
    "--since",
    type=str,
    default=None,
    metavar="DATE",
    help="Include only events at or after this date (ISO-8601).",
)
@click.option(
    "--until",
    type=str,
    default=None,
    metavar="DATE",
    help="Include only events at or before this date (ISO-8601).",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    help="Output format (default: table).",
)
@click.option(
    "--log-path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to the audit JSONL log file (default: <log_dir>/audit.jsonl).",
)
def audit(summary: bool, since: str | None, until: str | None, fmt: str, log_path: Path | None) -> None:
    """Inspect and analyze audit log records.

    Reads the JSONL audit log produced by the proxy and displays raw
    events or an aggregated summary with counts by severity, event type,
    source, and date.
    """
    cfg = AppConfig()
    path = log_path if log_path is not None else cfg.resolved_log_dir / _AUDIT_LOG_NAME

    if not path.exists():
        click.echo(f"Audit log not found: {path}")
        raise SystemExit(1)

    events = _load_audit_events(
        path,
        _parse_date(since),
        _parse_date(until),
    )

    if not events:
        click.echo("No audit events matched the current filters.")
        return

    if summary:
        _print_summary(events, fmt)
    else:
        _print_events(events, fmt)


# ── setup ──────────────────────────────────────────────────────────────

_CA_CERT_DIR = Path.home() / ".acf" / "certs"


def _ca_cert_instructions(ci: bool) -> str:
    """Return platform-specific CA certificate installation instructions."""
    system = platform.system()
    cert_path = _CA_CERT_DIR / "acf-ca-cert.pem"

    lines: list[str] = []
    lines.append("=== ACF CA Certificate Setup ===")
    lines.append("")
    lines.append(f"Certificate will be stored at: {cert_path}")
    lines.append("")

    if ci:
        lines.append("CI mode: add the following to your CI pipeline:")
        lines.append("")
        lines.append("  # Generate / download the CA cert, then trust it:")
        if system == "Linux":
            lines.append(f"  sudo cp {cert_path} /usr/local/share/ca-certificates/acf-ca-cert.crt")
            lines.append("  sudo update-ca-certificates")
        elif system == "Darwin":
            lines.append(f'  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {cert_path}')
        else:  # Windows
            lines.append(f'  certutil -addstore -f "ROOT" {cert_path}')
        lines.append("")
        lines.append("  # Point your AI tool at the ACF proxy:")
        lines.append('  export HTTPS_PROXY="http://127.0.0.1:8080"')
        lines.append('  export HTTP_PROXY="http://127.0.0.1:8080"')
        return "\n".join(lines)

    # Interactive (non-CI) instructions
    lines.append("Step 1: Start the proxy to generate the CA certificate:")
    lines.append("  acf start")
    lines.append("")
    lines.append("Step 2: Trust the CA certificate on your system:")
    lines.append("")

    if system == "Linux":
        lines.append("  # Debian/Ubuntu:")
        lines.append(f"  sudo cp {cert_path} /usr/local/share/ca-certificates/acf-ca-cert.crt")
        lines.append("  sudo update-ca-certificates")
        lines.append("")
        lines.append("  # Fedora/RHEL:")
        lines.append(f"  sudo cp {cert_path} /etc/pki/ca-trust/source/anchors/")
        lines.append("  sudo update-ca-trust")
    elif system == "Darwin":
        lines.append("  # macOS — add to System keychain:")
        lines.append(f'  sudo security add-trusted-cert -d -r trustRoot \\')
        lines.append(f"    -k /Library/Keychains/System.keychain {cert_path}")
        lines.append("")
        lines.append("  # Or drag the .pem file into Keychain Access and set to 'Always Trust'.")
    else:  # Windows
        lines.append("  # Windows — import into Trusted Root store:")
        lines.append(f'  certutil -addstore -f "ROOT" {cert_path}')
        lines.append("")
        lines.append("  # Or: Settings > Privacy & Security > Certificates > Import")

    lines.append("")
    lines.append("Step 3: Configure your AI tool to use the proxy:")
    lines.append("")
    lines.append("  # Environment variables (works with curl, pip, npm, etc.):")
    lines.append('  export HTTPS_PROXY="http://127.0.0.1:8080"')
    lines.append('  export HTTP_PROXY="http://127.0.0.1:8080"')
    lines.append("")
    lines.append("  # For Python requests/httpx:")
    lines.append('  export REQUESTS_CA_BUNDLE="' + str(cert_path) + '"')
    lines.append('  export SSL_CERT_FILE="' + str(cert_path) + '"')
    lines.append("")
    lines.append("  # For Node.js:")
    lines.append('  export NODE_EXTRA_CA_CERTS="' + str(cert_path) + '"')

    return "\n".join(lines)


@main.command()
@click.option(
    "--ci",
    is_flag=True,
    default=False,
    help="Output CI/CD pipeline-friendly instructions (non-interactive).",
)
def setup(ci: bool) -> None:
    """Generate CA certificate trust instructions and proxy configuration."""
    cfg = AppConfig()
    click.echo(_ca_cert_instructions(ci))
    click.echo("")
    click.echo("=== Proxy Configuration ===")
    click.echo(f"Listen address: {cfg.proxy_host}:{cfg.proxy_port}")
    click.echo("")
    click.echo("Set these environment variables to route AI traffic through ACF:")
    click.echo(f'  HTTPS_PROXY="http://{cfg.proxy_host}:{cfg.proxy_port}"')
    click.echo(f'  HTTP_PROXY="http://{cfg.proxy_host}:{cfg.proxy_port}"')
