"""
lyseis.reporter
~~~~~~~~~~~~~~~
Output dispatcher. Supports:
  - Rich terminal table (default, colored, grouped by severity)
  - JSON to stdout or file (--json / --output)
  - No-color mode for file redirection (--no-color)

Stdout carries data. Stderr carries status messages (see utils.py).
"""

from __future__ import annotations

import json
import sys

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import Finding, ScanResult, Severity


# ------------------------------------------------------------------ #
# Severity metadata
# ------------------------------------------------------------------ #

_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "yellow",
    Severity.INFO:     "cyan",
}

_ICONS: dict[Severity, str] = {
    Severity.CRITICAL: "💀",
    Severity.HIGH:     "🔴",
    Severity.MEDIUM:   "🟡",
    Severity.INFO:     "🔵",
}

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH:     1,
    Severity.MEDIUM:   2,
    Severity.INFO:     3,
}


# ------------------------------------------------------------------ #
# Terminal reporter
# ------------------------------------------------------------------ #

def _build_findings_table(findings: list[Finding]) -> Table:
    """Build a rich Table of findings sorted by severity."""
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on grey23",
        title=f"[bold white] Lyseis — {len(findings)} Finding(s) [/bold white]",
        expand=True,
        padding=(0, 1),
    )

    table.add_column("SEV",    style="bold",    width=4,  no_wrap=True)
    table.add_column("TYPE",   style="bold",    min_width=22)
    table.add_column("VALUE",                  max_width=60)
    table.add_column("SOURCE",  style="dim",    max_width=36)
    table.add_column("LINE",   style="dim",    width=6,  justify="right")

    sorted_findings = sorted(findings, key=lambda f: _SEVERITY_ORDER[f.severity])

    for f in sorted_findings:
        color = _COLORS[f.severity]
        icon  = _ICONS[f.severity]
        # Shorten source URL to last two path segments for readability
        parts = f.source_url.rstrip("/").split("/")
        source_display = "/".join(parts[-2:]) if len(parts) >= 2 else f.source_url
        source_display = source_display[:36]

        table.add_row(
            f"[{color}]{icon}[/{color}]",
            f"[{color}]{f.type}[/{color}]",
            Text(f.value[:80], no_wrap=False, overflow="fold"),
            source_display,
            str(f.line_number) if f.line_number else "-",
        )

    return table


def _summary_panel(result: ScanResult) -> Panel:
    counts = result.counts_by_severity()
    lines = [
        f"  [dim]Target:[/dim]       [white]{result.target}[/white]",
        f"  [dim]JS Sources:[/dim]   [green]{len(result.js_sources)}[/green]",
        f"  [dim]Findings:[/dim]     "
        f"[bold red]💀 {counts[Severity.CRITICAL]} CRITICAL[/bold red]  "
        f"[red]🔴 {counts[Severity.HIGH]} HIGH[/red]  "
        f"[yellow]🟡 {counts[Severity.MEDIUM]} MEDIUM[/yellow]  "
        f"[cyan]🔵 {counts[Severity.INFO]} INFO[/cyan]",
    ]
    return Panel(
        "\n".join(lines),
        title="[bold white] Scan Summary [/bold white]",
        border_style="bright_black",
        expand=False,
    )


def report_terminal(result: ScanResult, no_color: bool = False) -> None:
    console = Console(highlight=False, no_color=no_color)

    if not result.findings:
        console.print("\n[bold green]  ✅ No findings detected.[/bold green]\n")
        console.print(_summary_panel(result))
        return

    console.print()
    console.print(_build_findings_table(result.sorted_findings()))
    console.print()
    console.print(_summary_panel(result))
    console.print()


# ------------------------------------------------------------------ #
# JSON reporter
# ------------------------------------------------------------------ #

def _result_to_dict(result: ScanResult) -> dict:
    counts = result.counts_by_severity()
    return {
        "meta": {
            "tool":    "Lyseis",
            "version": "0.1.0",
            "target":  result.target,
        },
        "stats": {
            "js_sources": len(result.js_sources),
            "total":      len(result.findings),
            "critical":   counts[Severity.CRITICAL],
            "high":       counts[Severity.HIGH],
            "medium":     counts[Severity.MEDIUM],
            "info":       counts[Severity.INFO],
        },
        "findings": [
            {
                "type":        f.type,
                "value":       f.value,
                "severity":    f.severity.value,
                "source_url":  f.source_url,
                "source_type": f.source_type.value,
                "line":        f.line_number,
                "context":     f.context,
            }
            for f in result.sorted_findings()
        ],
        "js_sources": [
            {"url": s.url, "type": s.source_type.value}
            for s in result.js_sources
        ],
    }


def report_json(result: ScanResult, output_path: str | None = None) -> None:
    payload = json.dumps(_result_to_dict(result), indent=2, ensure_ascii=False)
    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(payload)
        except OSError as exc:
            print(f"[ERROR] Could not write to {output_path}: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        print(payload)


# ------------------------------------------------------------------ #
# Dispatcher
# ------------------------------------------------------------------ #

def dispatch(
    result: ScanResult,
    json_output: bool,
    output_path: str | None,
    no_color: bool,
) -> None:
    """Route output to the correct reporter based on CLI flags."""
    if json_output:
        report_json(result, output_path)
    else:
        report_terminal(result, no_color=no_color)
        if output_path:
            # Also save JSON to file when --output is given in terminal mode
            report_json(result, output_path)
