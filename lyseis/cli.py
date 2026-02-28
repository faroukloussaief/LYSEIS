#!/usr/bin/env python3
"""
lyseis.cli
~~~~~~~~~~
Entry point. Handles argument parsing, banner rendering, pipeline
orchestration (crawl → analyze → report), and clean Unix exit codes.

stdout  → findings data (table / JSON)
stderr  → status messages and errors
"""

from __future__ import annotations

import argparse
import sys
from urllib.parse import urlparse

from rich.console import Console

from .analyzer.engine import run
from .config import Config
from .crawler import crawl
from .models import ScanResult
from .reporter import dispatch
from .utils import get_logger

# ------------------------------------------------------------------ #
# Banner assets
# ------------------------------------------------------------------ #

_DOG_ART = r"""
         / \__
        (  ^-^)    sniff sniff...
        /|  🔍|\
       (_|_/\_|_)
"""

_LOGO = r"""
 ██╗  ██╗   ██╗███████╗███████╗██╗███████╗
 ██║  ╚██╗ ██╔╝██╔════╝██╔════╝██║██╔════╝
 ██║   ╚████╔╝ ███████╗█████╗  ██║███████╗
 ██║    ╚██╔╝  ╚════██║██╔══╝  ██║╚════██║
 ███████╗██║   ███████║███████╗██║███████║
 ╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝╚══════╝
"""

_TAGLINE = "  JavaScript Reconnaissance Tool  •  v0.1"
_LEGAL   = "  ⚠  For authorized security testing and educational purposes only."


def _print_banner(console: Console) -> None:
    console.print(_DOG_ART,  style="bold green",  highlight=False)
    console.print(_LOGO,     style="bold green",  highlight=False)
    console.print(_TAGLINE,  style="dim white",   highlight=False)
    console.print()
    console.print(f"[bold yellow]{_LEGAL}[/bold yellow]")
    console.print()


# ------------------------------------------------------------------ #
# URL validation
# ------------------------------------------------------------------ #

def _validate_url(raw: str) -> str:
    """Basic sanity-check on the target URL. Exits on failure."""
    try:
        parsed = urlparse(raw)
    except Exception as exc:
        _die(f"Malformed URL: {exc}")

    if parsed.scheme not in ("http", "https"):
        _die(
            f"Unsupported scheme '{parsed.scheme}'. "
            "Lyseis requires http:// or https://"
        )

    if not parsed.netloc:
        _die("URL has no host component.")

    return raw


def _die(message: str, code: int = 1) -> None:
    print(f"[!] {message}", file=sys.stderr)
    sys.exit(code)


# ------------------------------------------------------------------ #
# Argument parser
# ------------------------------------------------------------------ #

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lyseis",
        description="Lyseis — JavaScript Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Bot bypass tiers (escalate as needed):\n"
            "  Tier 1 (default)       — browser headers + auto-cloudscraper on block\n"
            "  Tier 2 --stealth       — force cloudscraper (Cloudflare JS challenge)\n"
            "  Tier 3 --browser       — Playwright Chromium (Cloudflare Turnstile)\n"
            "  Tier 3 --flaresolverr  — FlareSolverr service (strongest bypass)\n"
            "\nExamples:\n"
            "  lyseis -u https://target.com\n"
            "  lyseis -u https://target.com --stealth\n"
            "  lyseis -u https://target.com --browser\n"
            "  lyseis -u https://target.com --flaresolverr http://localhost:8191\n"
            "  lyseis -u https://target.com --stealth --proxy socks5://127.0.0.1:9050\n"
            "  lyseis -u https://target.com --json --output report.json\n"
        ),
    )

    parser.add_argument(
        "-u", "--url",
        required=True,
        metavar="URL",
        help="Target URL to analyse (required)",
    )
    parser.add_argument(
        "--allow-external",
        action="store_true",
        default=False,
        help="Also fetch and analyse JS from cross-origin domains",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        default=False,
        help="Output findings as JSON to stdout",
    )
    parser.add_argument(
        "--output",
        metavar="PATH",
        default=None,
        help="Write JSON report to a file",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        metavar="SEC",
        help="Delay between HTTP requests in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SEC",
        help="HTTP request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--user-agent",
        metavar="UA",
        default=None,
        help="Override the default User-Agent string",
    )
    parser.add_argument(
        "--stealth",
        action="store_true",
        default=False,
        help=(
            "Enable stealth mode: use cloudscraper to bypass Cloudflare JS challenges "
            "and send full browser-like headers. Auto-activates on bot-block detection."
        ),
    )
    parser.add_argument(
        "--proxy",
        metavar="URL",
        default=None,
        help="Route all requests through a proxy (e.g. socks5://127.0.0.1:9050 or http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--browser",
        action="store_true",
        default=False,
        help=(
            "Use Playwright headless Chromium to bypass Cloudflare Turnstile and "
            "JS-rendered challenges. Requires: pip install playwright playwright-stealth "
            "&& playwright install chromium"
        ),
    )
    parser.add_argument(
        "--flaresolverr",
        metavar="URL",
        default=None,
        dest="flaresolverr_url",
        help=(
            "Delegate page fetch to a FlareSolverr instance (strongest bypass). "
            "Example: --flaresolverr http://localhost:8191"
        ),
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI colour output",
    )
    parser.add_argument(
        "--silent",
        action="store_true",
        default=False,
        help="Suppress banner and progress messages (findings still emitted)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose debug logging on stderr",
    )

    return parser


# ------------------------------------------------------------------ #
# Status helpers (go to stderr so they don't contaminate JSON stdout)
# ------------------------------------------------------------------ #

def _status(err_console: Console, msg: str, silent: bool = False) -> None:
    if not silent:
        err_console.print(msg, highlight=False)


# ------------------------------------------------------------------ #
# Main
# ------------------------------------------------------------------ #

def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    # Two consoles:
    #   out_console → stdout (findings table / banner)
    #   err_console → stderr (progress / warnings)
    out_console = Console(
        highlight=False,
        no_color=args.no_color,
        file=sys.stdout,
    )
    err_console = Console(
        highlight=False,
        no_color=args.no_color,
        file=sys.stderr,
    )

    # Banner — only when NOT in json/silent mode
    if not args.silent and not args.json_output:
        _print_banner(out_console)

    # Validate URL
    url = _validate_url(args.url.strip())

    # Build config
    config = Config(
        url=url,
        allow_external=args.allow_external,
        json_output=args.json_output,
        output_path=args.output,
        delay=args.delay,
        timeout=args.timeout,
        user_agent=args.user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
        stealth_mode=args.stealth,
        browser_mode=args.browser,
        flaresolverr_url=args.flaresolverr_url,
        proxy=args.proxy,
        no_color=args.no_color,
        silent=args.silent,
        verbose=args.verbose,
    )

    logger = get_logger("lyseis", verbose=config.verbose)

    # ---------------------------------------------------------- #
    # Phase 1 — Crawl
    # ---------------------------------------------------------- #
    _status(err_console, f"[bold cyan]  [*] Target  :[/]  {url}", args.silent)
    if config.flaresolverr_url:
        _status(err_console, f"[bold cyan]  [*] Mode    :[/]  [red]FLARESOLVERR[/red] → {config.flaresolverr_url}", args.silent)
    elif config.browser_mode:
        _status(err_console, "[bold cyan]  [*] Mode    :[/]  [magenta]BROWSER[/magenta] (Playwright headless Chromium)", args.silent)
    elif config.stealth_mode:
        _status(err_console, "[bold cyan]  [*] Mode    :[/]  [yellow]STEALTH[/yellow] (cloudscraper)", args.silent)
    if config.proxy:
        _status(err_console, f"[bold cyan]  [*] Proxy   :[/]  {config.proxy}", args.silent)
    _status(err_console, "[bold cyan]  [*] Crawling for JavaScript sources...[/]", args.silent)

    js_sources = crawl(config)

    if not js_sources:
        _status(
            err_console,
            "[yellow]  [!] No JavaScript sources discovered. Exiting.[/yellow]",
            args.silent,
        )
        sys.exit(0)

    _status(
        err_console,
        f"[bold cyan]  [*] Found [green]{len(js_sources)}[/green] JS source(s).[/]",
        args.silent,
    )

    # ---------------------------------------------------------- #
    # Phase 2 — Analyse
    # ---------------------------------------------------------- #
    _status(err_console, "[bold cyan]  [*] Running analysis engines...[/]", args.silent)

    raw_findings = run(js_sources, config)

    # ---------------------------------------------------------- #
    # Phase 3 — Aggregate & deduplicate
    # ---------------------------------------------------------- #
    result = ScanResult(
        target=url,
        js_sources=js_sources,
        findings=raw_findings,
    )
    result.deduplicate()

    _status(
        err_console,
        f"[bold cyan]  [*] Analysis complete — "
        f"[bold white]{len(result.findings)}[/] unique finding(s).[/]",
        args.silent,
    )
    _status(err_console, "", args.silent)  # blank line before output

    # ---------------------------------------------------------- #
    # Phase 4 — Report
    # ---------------------------------------------------------- #
    dispatch(
        result=result,
        json_output=config.json_output,
        output_path=config.output_path,
        no_color=config.no_color,
    )

    if config.output_path and not args.silent:
        _status(
            err_console,
            f"[dim]  [✓] Report saved to: {config.output_path}[/dim]",
            args.silent,
        )

    # Exit with non-zero code when high-severity findings are present
    counts = result.counts_by_severity()
    from .models import Severity
    if counts[Severity.CRITICAL] > 0 or counts[Severity.HIGH] > 0:
        sys.exit(2)  # 2 = findings of concern (scriptable)
    sys.exit(0)


if __name__ == "__main__":
    main()
