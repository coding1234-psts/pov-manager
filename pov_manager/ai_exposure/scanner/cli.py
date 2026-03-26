"""
cli.py — Command-line interface for the AI Exposure Analyzer.

Flow:
  1. Discover all live assets for the target domain
  2. Display the asset table and ask for confirmation
  3. Scan each confirmed asset (collect → secrets → analyze → score)
  4. Write a combined JSON findings file and HTML report
"""

import ipaddress
import json
import os
import socket
import sys
from datetime import datetime

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

from .discovery import discover, print_asset_table
from .collector import collect
from .secrets import scan as scan_secrets
from .analyzer import analyze
from .scorer import score, combined_score
from .reporter import generate_combined_report

console = Console()

DEFAULT_OUTPUT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output"
)


def _parse_selection(raw: str, total: int) -> list[int] | None:
    """
    Parse a selection string like "1,3,5" or "1-3,5" into a list of 0-based indices.
    Returns None if the input means "all".
    """
    raw = raw.strip().lower()
    if raw in ("", "y", "yes", "all"):
        return None  # all assets

    indices = set()
    for part in raw.split(","):
        part = part.strip()
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                for i in range(int(a), int(b) + 1):
                    if 1 <= i <= total:
                        indices.add(i - 1)
            except ValueError:
                pass
        else:
            try:
                i = int(part)
                if 1 <= i <= total:
                    indices.add(i - 1)
            except ValueError:
                pass

    return sorted(indices) if indices else None


def _is_ip(host: str) -> bool:
    """Return True if host is a valid IPv4 or IPv6 address (no port)."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_local_or_private(host: str) -> bool:
    """Return True if host is localhost or a private/loopback address."""
    if host.lower() in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


def _parse_target(raw: str) -> tuple:
    """
    Parse a raw target string into (host, url, port).

    Accepts:
      example.com            → host=example.com,  url=https://example.com, port=None
      example.com:8443       → host=example.com,  url=https://example.com:8443, port=8443
      1.2.3.4                → host=1.2.3.4,      url=https://1.2.3.4, port=None
      1.2.3.4:8080           → host=1.2.3.4,      url=http://1.2.3.4:8080, port=8080
      localhost:5001         → host=localhost,     url=http://localhost:5001, port=5001
      https://example.com    → host=example.com,  url=https://example.com, port=None
    """
    explicit_scheme = None

    # Strip explicit scheme
    if "://" in raw:
        from urllib.parse import urlparse
        p = urlparse(raw)
        explicit_scheme = p.scheme
        host = p.hostname or ""
        port = p.port
    elif raw.count(":") == 1 and not raw.startswith("["):
        # host:port  (not an IPv6 address)
        host, port_str = raw.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            host = raw
            port = None
    else:
        # Plain hostname, IP, or IPv6
        host = raw
        port = None

    # Choose scheme: local/private targets default to http, everything else https
    if explicit_scheme:
        scheme = explicit_scheme
    elif _is_local_or_private(host):
        scheme = "http"
    else:
        scheme = "https"

    # Build canonical URL
    if port and not (scheme == "http" and port == 80) and not (scheme == "https" and port == 443):
        url = f"{scheme}://{host}:{port}"
    else:
        url = f"{scheme}://{host}"

    return host, url, port


def _make_direct_asset(host: str, url: str) -> dict:
    """Build a single synthetic asset dict for direct scanning (no discovery)."""
    if _is_ip(host):
        ip = host
    else:
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            ip = "unknown"
    return {"hostname": host, "url": url, "ip": ip, "source": "direct", "live": True}


def _scan_asset(asset: dict) -> dict:
    """Run the full scan pipeline on a single asset. Returns a result dict."""
    url = asset["url"]
    console.rule(f"[bold cyan]Scanning: {asset['hostname']}[/bold cyan]")
    try:
        collector_output = collect(url)
        findings = analyze(collector_output)
        secrets = scan_secrets(collector_output)
        score_result = score(findings, secrets)
        return {
            "asset": asset,
            "collector_output": collector_output,
            "findings": findings,
            "secrets": secrets,
            "score": score_result,
            "error": None,
        }
    except Exception as e:
        console.print(f"[red]✗ Scan failed for {url}: {e}[/red]")
        return {
            "asset": asset,
            "collector_output": {},
            "findings": [],
            "secrets": [],
            "score": {"total_score": 0, "risk_level": "low", "risk_label": "Low",
                      "risk_color": "#2d7a2d", "score_breakdown": [], "finding_count": 0},
            "error": str(e),
        }


@click.command()
@click.argument("target")
@click.option(
    "--output-dir", "-o",
    default=DEFAULT_OUTPUT_DIR,
    show_default=True,
    help="Directory to write JSON findings and HTML report.",
)
@click.option(
    "--no-report", is_flag=True,
    help="Skip HTML report generation.",
)
@click.option(
    "--yes", "-y", is_flag=True,
    help="Skip confirmation prompt and scan all discovered assets.",
)
@click.option(
    "--no-discovery", is_flag=True,
    help="Skip subdomain enumeration and scan TARGET directly (required for IP addresses).",
)
def cli(target: str, output_dir: str, no_report: bool, yes: bool, no_discovery: bool):
    """Discover and scan TARGET for AI-related public exposure.

    TARGET may be a domain name (example.com) or an IP address (1.2.3.4).
    IP addresses automatically skip subdomain discovery.
    """
    host, url, port = _parse_target(target.strip().rstrip("/").lower())

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    safe_name = host.replace(".", "_").replace(":", "_") + (f"_{port}" if port else "")

    target_is_ip = _is_ip(host)
    # Skip discovery if: IP, explicit port, localhost/private, or --no-discovery flag
    skip_discovery = no_discovery or target_is_ip or port is not None or _is_local_or_private(host)

    # ── Phase 1: Discovery (or direct) ───────────────────────────────────────
    console.print()
    if skip_discovery:
        if target_is_ip:
            console.print(f"[yellow]IP address detected — skipping subdomain discovery.[/yellow]")
        elif port is not None:
            console.print(f"[yellow]Port specified ({port}) — scanning {url} directly.[/yellow]")
        elif _is_local_or_private(host):
            console.print(f"[yellow]Local/private target — skipping subdomain discovery.[/yellow]")
        else:
            console.print(f"[yellow]--no-discovery set — scanning {url} directly.[/yellow]")
        assets = [_make_direct_asset(host, url)]
        # No confirmation needed when the user has already named a single target
        targets = assets
        console.print(f"\n[bold green]Scanning 1 target: {url}[/bold green]\n")
    else:
        assets = discover(host)

        if not assets:
            console.print("[red]No live assets found. Exiting.[/red]")
            sys.exit(1)

        console.print()
        print_asset_table(assets)
        console.print()

        # ── Phase 2: Confirmation ─────────────────────────────────────────────
        if yes:
            selected_indices = None  # all
        else:
            console.print(
                f"[bold]Found {len(assets)} live asset(s).[/bold]\n"
                "Enter [bold]Y[/bold] or press Enter to scan all, "
                "or enter asset numbers to scan a subset (e.g. [dim]1,3,5[/dim] or [dim]1-3[/dim]).\n"
                "Enter [bold]N[/bold] or [bold]0[/bold] to cancel."
            )
            raw = Prompt.ask("Scan selection", default="Y")
            if raw.strip().lower() in ("n", "no", "0", "q", "quit", "exit"):
                console.print("[yellow]Scan cancelled.[/yellow]")
                sys.exit(0)
            selected_indices = _parse_selection(raw, len(assets))

        if selected_indices is None:
            targets = assets
            console.print(f"\n[bold green]Scanning all {len(targets)} asset(s)...[/bold green]\n")
        else:
            targets = [assets[i] for i in selected_indices]
            console.print(
                f"\n[bold green]Scanning {len(targets)} selected asset(s):[/bold green] "
                + ", ".join(a["hostname"] for a in targets) + "\n"
            )

    # ── Phase 3: Scan each asset ──────────────────────────────────────────────
    asset_results = []
    for asset in targets:
        result = _scan_asset(asset)
        asset_results.append(result)

    # ── Phase 4: Aggregate and report ─────────────────────────────────────────
    all_scores = [r["score"] for r in asset_results]
    combined = combined_score(all_scores)
    combined["asset_count"] = len(asset_results)

    # Print combined summary
    risk_color_map = {"low": "green", "moderate": "yellow", "high": "red"}
    rc = risk_color_map.get(combined["risk_level"], "white")

    total_findings = sum(len(r["findings"]) for r in asset_results)
    total_secrets = sum(len(r["secrets"]) for r in asset_results)

    console.print(
        Panel(
            f"[bold {rc}]{combined['risk_label']} Risk — Combined Score: {combined['total_score']}[/bold {rc}]\n"
            f"Assets scanned: {len(asset_results)}  |  "
            f"Total findings: {total_findings}  |  "
            f"Credentials detected: {total_secrets}",
            title="[bold]Scan Complete[/bold]",
            border_style=rc,
        )
    )

    # Per-asset summary table
    summary_table = Table(title="Asset Risk Summary", show_lines=True)
    summary_table.add_column("Hostname", style="bold")
    summary_table.add_column("Risk")
    summary_table.add_column("Score", justify="right")
    summary_table.add_column("Findings", justify="right")
    summary_table.add_column("Secrets", justify="right")

    for r in sorted(asset_results, key=lambda x: x["score"]["total_score"], reverse=True):
        rl = r["score"]["risk_level"]
        color = risk_color_map.get(rl, "white")
        summary_table.add_row(
            r["asset"]["hostname"],
            f"[{color}]{r['score']['risk_label']}[/{color}]",
            str(r["score"]["total_score"]),
            str(len(r["findings"])),
            str(len(r["secrets"])),
        )
    console.print(summary_table)

    # ── Phase 5: Write outputs ────────────────────────────────────────────────
    os.makedirs(output_dir, exist_ok=True)

    # JSON findings
    findings_path = os.path.join(output_dir, f"{safe_name}_{ts}_findings.json")
    report_data = {
        "domain": host,
        "scan_time": scan_time,
        "combined_score": combined,
        "assets": [
            {
                "asset": r["asset"],
                "score": r["score"],
                "findings": r["findings"],
                "secrets": r["secrets"],
                "error": r.get("error"),
            }
            for r in asset_results
        ],
    }
    with open(findings_path, "w", encoding="utf-8") as fh:
        json.dump(report_data, fh, indent=2)
    console.print(f"\n[green]✓[/green] JSON findings: {findings_path}")

    # HTML report
    if not no_report:
        html_path = os.path.join(output_dir, f"{safe_name}_{ts}_report.html")
        generate_combined_report(
            domain=host,
            asset_results=asset_results,
            combined=combined,
            output_path=html_path,
            scan_time=scan_time,
        )
        console.print(f"[green]✓[/green] HTML report:  {html_path}")


def main():
    cli()


if __name__ == "__main__":
    main()
