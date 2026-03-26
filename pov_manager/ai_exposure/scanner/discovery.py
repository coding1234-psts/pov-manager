"""
discovery.py — Asset discovery for a target domain.

Three passive, non-invasive sources:
  1. Certificate Transparency via crt.sh
  2. DNS probe of high-value common subdomains
  3. Homepage link extraction

All candidates are resolved via DNS — only live hosts are returned.
"""

import socket
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table

console = Console()

# High-value subdomain names to probe via DNS.
# Curated for AI/tech exposure surface — not a brute-force wordlist.
_PROBE_NAMES = [
    "www", "api", "app", "chat", "ai", "ml", "bot", "copilot", "assistant",
    "admin", "dashboard", "portal", "docs", "dev", "staging", "test", "beta",
    "cdn", "assets", "static", "data", "ingest", "inference", "models",
    "llm", "search", "embed", "vector", "proxy", "gateway",
]


def _strip_domain(target: str) -> str:
    """Return bare hostname from a URL or domain string."""
    target = target.strip().lower()
    if "://" in target:
        target = urlparse(target).netloc
    return target.rstrip("/")


def _resolve(hostname: str) -> str | None:
    """Return IPv4 address for hostname, or None if it doesn't resolve."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_INET)
        return results[0][4][0]
    except Exception:
        return None


def _query_crt_sh(domain: str) -> list[str]:
    """
    Query crt.sh certificate transparency logs for all subdomains.
    Returns a deduplicated list of hostnames.
    """
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=20,
            headers={"User-Agent": "AIExposureAnalyzer/1.0 (Security Assessment Scanner; non-invasive)"},
        )
        if resp.status_code != 200:
            console.print(f"  [yellow]crt.sh returned HTTP {resp.status_code}[/yellow]")
            return []

        subdomains = set()
        for entry in resp.json():
            for line in entry.get("name_value", "").splitlines():
                line = line.strip().lower()
                # Strip wildcard prefix
                if line.startswith("*."):
                    line = line[2:]
                if line.endswith(f".{domain}") or line == domain:
                    subdomains.add(line)
        return sorted(subdomains)

    except Exception as e:
        console.print(f"  [yellow]crt.sh query failed: {e}[/yellow]")
        return []


def _extract_homepage_subdomains(domain: str) -> tuple[list[str], str | None]:
    """
    Fetch the root homepage and extract any subdomain references.
    Returns (list of subdomains, homepage_html or None).
    """
    homepage_html = None
    subdomains = set()
    try:
        resp = requests.get(
            f"https://{domain}",
            timeout=10,
            headers={"User-Agent": "AIExposureAnalyzer/1.0 (Security Assessment Scanner; non-invasive)"},
            allow_redirects=True,
        )
        if resp.status_code == 200:
            homepage_html = resp.text
            soup = BeautifulSoup(homepage_html, "html.parser")
            for tag in soup.find_all(["a", "script", "link", "form", "img", "iframe"]):
                for attr in ["href", "src", "action", "data-src"]:
                    val = tag.get(attr) or ""
                    if not val:
                        continue
                    try:
                        host = urlparse(val).netloc.lower()
                        if host and host != domain and host.endswith(f".{domain}"):
                            subdomains.add(host)
                    except Exception:
                        pass
    except Exception as e:
        console.print(f"  [yellow]Homepage fetch failed: {e}[/yellow]")

    return sorted(subdomains), homepage_html


def discover(domain: str) -> list[dict]:
    """
    Discover live assets for the given domain using three passive sources.

    Returns a sorted list of asset dicts:
        hostname, url, ip, source, live
    """
    domain = _strip_domain(domain)

    console.rule(f"[bold cyan]Asset Discovery — {domain}[/bold cyan]")

    # candidates: hostname -> source (first-seen source wins)
    candidates: dict[str, str] = {}

    # Always include the root domain
    candidates[domain] = "root"

    # ── Source 1: Certificate Transparency ───────────────────────────────────
    console.print("[bold]Source 1/3:[/bold] Certificate Transparency (crt.sh)...")
    crt_hosts = _query_crt_sh(domain)
    added = 0
    for h in crt_hosts:
        if h not in candidates:
            candidates[h] = "crt.sh"
            added += 1
    console.print(f"  [green]✓[/green] {added} new candidate(s) from {len(crt_hosts)} cert entries")

    # ── Source 2: Common subdomain DNS probe ──────────────────────────────────
    console.print("[bold]Source 2/3:[/bold] DNS probe (common subdomains)...")
    dns_added = 0
    for name in _PROBE_NAMES:
        host = f"{name}.{domain}"
        if host not in candidates:
            candidates[host] = "dns_probe"
            dns_added += 1
    console.print(f"  [green]✓[/green] {dns_added} candidate(s) added for DNS resolution")

    # ── Source 3: Homepage link extraction ────────────────────────────────────
    console.print("[bold]Source 3/3:[/bold] Homepage link extraction...")
    link_hosts, _ = _extract_homepage_subdomains(domain)
    link_added = 0
    for h in link_hosts:
        if h not in candidates:
            candidates[h] = "homepage_link"
            link_added += 1
    console.print(f"  [green]✓[/green] {link_added} subdomain reference(s) found in homepage")

    # ── DNS resolution filter ─────────────────────────────────────────────────
    console.print(f"\n[bold]Resolving {len(candidates)} candidate(s) via DNS...[/bold]")

    assets = []
    for hostname, source in candidates.items():
        ip = _resolve(hostname)
        if ip:
            assets.append({
                "hostname": hostname,
                "url": f"https://{hostname}",
                "ip": ip,
                "source": source,
                "live": True,
            })

    # Sort: root first, then homepage links, then crt.sh, then dns probes
    _order = {"root": 0, "homepage_link": 1, "crt.sh": 2, "dns_probe": 3}
    assets.sort(key=lambda a: (_order.get(a["source"], 9), a["hostname"]))

    console.rule(f"[green]{len(assets)} live asset(s) discovered[/green]")
    return assets


def print_asset_table(assets: list[dict]) -> None:
    """Render the discovered assets as a rich table."""
    table = Table(title=f"Discovered Assets ({len(assets)})", show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Hostname", style="bold")
    table.add_column("IP Address")
    table.add_column("Source")

    source_style = {
        "root": "cyan",
        "homepage_link": "green",
        "crt.sh": "yellow",
        "dns_probe": "dim",
    }
    for i, asset in enumerate(assets, 1):
        style = source_style.get(asset["source"], "")
        table.add_row(
            str(i),
            asset["hostname"],
            asset["ip"],
            f"[{style}]{asset['source']}[/{style}]" if style else asset["source"],
        )
    console.print(table)
