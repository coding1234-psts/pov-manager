import time
import re
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
import yaml
import os

from rich.console import Console

console = Console()

_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config", "patterns.yaml"
)


def _load_config():
    with open(_CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)


def collect(target: str) -> dict:
    """
    Collect publicly accessible assets from the target domain.

    Returns a dict with keys:
        target, base_domain, homepage_html, js_bundles,
        ai_endpoints, sensitive_files, robots_txt, requests_log
    """
    config = _load_config()
    scanner = config["scanner"]

    # Normalize target URL
    if not re.match(r"https?://", target):
        target = "https://" + target
    target = target.rstrip("/")

    parsed_base = urlparse(target)
    base_domain = parsed_base.netloc

    user_agent = scanner["user_agent"]
    timeout = scanner["request_timeout_seconds"]
    delay = scanner["delay_between_requests_seconds"]
    max_js_bytes = int(scanner["max_js_bundle_size_mb"] * 1024 * 1024)

    result = {
        "target": target,
        "base_domain": base_domain,
        "homepage_html": None,
        "js_bundles": [],
        "ai_endpoints": [],
        "sensitive_files": [],
        "robots_txt": None,
        "requests_log": [],
    }

    request_count = [0]
    MAX_REQUESTS = 100

    def _log(url, status_code, error=None, content_type=""):
        result["requests_log"].append(
            {
                "url": url,
                "status_code": status_code,
                "content_type": content_type,
                "error": error,
            }
        )

    def _get(url, allow_redirects=True, method="GET"):
        """Safe GET or HEAD request with redirect control and request cap."""
        if request_count[0] >= MAX_REQUESTS:
            console.print(
                f"[yellow]⚠ Request cap ({MAX_REQUESTS}) reached, skipping: {url}[/yellow]"
            )
            return None

        request_count[0] += 1
        try:
            if method == "HEAD":
                resp = requests.head(
                    url,
                    timeout=timeout,
                    headers={"User-Agent": user_agent},
                    allow_redirects=False,
                )
            else:
                resp = requests.get(
                    url,
                    timeout=timeout,
                    headers={"User-Agent": user_agent},
                    allow_redirects=False,
                )

            _log(
                url,
                resp.status_code,
                content_type=resp.headers.get("Content-Type", ""),
            )

            # Manually handle same-domain redirects only
            if allow_redirects and resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if location:
                    redirect_url = urljoin(url, location)
                    redirect_parsed = urlparse(redirect_url)
                    if redirect_parsed.netloc in ("", base_domain):
                        time.sleep(delay)
                        return _get(redirect_url, allow_redirects=allow_redirects, method=method)
                    else:
                        console.print(
                            f"  [dim]Cross-domain redirect blocked: {url} → {redirect_url}[/dim]"
                        )
            time.sleep(delay)
            return resp

        except Exception as e:
            _log(url, None, error=str(e))
            console.print(f"  [red]✗ {url} — {e}[/red]")
            time.sleep(delay)
            return None

    # ── Step 1: Homepage ──────────────────────────────────────────────────────
    console.rule(f"[bold cyan]AI Exposure Analyzer[/bold cyan]")
    console.print(f"\n[bold]Target:[/bold] {target}\n")
    console.print("[bold]Step 1/5:[/bold] Fetching homepage...")

    resp = _get(target)
    if resp and resp.status_code == 200:
        result["homepage_html"] = resp.text
        console.print(f"  [green]✓[/green] {len(resp.text):,} chars")
    elif resp:
        console.print(f"  [yellow]HTTP {resp.status_code}[/yellow]")

    # ── Step 2: JS bundles ────────────────────────────────────────────────────
    console.print("[bold]Step 2/5:[/bold] Fetching JS bundles...")

    if result["homepage_html"]:
        soup = BeautifulSoup(result["homepage_html"], "html.parser")
        script_tags = soup.find_all("script", src=True)
        console.print(f"  Found {len(script_tags)} script tag(s)")

        for tag in script_tags:
            src = tag.get("src", "")
            js_url = urljoin(target, src)
            js_parsed = urlparse(js_url)

            # Skip external scripts
            if js_parsed.netloc and js_parsed.netloc != base_domain:
                console.print(f"  [dim]Skip external: {js_url}[/dim]")
                continue

            # Check size with HEAD first
            skip = False
            head = _get(js_url, method="HEAD")
            if head:
                cl_str = head.headers.get("Content-Length", "")
                if cl_str and cl_str.isdigit() and int(cl_str) > max_js_bytes:
                    console.print(
                        f"  [yellow]⚠ Skip large JS "
                        f"({int(cl_str) // 1024 // 1024}MB): {js_url}[/yellow]"
                    )
                    skip = True

            if skip:
                continue

            console.print(f"  [dim]→ Fetching: {js_url}[/dim]")
            js_resp = _get(js_url)
            if js_resp and js_resp.status_code == 200:
                content = js_resp.text
                if len(content) > max_js_bytes:
                    console.print(f"  [yellow]⚠ Skip large JS (content): {js_url}[/yellow]")
                    continue
                result["js_bundles"].append(
                    {"url": js_url, "content": content, "size": len(content)}
                )
                console.print(f"  [green]✓[/green] {js_url} ({len(content):,} chars)")

    # ── Step 3: AI endpoint paths ─────────────────────────────────────────────
    ai_paths = config.get("ai_endpoint_paths", [])
    console.print(f"[bold]Step 3/5:[/bold] Probing {len(ai_paths)} AI endpoint paths...")

    for path in ai_paths:
        url = target + path
        resp = _get(url, allow_redirects=False)
        if resp is not None:
            body = resp.text or ""
            result["ai_endpoints"].append(
                {
                    "url": url,
                    "path": path,
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "body_preview": body[:500],
                }
            )
            if resp.status_code == 200:
                console.print(f"  [bold green]✓ FOUND: {url} (200 OK)[/bold green]")

    # ── Step 4: Sensitive paths ───────────────────────────────────────────────
    sensitive_paths = config.get("sensitive_paths", [])
    console.print(
        f"[bold]Step 4/5:[/bold] Probing {len(sensitive_paths)} sensitive paths..."
    )

    for path in sensitive_paths:
        url = target + path
        resp = _get(url, allow_redirects=False)
        if resp is not None:
            body = resp.text or ""
            result["sensitive_files"].append(
                {
                    "url": url,
                    "path": path,
                    "status_code": resp.status_code,
                    "has_content": bool(body.strip()),
                    "body_preview": body[:500],
                }
            )
            if resp.status_code == 200:
                console.print(
                    f"  [bold yellow]⚠ FOUND: {url} (200 OK)[/bold yellow]"
                )

    # ── Step 5: robots.txt ────────────────────────────────────────────────────
    console.print("[bold]Step 5/5:[/bold] Fetching /robots.txt...")
    robots_url = target + "/robots.txt"
    resp = _get(robots_url)
    if resp and resp.status_code == 200:
        result["robots_txt"] = resp.text
        console.print(
            f"  [green]✓[/green] robots.txt ({len(resp.text):,} chars)"
        )

    console.rule(
        f"[green]Collection complete — {request_count[0]} requests made[/green]"
    )
    return result
