"""
reporter.py — Generates board-ready HTML reports from scan results.

Provides two entry points:
  generate_combined_report() — multi-asset report with collapsible per-asset sections.
  generate_html_report()     — single-asset report (backward-compatible shim).
"""

from datetime import datetime
import html as _html_escape_module
import yaml
import os

_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config", "patterns.yaml"
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TYPE_LABELS = {
    "ai_fingerprint": "AI SDK",
    "chatbot_fingerprint": "Chatbot",
    "missing_auth": "Missing Auth",
    "missing_rate_limiting": "Rate Limit",
    "open_api_docs": "Open API Docs",
    "source_map_exposed": "Source Map",
    "missing_csrf": "CSRF",
    "open_storage_bucket": "Storage Bucket",
}

_CONF_COLORS = {
    "high":   "#b30000",
    "medium": "#b35c00",
    "low":    "#2d7a2d",
}

_RISK_COLORS = {
    "high":     "#b30000",
    "moderate": "#b35c00",
    "low":      "#2d7a2d",
}

_SOURCE_BADGE_COLORS = {
    "root":          "#0071b3",   # cyan-blue
    "homepage_link": "#2d7a2d",   # green
    "crt.sh":        "#8a6d00",   # amber/yellow (dark enough for white text)
    "dns_probe":     "#555555",   # gray
}

_TYPE_TO_REMEDIATION_KEY = {
    "missing_auth":         "public_ai_endpoint_no_auth",
    "open_api_docs":        "open_api_docs",
    "source_map_exposed":   "source_map_exposed",
    "open_storage_bucket":  "open_storage_bucket",
    "missing_rate_limiting":"missing_rate_limiting",
    "missing_csrf":         "chatbot_no_validation",
    "chatbot_fingerprint":  "chatbot_no_validation",
}


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    with open(_CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# Shared inline CSS
# ---------------------------------------------------------------------------

def _css(combined_risk_color: str) -> str:
    return f"""
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #f5f5f7; color: #1d1d1f; font-size: 15px; line-height: 1.6;
  }}

  /* ---- Header ---- */
  .header {{ background: #1d1d1f; color: #fff; padding: 36px 48px; }}
  .header h1 {{ font-size: 26px; font-weight: 700; margin-bottom: 6px; }}
  .header .meta {{ color: #999; font-size: 13px; line-height: 1.8; }}

  /* ---- Page container ---- */
  .container {{ max-width: 1140px; margin: 32px auto; padding: 0 24px; }}

  /* ---- Score card ---- */
  .score-card {{
    background: #fff; border-radius: 12px; padding: 32px 40px;
    margin-bottom: 28px; display: flex; align-items: center; gap: 40px;
    box-shadow: 0 1px 4px rgba(0,0,0,.08);
  }}
  .score-ring {{
    width: 110px; height: 110px; border-radius: 50%;
    border: 8px solid {combined_risk_color};
    display: flex; flex-direction: column;
    align-items: center; justify-content: center; flex-shrink: 0;
  }}
  .score-ring .num {{ font-size: 32px; font-weight: 800; color: {combined_risk_color}; }}
  .score-ring .lbl {{ font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 1px; }}
  .score-meta h2 {{ font-size: 22px; font-weight: 700; color: {combined_risk_color}; margin-bottom: 8px; }}
  .score-meta p {{ color: #444; max-width: 640px; }}

  /* ---- Generic section card ---- */
  section {{
    background: #fff; border-radius: 12px; padding: 28px 36px;
    margin-bottom: 24px; box-shadow: 0 1px 4px rgba(0,0,0,.08);
  }}
  section h2 {{
    font-size: 17px; font-weight: 700; margin-bottom: 20px;
    border-bottom: 1px solid #e8e8ed; padding-bottom: 12px; color: #1d1d1f;
  }}

  /* ---- Tables ---- */
  table {{ width: 100%; border-collapse: collapse; font-size: 13.5px; }}
  th {{
    text-align: left; padding: 10px 12px; background: #f5f5f7;
    font-weight: 600; color: #555; border-bottom: 1px solid #e0e0e0;
  }}
  td {{
    padding: 10px 12px; border-bottom: 1px solid #f0f0f0; vertical-align: top;
  }}
  tr:last-child td {{ border-bottom: none; }}
  .url {{ font-size: 12px; color: #555; word-break: break-all; }}
  .evidence {{ font-size: 12px; color: #333; max-width: 260px; }}

  /* ---- Badges ---- */
  .badge {{
    display: inline-block; padding: 2px 10px; border-radius: 20px;
    color: #fff; font-size: 11px; font-weight: 700; letter-spacing: .4px;
  }}

  /* ---- Scorecard table ---- */
  .scorecard-table th {{ white-space: nowrap; }}
  .scorecard-table td.score-cell {{
    font-weight: 700; font-size: 15px; text-align: right;
  }}
  .scorecard-table td.findings-cell {{ text-align: right; }}

  /* ---- Asset details/summary ---- */
  details {{
    background: #fff; border-radius: 12px;
    margin-bottom: 16px; box-shadow: 0 1px 4px rgba(0,0,0,.08);
    overflow: hidden;
  }}
  summary {{
    padding: 18px 28px; cursor: pointer; list-style: none;
    display: flex; align-items: center; gap: 14px;
    font-size: 15px; font-weight: 600; color: #1d1d1f;
    user-select: none;
    transition: background 0.15s;
  }}
  summary::-webkit-details-marker {{ display: none; }}
  summary::before {{
    content: '\\25B6';
    font-size: 11px; color: #888;
    flex-shrink: 0;
    transition: transform 0.2s;
  }}
  details[open] > summary::before {{
    content: '\\25BC';
  }}
  summary:hover {{ background: #f5f5f7; }}
  .summary-hostname {{ flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .summary-meta {{ font-size: 12.5px; color: #666; font-weight: 400; white-space: nowrap; }}

  /* ---- Details inner content ---- */
  .details-body {{ padding: 0 28px 28px 28px; }}
  .details-body h3 {{
    font-size: 14px; font-weight: 600; color: #444;
    margin: 24px 0 10px; text-transform: uppercase; letter-spacing: .5px;
  }}
  .details-body h3:first-child {{ margin-top: 4px; }}

  /* ---- Score breakdown ---- */
  .breakdown-table td:first-child {{ color: #444; }}
  .breakdown-total td {{ font-weight: 700; border-top: 2px solid #e0e0e0 !important; }}

  /* ---- Remediation ---- */
  .remediation-card {{
    border-left: 4px solid #0071e3; padding: 16px 20px;
    margin-bottom: 20px; background: #f9f9fb; border-radius: 0 8px 8px 0;
  }}
  .remediation-card:last-child {{ margin-bottom: 0; }}
  .remediation-card h3 {{ font-size: 15px; font-weight: 700; margin-bottom: 10px; }}
  .remediation-card ul {{ margin-left: 20px; }}
  .remediation-card li {{ margin-bottom: 6px; font-size: 13.5px; color: #333; }}
  .rem-priority {{
    display: inline-block; font-size: 11px; font-weight: 700;
    padding: 2px 10px; border-radius: 20px; margin-bottom: 10px; color: #fff;
  }}
  .rem-priority.critical {{ background: #b30000; }}
  .rem-priority.high {{ background: #b35c00; }}
  .rem-priority.medium {{ background: #0071e3; }}

  /* ---- Misc ---- */
  code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
  pre {{
    background: #f5f5f7; padding: 14px; border-radius: 8px; font-size: 12px;
    overflow-x: auto; white-space: pre-wrap; word-break: break-word;
  }}
  .none {{ color: #888; font-style: italic; font-size: 13.5px; }}
  .error-row {{ background: #fff5f5; color: #b30000; font-size: 13px; padding: 14px 0; }}

  footer {{
    text-align: center; color: #999; font-size: 12px; padding: 32px;
  }}
"""


# ---------------------------------------------------------------------------
# Table helpers
# ---------------------------------------------------------------------------

def _esc(text: str) -> str:
    """HTML-escape a string."""
    return _html_escape_module.escape(str(text) if text is not None else "")


def _findings_table(findings: list) -> str:
    if not findings:
        return "<p class='none'>No analysis findings.</p>"

    rows = ""
    for f in findings:
        conf = f.get("confidence", "medium")
        color = _CONF_COLORS.get(conf, "#555")
        type_label = _TYPE_LABELS.get(f.get("type", ""), _esc(f.get("type", "")))
        rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{type_label}</span></td>
          <td><strong>{_esc(f.get('name',''))}</strong></td>
          <td class="url">{_esc(f.get('source_url',''))}</td>
          <td class="evidence">{_esc(f.get('evidence',''))}</td>
        </tr>"""

    return f"""
    <table>
      <thead><tr>
        <th>Type</th><th>Finding</th><th>Source URL</th><th>Evidence</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>"""


def _secrets_table(secrets: list) -> str:
    if not secrets:
        return "<p class='none'>No credentials detected.</p>"

    rows = ""
    for s in secrets:
        conf = s.get("confidence", "medium")
        color = _CONF_COLORS.get(conf, "#555")
        rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{_esc(conf.upper())}</span></td>
          <td><strong>{_esc(s.get('credential_name',''))}</strong></td>
          <td class="url">{_esc(s.get('source_url',''))}</td>
          <td><code>{_esc(s.get('redacted_sample',''))}</code></td>
        </tr>"""

    return f"""
    <table>
      <thead><tr>
        <th>Confidence</th><th>Credential</th><th>Source URL</th><th>Sample (redacted)</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>"""


def _score_breakdown_table(score_result: dict) -> str:
    breakdown = score_result.get("score_breakdown", [])
    total_score = score_result.get("total_score", 0)
    if not breakdown:
        return "<p class='none'>No scored items.</p>"

    rows = "".join(
        f"<tr><td>{_esc(b['item'])}</td>"
        f"<td style='text-align:right;font-weight:bold'>{b['score']}</td></tr>"
        for b in breakdown
    )
    return f"""
    <table class="breakdown-table">
      <thead><tr><th>Item</th><th style="text-align:right">Points</th></tr></thead>
      <tbody>
        {rows}
        <tr class="breakdown-total">
          <td>Total</td>
          <td style="text-align:right">{total_score}</td>
        </tr>
      </tbody>
    </table>"""


# ---------------------------------------------------------------------------
# Remediation helpers
# ---------------------------------------------------------------------------

def _collect_remediation_keys(findings: list, secrets: list) -> list:
    """Return ordered list of deduplicated remediation keys for the given findings/secrets."""
    seen = set()
    keys = []

    for s in secrets:
        name = s.get("credential_name", "").lower()
        ai_providers = ["openai", "anthropic", "hugging", "cohere", "mistral"]
        key = "exposed_ai_key" if any(p in name for p in ai_providers) else "exposed_cloud_key"
        if key not in seen:
            seen.add(key)
            keys.append(key)

    for f in findings:
        ftype = f.get("type", "")
        key = _TYPE_TO_REMEDIATION_KEY.get(ftype)
        if key and key not in seen:
            seen.add(key)
            keys.append(key)

    return keys


def _remediation_cards_html(rem_keys: list, remediation: dict) -> str:
    blocks = ""
    for key in rem_keys:
        if key not in remediation:
            continue
        r = remediation[key]
        priority = r.get("priority", "Medium")
        steps = "".join(f"<li>{_esc(step)}</li>" for step in r.get("steps", []))
        blocks += f"""
        <div class="remediation-card">
          <div class="rem-priority {priority.lower()}">{priority.upper()}</div>
          <h3>{_esc(r.get('title',''))}</h3>
          <ul>{steps}</ul>
        </div>"""
    return blocks or "<p class='none'>No remediation actions required.</p>"


# ---------------------------------------------------------------------------
# Asset scorecard table
# ---------------------------------------------------------------------------

def _asset_scorecard_table(asset_results: list) -> str:
    sorted_results = sorted(
        asset_results,
        key=lambda r: r.get("score", {}).get("total_score", 0),
        reverse=True,
    )

    rows = ""
    for r in sorted_results:
        asset = r.get("asset", {})
        hostname = _esc(asset.get("hostname", "unknown"))
        ip = _esc(asset.get("ip") or "—")
        source = asset.get("source", "")
        source_color = _SOURCE_BADGE_COLORS.get(source, "#555")
        source_label = _esc(source or "unknown")

        score_data = r.get("score", {})
        risk_label = _esc(score_data.get("risk_label", "—"))
        risk_color = score_data.get("risk_color", "#555")
        total_score = score_data.get("total_score", 0)
        finding_count = score_data.get("finding_count", 0)

        error = r.get("error")
        if error:
            rows += f"""
            <tr>
              <td><strong>{hostname}</strong></td>
              <td>{ip}</td>
              <td><span class="badge" style="background:{source_color}">{source_label}</span></td>
              <td colspan="3" class="error-row">Scan failed: {_esc(str(error))}</td>
            </tr>"""
        else:
            rows += f"""
            <tr>
              <td><strong>{hostname}</strong></td>
              <td>{ip}</td>
              <td><span class="badge" style="background:{source_color}">{source_label}</span></td>
              <td><span class="badge" style="background:{risk_color}">{risk_label}</span></td>
              <td class="score-cell">{total_score}</td>
              <td class="findings-cell">{finding_count}</td>
            </tr>"""

    return f"""
    <table class="scorecard-table">
      <thead><tr>
        <th>Hostname</th><th>IP</th><th>Source</th>
        <th>Risk</th>
        <th style="text-align:right">Score</th>
        <th style="text-align:right">Findings</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>"""


# ---------------------------------------------------------------------------
# Per-asset collapsible section
# ---------------------------------------------------------------------------

def _asset_details_section(r: dict, is_first: bool) -> str:
    asset = r.get("asset", {})
    hostname = _esc(asset.get("hostname", "unknown"))
    url = _esc(asset.get("url", ""))

    score_data = r.get("score", {})
    risk_label = _esc(score_data.get("risk_label", "Unknown"))
    risk_color = score_data.get("risk_color", "#555")
    total_score = score_data.get("total_score", 0)
    finding_count = score_data.get("finding_count", 0)

    findings = r.get("findings", [])
    secrets = r.get("secrets", [])
    error = r.get("error")

    open_attr = " open" if is_first else ""

    summary_line = (
        f'<span class="summary-hostname">{hostname}</span>'
        f'<span class="badge" style="background:{risk_color};margin-left:4px">{risk_label}</span>'
        f'<span class="summary-meta">&nbsp;&nbsp;{total_score} pts'
        f'&nbsp;|&nbsp;{finding_count} findings'
        f'&nbsp;|&nbsp;{len(secrets)} secrets</span>'
    )

    if error:
        body = f"<div class='details-body'><p class='error-row'>Scan failed: {_esc(str(error))}</p></div>"
    else:
        url_line = f"<p style='font-size:12px;color:#888;margin-bottom:20px'>{url}</p>" if url else ""
        body = f"""
        <div class="details-body">
          {url_line}
          <h3>Analysis Findings ({len(findings)})</h3>
          {_findings_table(findings)}

          <h3>Credential Exposure ({len(secrets)})</h3>
          {_secrets_table(secrets)}

          <h3>Score Breakdown</h3>
          {_score_breakdown_table(score_data)}
        </div>"""

    return f"""
    <details{open_attr}>
      <summary>{summary_line}</summary>
      {body}
    </details>"""


# ---------------------------------------------------------------------------
# Combined remediation across all assets
# ---------------------------------------------------------------------------

def _combined_remediation_section(asset_results: list, config: dict) -> str:
    remediation = config.get("remediation", {})
    seen_keys = set()
    all_keys = []

    for r in asset_results:
        if r.get("error"):
            continue
        findings = r.get("findings", [])
        secrets = r.get("secrets", [])
        for key in _collect_remediation_keys(findings, secrets):
            if key not in seen_keys:
                seen_keys.add(key)
                all_keys.append(key)

    return _remediation_cards_html(all_keys, remediation)


# ---------------------------------------------------------------------------
# Public API: generate_combined_report
# ---------------------------------------------------------------------------

def generate_combined_report(
    domain: str,
    asset_results: list,
    combined: dict,
    output_path: str,
    scan_time: str,
) -> str:
    """
    Write a combined multi-asset HTML report.

    Parameters
    ----------
    domain        : The root domain being reported on.
    asset_results : List of per-asset result dicts (see module docstring).
    combined      : Output of scorer.combined_score().
    output_path   : Filesystem path to write the HTML file to.
    scan_time     : Human-readable scan timestamp string.

    Returns
    -------
    output_path (str)
    """
    config = _load_config()

    risk_color = combined.get("risk_color", "#555")
    risk_label = combined.get("risk_label", "Unknown")
    total_score = combined.get("total_score", 0)
    finding_count = combined.get("finding_count", 0)
    asset_count = combined.get("asset_count", len(asset_results))

    # Sort asset results by score descending (same order as scorecard)
    sorted_results = sorted(
        asset_results,
        key=lambda r: r.get("score", {}).get("total_score", 0),
        reverse=True,
    )

    # Per-asset collapsible sections — first (highest risk) is open by default
    asset_details_html = ""
    for idx, r in enumerate(sorted_results):
        asset_details_html += _asset_details_section(r, is_first=(idx == 0))

    # Combined remediation (deduped)
    remediation_html = _combined_remediation_section(asset_results, config)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Exposure Report — {_esc(domain)}</title>
<style>{_css(risk_color)}</style>
</head>
<body>

<div class="header">
  <h1>AI Public Exposure Report</h1>
  <div class="meta">
    Domain: <strong style="color:#fff">{_esc(domain)}</strong>
    &nbsp;|&nbsp; Scanned: {_esc(scan_time)}
    &nbsp;|&nbsp; {asset_count} asset{'' if asset_count == 1 else 's'} scanned
  </div>
</div>

<div class="container">

  <!-- Aggregate Risk Score -->
  <div class="score-card">
    <div class="score-ring">
      <div class="num">{total_score}</div>
      <div class="lbl">Risk Score</div>
    </div>
    <div class="score-meta">
      <h2>{_esc(risk_label)} Risk</h2>
      <p>
        Aggregated across <strong>{asset_count}</strong>
        asset{'' if asset_count == 1 else 's'} with a combined total of
        <strong>{finding_count}</strong>
        finding{'' if finding_count == 1 else 's'}.
        Risk level is driven by the highest-risk individual asset.
      </p>
    </div>
  </div>

  <!-- Asset Scorecard -->
  <section>
    <h2>Asset Scorecard ({asset_count} asset{'' if asset_count == 1 else 's'})</h2>
    {_asset_scorecard_table(asset_results)}
  </section>

  <!-- Per-Asset Detail Sections -->
  <section style="background:transparent;box-shadow:none;padding:0;margin-bottom:0">
    <h2 style="padding:0 0 12px;border-bottom:none;margin-bottom:16px">
      Per-Asset Findings
    </h2>
    {asset_details_html}
  </section>

  <!-- Combined Remediation -->
  <section>
    <h2>Remediation Guidance</h2>
    {remediation_html}
  </section>

</div>

<footer>
  Generated by AI Exposure Analyzer &nbsp;|&nbsp; {_esc(scan_time)}
</footer>

</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path


# ---------------------------------------------------------------------------
# Public API: generate_html_report (single-asset, backward-compatible shim)
# ---------------------------------------------------------------------------

def generate_html_report(
    collector_output: dict,
    findings: list,
    secrets: list,
    score_result: dict,
    output_path: str,
) -> str:
    """
    Generate and write a board-ready HTML report for a single asset.

    This is a backward-compatible shim that wraps its arguments into a
    single-element asset_results list and calls generate_combined_report().

    Returns the path to the written file.
    """
    target = collector_output.get("target", "unknown")
    base_domain = collector_output.get("base_domain", target)
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Synthesise an asset dict from the collector output
    asset = {
        "hostname": target,
        "url": collector_output.get("target_url", f"https://{target}"),
        "ip": collector_output.get("ip"),
        "source": "root",
    }

    # Wrap into a single-element asset_results list
    asset_results = [
        {
            "asset": asset,
            "collector_output": collector_output,
            "findings": findings,
            "secrets": secrets,
            "score": score_result,
            "error": None,
        }
    ]

    # Use score_result as both the per-asset score and the combined score.
    # Augment with asset_count so the combined dict is well-formed.
    combined = dict(score_result)
    combined.setdefault("asset_count", 1)

    return generate_combined_report(
        domain=base_domain,
        asset_results=asset_results,
        combined=combined,
        output_path=output_path,
        scan_time=scan_time,
    )
