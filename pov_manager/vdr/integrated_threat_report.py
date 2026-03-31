"""
Build a single integrated HTML report (AI exposure + suspicious domains + credentials)
from the CTU zip and profile data. Used after autobrief zip download.
"""

from __future__ import annotations

import html
import io
import logging
import os
import re
import tempfile
import zipfile
from collections import Counter
from typing import Any

import pandas as pd
from bs4 import BeautifulSoup
from django.conf import settings

from ai_exposure.scanner.reporter import AI_REPORT_ROOT_CLASS

from vdr.models import ThreatProfile

logger = logging.getLogger(__name__)

SUFFIX_CREDENTIALS = "_credentials.xlsx"
SUFFIX_SUSPICIOUS = "_suspicious_domains.xlsx"

MSG_AI_UNAVAILABLE = (
    "An AI exposure assessment could not be included in this report."
)
MSG_SUSPICIOUS_EMPTY = "No findings for current domain(s) specified."
MSG_CREDENTIALS_EMPTY = "No findings for current specified domains."
MSG_EXEC_NONE = "No executive accounts were specified for this assessment."
MSG_EXEC_NO_BREACHES = (
    "No breach records were identified for the specified executive accounts."
)
MSG_METRIC_NONE = "No qualifying records were identified for this measure."
MSG_LC1_EMPTY = "No data rows were supplied for this category."
MSG_CREDENTIALS_DISCLAIMER = (
    "The information in this section is derived from third-party breach and "
    "exposure intelligence. It is provided for defensive assessment purposes and "
    "does not constitute authentication of current account status or live "
    "credential validity."
)


def integrated_report_zip_entry_name(report_id: str) -> str:
    return f"{report_id}_integrated_threat_report.html"


def _find_zip_member_by_suffix(zipf: zipfile.ZipFile, suffix: str) -> str | None:
    suffix_l = suffix.lower()
    matches = [n for n in zipf.namelist() if n.lower().endswith(suffix_l)]
    if not matches:
        return None
    matches.sort(key=len, reverse=True)
    return matches[0]


def _read_excel_sheet(
    zipf: zipfile.ZipFile, member: str, sheet: str | int
) -> pd.DataFrame | None:
    try:
        data = zipf.read(member)
    except KeyError:
        return None
    try:
        return pd.read_excel(io.BytesIO(data), sheet_name=sheet, engine="openpyxl")
    except Exception as e:
        logger.warning("Failed to read %s sheet %s: %s", member, sheet, e)
        return None


def _parse_dates(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series, errors="coerce")


def _normalize_email(s: Any) -> str | None:
    if s is None or (isinstance(s, float) and pd.isna(s)):
        return None
    t = str(s).strip().lower()
    return t if t else None


def _extract_ai_embed_for_integrated(ai_html: bytes) -> str:
    """
    Build embed HTML: scoped <style> from <head> plus the .ai-exposure-report subtree
    when present. Legacy reports (no wrapper) embed body children only and omit
    stylesheet so unscoped rules do not affect the integrated document.
    """
    text = ai_html.decode("utf-8", errors="replace")
    try:
        soup = BeautifulSoup(ai_html, "html.parser")
    except Exception as e:
        logger.warning("Could not parse AI HTML for embedding: %s", e)
        return f"<pre>{html.escape(text)}</pre>"

    style_chunks = re.findall(r"<style[^>]*>([\s\S]*?)</style>", text, flags=re.I)
    combined_css = "\n".join(s.strip() for s in style_chunks if s and s.strip())

    root = soup.select_one(f"div.{AI_REPORT_ROOT_CLASS}")
    if root is not None:
        frag = str(root)
        if combined_css:
            return f"<style>\n{combined_css}\n</style>\n{frag}"
        logger.warning(
            "AI exposure HTML has %s wrapper but no <style> blocks; layout may be wrong.",
            AI_REPORT_ROOT_CLASS,
        )
        return frag

    body = soup.body
    if body:
        inner = "".join(str(c) for c in body.children)
        if inner.strip():
            logger.info(
                "AI exposure HTML has no div.%s; embedding body without stylesheet "
                "(regenerate the AI report for full styling in the integrated view).",
                AI_REPORT_ROOT_CLASS,
            )
        return inner
    return soup.decode()


def _bar_chart_html(
    title: str,
    items: list[tuple[str, float]],
    max_bars: int = 10,
) -> str:
    if not items:
        return f'<p class="empty-msg">{html.escape(MSG_METRIC_NONE)}</p>'
    items = items[:max_bars]
    max_v = max(v for _, v in items) or 1.0
    rows = []
    for label, value in items:
        pct = min(100.0, 100.0 * value / max_v)
        lab_esc = html.escape(str(label)[:120])
        rows.append(
            f'<div class="bar-row"><div class="bar-label">{lab_esc}</div>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{pct:.1f}%"></div></div>'
            f'<div class="bar-val">{html.escape(str(int(value) if value == int(value) else round(value, 2)))}</div></div>'
        )
    return (
        f'<h3 class="chart-title">{html.escape(title)}</h3>'
        f'<div class="bar-chart">{"".join(rows)}</div>'
    )


def _kpi_card(label: str, value: str) -> str:
    return (
        f'<div class="kpi"><div class="kpi-val">{html.escape(value)}</div>'
        f'<div class="kpi-lbl">{html.escape(label)}</div></div>'
    )


def _section_suspicious_domains(zipf: zipfile.ZipFile) -> tuple[str, bool]:
    """
    Returns (panel inner HTML including h2, include_tab).
    include_tab False if workbook missing/unreadable.
    """
    member = _find_zip_member_by_suffix(zipf, SUFFIX_SUSPICIOUS)
    if not member:
        return ("", False)

    df = _read_excel_sheet(zipf, member, "Suspicious domains")
    if df is None:
        return ("", False)

    if "domain" not in df.columns:
        return ("", False)

    df = df.copy()
    df["_domain"] = df["domain"].astype(str).str.strip()
    df = df[df["_domain"].str.len() > 0]

    if len(df) == 0:
        inner = f'<p class="empty-msg">{html.escape(MSG_SUSPICIOUS_EMPTY)}</p>'
        return (f"<h2>Suspicious domains</h2>{inner}", True)

    rs = pd.to_numeric(df.get("risk_score"), errors="coerce")
    df["_rs"] = rs

    n_rows = len(df)
    orig = df.get("original_domain")
    if orig is not None:
        n_brands = (
            orig.dropna()
            .astype(str)
            .str.strip()
            .replace("", pd.NA)
            .dropna()
            .nunique()
        )
    else:
        n_brands = 0

    max_rs = df["_rs"].max()
    high_n = int((df["_rs"] >= 80).sum()) if df["_rs"].notna().any() else 0

    kpis = [
        _kpi_card("Total records", str(n_rows)),
        _kpi_card("Distinct brand roots", str(int(n_brands))),
    ]
    if df["_rs"].notna().any():
        max_val = float(max_rs)
        max_display = (
            str(int(max_val)) if max_val == int(max_val) else str(max_val)
        )
        kpis.append(_kpi_card("Max Risk Score", max_display))
        kpis.append(_kpi_card("Records with risk ≥ 80", str(high_n)))
    else:
        kpis.append(
            f'<div class="kpi wide"><p class="empty-msg">{html.escape(MSG_METRIC_NONE)}</p></div>'
        )

    threat_block = ""
    if "risk_threat_profile" in df.columns:
        tags: list[str] = []
        for cell in df["risk_threat_profile"].dropna().astype(str):
            for part in re.split(r"[,;]", cell):
                t = part.strip().lower()
                if t:
                    tags.append(t)
        if tags:
            cnt = Counter(tags).most_common(12)
            lis = "".join(f"<li>{html.escape(k)} ({v})</li>" for k, v in cnt)
            threat_block = f'<h3>Threat profile tags</h3><ul class="tag-list">{lis}</ul>'

    country_chart = ""
    if "country" in df.columns:
        c = (
            df["country"]
            .dropna()
            .astype(str)
            .str.strip()
            .replace("", pd.NA)
            .dropna()
        )
        if len(c):
            vc = c.value_counts().head(10)
            country_chart = _bar_chart_html(
                "Top countries (record count)",
                list(zip(vc.index.tolist(), vc.values.tolist())),
            )
        else:
            country_chart = f'<p class="empty-msg">{html.escape(MSG_METRIC_NONE)}</p>'

    sort_df = df.sort_values("_rs", ascending=False, na_position="last")
    show_n = len(sort_df) if len(sort_df) <= 10 else 10
    sub = sort_df.head(show_n)
    cols = [
        c
        for c in (
            "domain",
            "original_domain",
            "risk_score",
            "risk_threat_profile",
            "create_date",
            "country",
            "registrar",
        )
        if c in sub.columns
    ]
    thead = "<tr>" + "".join(f"<th>{html.escape(c)}</th>" for c in cols) + "</tr>"
    trs = []
    for _, row in sub.iterrows():
        tds = []
        for c in cols:
            v = row.get(c)
            if pd.isna(v):
                s = ""
            else:
                s = str(v)
            tds.append(f"<td>{html.escape(s[:500])}</td>")
        trs.append("<tr>" + "".join(tds) + "</tr>")
    caption = (
        "All records sorted by risk score."
        if len(sort_df) <= 10
        else "Ten highest-risk domains (by risk score)."
    )
    table_html = (
        f'<h3>Domain detail</h3><p class="table-caption">{html.escape(caption)}</p>'
        f'<div class="table-wrap"><table class="data-table">{thead}<tbody>{"".join(trs)}</tbody></table></div>'
    )

    body = (
        f'<div class="kpi-row">{"".join(kpis)}</div>'
        f"{threat_block}{country_chart}{table_html}"
    )
    return (f"<h2>Suspicious domains</h2>{body}", True)


def _split_data_leaked_categories(series: pd.Series) -> Counter:
    cnt: Counter = Counter()
    for cell in series.dropna().astype(str):
        for part in re.split(r"[,;]", cell):
            t = part.strip()
            if not t:
                continue
            key = " ".join(t.split()).lower()
            cnt[key] += 1
    return cnt


def _display_category(key: str) -> str:
    return key.title() if key else ""


def _lc_kpi_value_distinct_emails(b: pd.DataFrame) -> str:
    if "Email" not in b.columns:
        return MSG_METRIC_NONE
    n = (
        b["Email"]
        .dropna()
        .astype(str)
        .str.strip()
        .str.lower()
        .replace("", pd.NA)
        .dropna()
        .nunique()
    )
    return str(int(n)) if n > 0 else MSG_METRIC_NONE


def _lc_kpi_value_distinct_breaches(b: pd.DataFrame) -> str:
    if "Breach" not in b.columns:
        return MSG_METRIC_NONE
    n = (
        b["Breach"]
        .dropna()
        .astype(str)
        .str.strip()
        .replace("", pd.NA)
        .dropna()
        .nunique()
    )
    return str(int(n)) if n > 0 else MSG_METRIC_NONE


def _lc_kpi_value_date_range(b: pd.DataFrame) -> str:
    if "Date" not in b.columns:
        return MSG_METRIC_NONE
    dt = _parse_dates(b["Date"])
    valid = dt.notna()
    if not valid.any():
        return MSG_METRIC_NONE
    mn = dt[valid].min()
    mx = dt[valid].max()
    if mn.year == mx.year and mn.month == mx.month:
        return mn.strftime("%B %Y")
    # e.g. "Dec 2008 -> November 2025" (abbrev. start, full month end)
    start_lbl = mn.strftime("%b %Y")
    end_lbl = mx.strftime("%B %Y")
    return f"{start_lbl} -> {end_lbl}"


def _section_leaked_credentials(
    zipf: zipfile.ZipFile, profile: ThreatProfile
) -> tuple[str, bool]:
    member = _find_zip_member_by_suffix(zipf, SUFFIX_CREDENTIALS)
    if not member:
        return ("", False)

    breaches = _read_excel_sheet(zipf, member, "Breaches")
    emails_sheet = _read_excel_sheet(zipf, member, "Emails")

    if breaches is None and emails_sheet is None:
        return ("", False)

    parts: list[str] = []
    b_valid_rows: pd.DataFrame | None = None

    parts.append("<h2>Leaked credentials</h2>")

    if breaches is None or len(breaches.columns) == 0:
        parts.append(
            f'<p class="empty-msg">{html.escape(MSG_CREDENTIALS_EMPTY)}</p>'
        )
    else:
        b = breaches.copy()
        if not {"Email", "Breach", "Date", "Data Leaked"}.issubset(set(b.columns)):
            parts.append(
                f'<p class="empty-msg">{html.escape(MSG_CREDENTIALS_EMPTY)}</p>'
            )
        else:
            b["_em"] = b["Email"].map(_normalize_email)
            data_rows = b[b["_em"].notna() | b["Breach"].notna()]
            if len(data_rows) == 0:
                parts.append(
                    f'<p class="empty-msg">{html.escape(MSG_CREDENTIALS_EMPTY)}</p>'
                )
            else:
                b = data_rows
                b_valid_rows = b

                # LC-1 … LC-4 KPI row
                if len(b) == 0:
                    lc1_display = MSG_LC1_EMPTY
                else:
                    lc1_display = str(len(b))
                lc2_display = _lc_kpi_value_distinct_emails(b)
                lc3_display = _lc_kpi_value_distinct_breaches(b)
                lc4_display = _lc_kpi_value_date_range(b)

                kpi_lc = [
                    _kpi_card("Breach incidents (rows)", lc1_display),
                    _kpi_card("Distinct affected emails", lc2_display),
                    _kpi_card("Distinct breach sources", lc3_display),
                    _kpi_card("Date range (earliest – latest)", lc4_display),
                ]
                parts.append(f'<div class="kpi-row">{"".join(kpi_lc)}</div>')

                # LC-6 — breaches by year (bars)
                year_chart = ""
                if "Date" not in b.columns:
                    year_chart = f'<p class="empty-msg">{html.escape(MSG_METRIC_NONE)}</p>'
                else:
                    dt = _parse_dates(b["Date"])
                    valid_d = dt.notna()
                    if not valid_d.any():
                        year_chart = f'<p class="empty-msg">{html.escape(MSG_METRIC_NONE)}</p>'
                    else:
                        yc = dt[valid_d].dt.year.value_counts().sort_index()
                        year_items = [(str(int(y)), float(c)) for y, c in yc.items()]
                        year_chart = _bar_chart_html("Breaches by year", year_items)
                parts.append(year_chart)

                # LC-5 — single visualization (same split as former chart B)
                if "Data Leaked" not in b.columns:
                    cat_chart = f'<p class="empty-msg">{html.escape(MSG_METRIC_NONE)}</p>'
                else:
                    cats = _split_data_leaked_categories(b["Data Leaked"])
                    if not cats:
                        cat_chart = f'<p class="empty-msg">{html.escape(MSG_METRIC_NONE)}</p>'
                    else:
                        top_cats = sorted(cats.items(), key=lambda x: -x[1])[:10]
                        chart_items = [
                            (_display_category(k), float(v)) for k, v in top_cats
                        ]
                        cat_chart = _bar_chart_html(
                            "Top information types leaked (occurrence count)",
                            chart_items,
                        )
                parts.append(cat_chart)

                # LC-7 — top breaches by distinct accounts (unchanged)
                grp = b.groupby("Breach", dropna=False)["_em"].nunique().sort_values(
                    ascending=False
                )
                chart_a = _bar_chart_html(
                    "Top breaches by distinct accounts (email count)",
                    list(zip(grp.index.astype(str).tolist(), grp.values.tolist())),
                )
                parts.append(chart_a)

                # Executive subsection
                exec_emails = [
                    _normalize_email(e)
                    for e in (profile.organization_emails or [])
                ]
                exec_emails = [e for e in exec_emails if e]
                parts.append("<h3>Executive accounts</h3>")
                if not exec_emails:
                    parts.append(
                        f'<p class="empty-msg">{html.escape(MSG_EXEC_NONE)}</p>'
                    )
                else:
                    exec_set = set(exec_emails)
                    sub = b[b["_em"].isin(exec_set)]
                    if len(sub) == 0:
                        parts.append(
                            f'<p class="empty-msg">{html.escape(MSG_EXEC_NO_BREACHES)}</p>'
                        )
                    else:
                        x = int(sub["_em"].nunique())
                        y = len(sub)
                        pwd_mask = (
                            sub["Data Leaked"]
                            .astype(str)
                            .str.contains("password", case=False, na=False)
                        )
                        sub_pwd = sub[pwd_mask]
                        z = len(sub_pwd)
                        w = int(sub_pwd["_em"].nunique()) if z else 0
                        parts.append('<ul class="exec-metrics">')
                        parts.append(
                            "<li>"
                            + html.escape(
                                f"Information found for {x} executive(s)."
                            )
                            + "</li>"
                        )
                        parts.append(
                            "<li>"
                            + html.escape(
                                f"{y} breach record(s) identified for {x} executive(s)."
                            )
                            + "</li>"
                        )
                        parts.append(
                            "<li>"
                            + html.escape(
                                f"{z} password-related leak record(s) identified "
                                f"for {w} executive(s)."
                            )
                            + "</li>"
                        )
                        parts.append("</ul>")

    if emails_sheet is not None and len(emails_sheet.columns) > 0:
        col = emails_sheet.columns[0]
        n_em = emails_sheet[col].dropna().astype(str).str.strip()
        n_em = n_em[n_em.str.len() > 0]
        if len(n_em) and b_valid_rows is not None and len(b_valid_rows) > 0:
            parts.append(
                f"<p class=\"meta\">Discovered email addresses in workbook: {len(n_em)} row(s).</p>"
            )

    parts.append(
        f'<p class="disclaimer">{html.escape(MSG_CREDENTIALS_DISCLAIMER)}</p>'
    )
    return ("".join(parts), True)


def _ai_tab_content(profile: ThreatProfile) -> tuple[str, bool]:
    basename = (profile.ai_exposure_report_html or "").strip()
    if not basename or profile.ai_exposure_job_status != ThreatProfile.AI_EXPOSURE_JOB_READY:
        return ("", False)
    ai_path = os.path.join(settings.CTU_REPORTS_PATH, basename)
    if not os.path.isfile(ai_path):
        return ("", False)
    try:
        with open(ai_path, "rb") as f:
            raw = f.read()
        inner = _extract_ai_embed_for_integrated(raw)
    except OSError as e:
        logger.warning("Could not read AI HTML: %s", e)
        return ("", False)
    body = f"<h2>AI exposure</h2><div class=\"ai-embed\">{inner}</div>"
    return (body, True)


def build_integrated_threat_report_html(
    profile: ThreatProfile,
    zip_path: str,
    report_id: str,
) -> str | None:
    """
    Build full integrated HTML. Returns None if zip unreadable.
    """
    try:
        with zipfile.ZipFile(zip_path, "r") as zipf:
            sd_inner, show_sd = _section_suspicious_domains(zipf)
            lc_inner, show_lc = _section_leaked_credentials(zipf, profile)
    except zipfile.BadZipFile as e:
        logger.error("Bad zip for integrated report: %s", e)
        return None
    except Exception as e:
        logger.exception("Integrated report zip read failed: %s", e)
        return None

    ai_inner, show_ai = _ai_tab_content(profile)

    tabs: list[tuple[str, str, str]] = []
    if show_sd:
        tabs.append(("sd", "tab-sd", "Suspicious domains"))
    if show_lc:
        tabs.append(("lc", "tab-lc", "Leaked credentials"))
    if show_ai:
        tabs.append(("ai", "tab-ai", "AI exposure"))

    panel_html_by_key = {"sd": sd_inner, "lc": lc_inner, "ai": ai_inner}
    tab_buttons = []
    tab_panels_filled = []
    for i, (key, tid, label) in enumerate(tabs):
        panel_id = f"panel-{key}"
        selected = i == 0
        body = panel_html_by_key[key]
        tab_buttons.append(
            f'<button type="button" class="report-tab{" is-active" if selected else ""}" '
            f'id="{tid}" role="tab" aria-selected="{"true" if selected else "false"}" '
            f'aria-controls="{panel_id}" data-tab="{key}">{html.escape(label)}</button>'
        )
        tab_panels_filled.append(
            f'<div class="report-tab-panel" id="{panel_id}" role="tabpanel" '
            f'aria-labelledby="{tid}"{" hidden" if not selected else ""} data-panel="{key}">'
            f"{body}</div>"
        )

    tab_bar_html = ""
    panels_wrap = ""
    if tabs:
        tab_bar_html = (
            f'<div class="tab-bar" role="tablist">{" ".join(tab_buttons)}</div>'
        )
        panels_wrap = f'<div class="tab-panels">{"".join(tab_panels_filled)}</div>'
    else:
        panels_wrap = '<p class="empty-msg">No report sections are available.</p>'

    org_esc = html.escape(profile.organization_name or "")
    title = f"Integrated threat report — {profile.organization_name}"

    css = """
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #f5f5f7; color: #1d1d1f; font-size: 15px; line-height: 1.6; }
  .page-header { background: #10037C; color: #fff; padding: 28px 48px 36px; }
  .page-header h1 { font-size: 24px; font-weight: 700; margin-bottom: 8px; }
  .page-header .meta { color: #999; font-size: 13px; }
  .container { max-width: 1140px; margin: 24px auto; padding: 0 24px 48px; }
  .report-shell { background: #fff; border-radius: 12px; padding: 0;
    box-shadow: 0 1px 4px rgba(0,0,0,.08); overflow: hidden; }
  .tab-bar { display: flex; flex-wrap: wrap; gap: 10px; padding: 20px 24px 16px;
    border-bottom: 1px solid #e8e8ed; background: #fafafa; }
  .report-tab { appearance: none; border: 1px solid #d2d2d7; background: #fff;
    color: #1d1d1f; padding: 10px 18px; border-radius: 8px; font-size: 14px;
    font-weight: 600; cursor: pointer; font-family: inherit; }
  .report-tab:hover { border-color: #0071b3; color: #0071b3; }
  .report-tab.is-active { background: #10037C; color: #fff; border-color: #10037C; }
  .report-tab:focus-visible { outline: 2px solid #0071b3; outline-offset: 2px; }
  .tab-panels { padding: 24px 28px 32px; }
  .report-tab-panel[hidden] { display: none !important; }
  .report-tab-panel h2 { font-size: 17px; font-weight: 700; margin-bottom: 20px;
    border-bottom: 1px solid #e8e8ed; padding-bottom: 12px; color: #1d1d1f; }
  .empty-msg { color: #555; font-style: italic; margin: 12px 0; }
  .kpi-row { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 24px; }
  .kpi { background: #f5f5f7; border-radius: 10px; padding: 16px 20px; min-width: 140px; flex: 1; }
  .kpi.wide { flex: 100%; }
  .kpi-val { font-size: 18px; font-weight: 700; color: #1d1d1f; line-height: 1.35; }
  .kpi-lbl { font-size: 12px; color: #666; margin-top: 4px; }
  .chart-title { font-size: 15px; margin: 20px 0 12px; color: #333; }
  .bar-chart { margin-bottom: 24px; }
  .bar-row { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
  .bar-label { flex: 0 0 200px; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bar-track { flex: 1; height: 22px; background: #e8e8ed; border-radius: 4px; overflow: hidden; }
  .bar-fill { height: 100%; background: #0071b3; border-radius: 4px; min-width: 2px; }
  .bar-val { flex: 0 0 48px; text-align: right; font-size: 13px; font-weight: 600; }
  .table-wrap { overflow-x: auto; margin-top: 12px; }
  table.data-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  table.data-table th, table.data-table td { border: 1px solid #e8e8ed; padding: 8px 10px; text-align: left; }
  table.data-table th { background: #f5f5f7; font-weight: 600; }
  .table-caption { font-size: 13px; color: #666; margin-bottom: 8px; }
  .tag-list { margin: 12px 0 20px 20px; }
  .ai-embed { overflow-x: auto; }
  .ai-embed pre { white-space: pre-wrap; word-break: break-word; }
  .disclaimer { font-size: 12px; color: #666; margin-top: 20px; line-height: 1.5; }
  .meta { font-size: 13px; color: #666; margin-top: 12px; }
  .exec-metrics { margin: 12px 0 20px 20px; line-height: 1.7; list-style: disc; }
"""

    tab_script = """
(function(){
  var tabs = document.querySelectorAll('.report-tab');
  var panels = document.querySelectorAll('.report-tab-panel');
  function show(key) {
    panels.forEach(function(p) {
      var on = p.getAttribute('data-panel') === key;
      p.hidden = !on;
    });
    tabs.forEach(function(t) {
      var sel = t.getAttribute('data-tab') === key;
      t.setAttribute('aria-selected', sel ? 'true' : 'false');
      t.classList.toggle('is-active', sel);
    });
  }
  tabs.forEach(function(t) {
    t.addEventListener('click', function() { show(t.getAttribute('data-tab')); });
  });
})();
"""

    body = (
        f'<header class="page-header"><h1>{html.escape(title)}</h1>'
        f'<p class="meta">Organization: {org_esc}</p></header>'
        f'<div class="container"><div class="report-shell">{tab_bar_html}{panels_wrap}</div></div>'
    )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>{css}</style>
</head>
<body>
{body}
<script>{tab_script}</script>
</body>
</html>
"""
    return doc


def _zip_replace_or_add_entry(
    zip_path: str,
    entry_name: str,
    new_data: bytes,
) -> bool:
    """
    Write a new zip at zip_path: all members preserved except any matching entry_name,
    then entry_name with new_data. Atomic replace on success.
    """
    zip_dir = os.path.dirname(os.path.abspath(zip_path)) or "."
    tmp_path: str | None = None
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".zip", dir=zip_dir)
        os.close(fd)
        with zipfile.ZipFile(zip_path, "r") as zin:
            with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as zout:
                for info in zin.infolist():
                    if info.filename == entry_name:
                        continue
                    zout.writestr(info, zin.read(info.filename))
                zout.writestr(entry_name, new_data)
        os.replace(tmp_path, zip_path)
        tmp_path = None
        return True
    except Exception as e:
        logger.error("Failed to rewrite zip %s: %s", zip_path, e)
        return False
    finally:
        if tmp_path and os.path.isfile(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def replace_integrated_report_in_zip(
    profile: ThreatProfile,
    zip_path: str,
    report_id: str,
) -> bool:
    """Regenerate integrated HTML and replace its entry inside the zip (no duplicate)."""
    html_out = build_integrated_threat_report_html(profile, zip_path, report_id)
    if not html_out:
        return False
    name = integrated_report_zip_entry_name(report_id)
    return _zip_replace_or_add_entry(zip_path, name, html_out.encode("utf-8"))


def append_integrated_report_to_zip(
    profile: ThreatProfile,
    zip_path: str,
    report_id: str,
) -> bool:
    """Generate integrated HTML and place it in the zip (replaces entry if already present)."""
    html_out = build_integrated_threat_report_html(profile, zip_path, report_id)
    if not html_out:
        return False
    name = integrated_report_zip_entry_name(report_id)
    return _zip_replace_or_add_entry(zip_path, name, html_out.encode("utf-8"))


def read_integrated_report_html_from_zip(zip_path: str, report_id: str) -> bytes | None:
    """
    Return the raw bytes of the integrated threat report HTML as stored in the CTU zip.
    If duplicate member names exist, the last entry wins (matches typical re-pack behavior).
    """
    rid = (report_id or "").strip()
    if not rid or not zip_path or not os.path.isfile(zip_path):
        return None
    entry = integrated_report_zip_entry_name(rid)
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            matches = [i for i in zf.infolist() if i.filename == entry]
            if not matches:
                suffix = "/" + entry
                matches = [i for i in zf.infolist() if i.filename.endswith(suffix)]
            if not matches:
                return None
            return zf.read(matches[-1].filename)
    except (zipfile.BadZipFile, OSError, KeyError) as e:
        logger.warning("Could not read integrated report from zip %s: %s", zip_path, e)
        return None


def resolve_profile_for_integrated_report(report_id: str) -> ThreatProfile | None:
    """Return a threat profile for this CTU autobrief report id, or None."""
    rid = (report_id or "").strip()
    if not rid:
        return None
    return (
        ThreatProfile.objects.filter(ctu_autobrief_report_id=rid)
        .order_by("-pk")
        .first()
    )
