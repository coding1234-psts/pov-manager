"""
Build a single integrated HTML report (AI exposure + suspicious domains + credentials)
from the CTU zip and profile data. Used after autobrief zip download.
"""

from __future__ import annotations

import html
import io
import json
import logging
import os
import re
import tempfile
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import pandas as pd
from django.conf import settings

from ai_exposure.scanner.reporter import render_combined_report_embed_from_payload

from vdr.integrated_report_v4 import (
    INTEGRATED_REPORT_V4_TAB_SCRIPT,
    integrated_report_v4_stylesheet,
)
from vdr.models import ThreatProfile

logger = logging.getLogger(__name__)

SUFFIX_CREDENTIALS = "_credentials.xlsx"
SUFFIX_SUSPICIOUS = "_suspicious_domains.xlsx"

# Suspicious-domain risk_score bands (aligned with AI-style scoring on the same 0–100 scale).
SD_RISK_MONITORED_MAX = 25
SD_RISK_ELEVATED_MIN = 26
SD_RISK_ELEVATED_MAX = 75
SD_RISK_CRITICAL_MIN = 76


def _sd_risk_severity_counts(rs: pd.Series) -> tuple[int, int, int]:
    """Return (monitored ≤25, elevated 26–75, critical ≥76) for non-null risk scores."""
    valid = rs.dropna()
    if len(valid) == 0:
        return (0, 0, 0)
    monitored = int((valid <= SD_RISK_MONITORED_MAX).sum())
    elevated = int(
        ((valid >= SD_RISK_ELEVATED_MIN) & (valid <= SD_RISK_ELEVATED_MAX)).sum()
    )
    critical = int((valid >= SD_RISK_CRITICAL_MIN).sum())
    return (monitored, elevated, critical)

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


@dataclass
class ExecutiveSummaryMetrics:
    """Counts/strings for the Executive Summary tab; None usually means omit that tile."""

    # Suspicious-domain rows (non-empty domain); always shown when set, including 0.
    sd_typosquat: int | None = None
    sd_high_risk: int | None = None
    lc_distinct_accounts: int | None = None
    lc_exec_num: int | None = None
    lc_exec_den: int | None = None
    lc_timeline: str | None = None
    ai_score: int | None = None
    ai_asset_count: int | None = None


@dataclass
class SdTabStats:
    """Suspicious-domains tab: figures for badges, exec dash, and detail."""

    row_count: int = 0
    brand_roots: int = 0
    max_rs: float | None = None
    monitored: int = 0
    elevated: int = 0
    critical: int = 0
    tag_variety: int = 0


@dataclass
class LcTabStats:
    """Leaked-credentials tab: breach workbook summary for dash and badges."""

    breach_rows: int = 0
    distinct_emails: int = 0
    distinct_breaches: int = 0
    date_range: str = ""
    year_bars: list[tuple[int, int]] = field(default_factory=list)
    password_leak_rows: int = 0
    exec_distinct_hit: int = 0
    exec_den: int = 0
    exec_breach_rows: int = 0
    exec_pwd_rows: int = 0
    discovered_email_note: str = ""


@dataclass
class AiDashStats:
    """AI exposure JSON-derived counts for exec dash and tab badge."""

    score: int = 0
    assets: int = 0
    high: int = 0
    moderate: int = 0
    low_active: int = 0
    clean: int = 0
    total_findings: int = 0
    secrets: int = 0
    with_findings: int = 0
    risk_label: str = ""
    risk_level: str = ""


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


def _sd_table_cell_str(v: Any) -> str:
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return ""
    if hasattr(v, "strftime"):
        try:
            return v.strftime("%Y-%m-%d")
        except (TypeError, ValueError, AttributeError):
            pass
    return str(v)


def _v4_bars_html_peak_years(
    title: str,
    items: list[tuple[str, float]],
    max_bars: int = 12,
) -> str:
    """Breaches-by-year style: tallest bar(s) use bf--red, others bf--violet."""
    if not items:
        return f'<p class="empty-msg">{html.escape(MSG_METRIC_NONE)}</p>'
    items = items[:max_bars]
    peak = max(v for _, v in items) or 1.0
    max_v = peak
    rows = []
    for label, value in items:
        pct = min(100.0, 100.0 * value / max_v)
        fc = "bf--red" if value == peak and peak > 0 else "bf--violet"
        lab_esc = html.escape(str(label)[:120])
        rows.append(
            f'<div class="bar"><div class="bar-lbl">{lab_esc}</div>'
            f'<div class="bar-track"><div class="bar-fill {fc}" style="width:{pct:.1f}%"></div></div>'
            f'<div class="bar-val">{html.escape(str(int(value) if value == int(value) else round(value, 2)))}</div></div>'
        )
    return (
        f'<div class="shd">{html.escape(title)}</div>'
        f'<div class="bars">{"".join(rows)}</div>'
    )


def _v4_bars_html(
    title: str,
    items: list[tuple[str, float]],
    fill_class: str,
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
            f'<div class="bar"><div class="bar-lbl">{lab_esc}</div>'
            f'<div class="bar-track"><div class="bar-fill {fill_class}" style="width:{pct:.1f}%"></div></div>'
            f'<div class="bar-val">{html.escape(str(int(value) if value == int(value) else round(value, 2)))}</div></div>'
        )
    return (
        f'<div class="shd">{html.escape(title)}</div>'
        f'<div class="bars">{"".join(rows)}</div>'
    )


def _v4_kpis_grid(
    pairs: list[tuple[str, str]], crit_value_indices: set[int] | None = None
) -> str:
    crit_value_indices = crit_value_indices or set()
    cells = []
    for i, (val, lbl) in enumerate(pairs):
        cn = " kpi-num--crit" if i in crit_value_indices else ""
        cells.append(
            f'<div class="kpi"><div class="kpi-num{cn}">{html.escape(val)}</div>'
            f'<div class="kpi-txt">{html.escape(lbl)}</div></div>'
        )
    return f'<div class="kpis">{"".join(cells)}</div>'


def _v4_risk_meter_cell(score_val: Any) -> str:
    if score_val is None or (isinstance(score_val, float) and pd.isna(score_val)):
        return '<span class="mono" style="color:var(--text-4)">—</span>'
    try:
        v = float(score_val)
    except (TypeError, ValueError):
        return html.escape(str(score_val)[:80])
    pct = min(100.0, max(0.0, v))
    if v >= SD_RISK_CRITICAL_MIN:
        col = "var(--critical)"
    elif v >= SD_RISK_ELEVATED_MIN:
        col = "var(--warn)"
    else:
        col = "var(--blue)"
    disp = int(v) if v == int(v) else round(v, 1)
    return (
        f'<div class="rm"><div class="rm-track"><div class="rm-fill" style="width:{pct:.1f}%;background:{col}"></div></div>'
        f'<span class="rm-val" style="color:{col}">{html.escape(str(disp))}</span></div>'
    )


def _v4_threat_tags_cell(raw: Any) -> str:
    if raw is None or (isinstance(raw, float) and pd.isna(raw)):
        return '<span style="color:var(--text-4)">—</span>'
    parts = [p.strip().lower() for p in re.split(r"[,;]", str(raw)) if p.strip()]
    if not parts:
        return '<span style="color:var(--text-4)">—</span>'
    spans = []
    for p in parts[:10]:
        cls = (
            "bg--crit"
            if p in ("phishing", "malware")
            else "bg--warn"
            if p == "spam"
            else "bg--info"
        )
        spans.append(f'<span class="bg {cls}">{html.escape(p)}</span>')
    return " ".join(spans)


def _section_suspicious_domains(
    zipf: zipfile.ZipFile, profile: ThreatProfile
) -> tuple[str, bool, SdTabStats | None]:
    """
    v4 card markup for the Suspicious Domains tab; stats for exec dash and tab badge.
    """
    member = _find_zip_member_by_suffix(zipf, SUFFIX_SUSPICIOUS)
    if not member:
        return ("", False, None)

    df = _read_excel_sheet(zipf, member, "Suspicious domains")
    if df is None or "domain" not in df.columns:
        return ("", False, None)

    df = df.copy()
    df["_domain"] = df["domain"].astype(str).str.strip()
    df = df[df["_domain"].str.len() > 0]

    org = html.escape(profile.organization_name or "organization")
    sub_copy = f"Typosquat and lookalike domain monitoring for {org}."

    if len(df) == 0:
        inner = f'<p class="empty-msg">{html.escape(MSG_SUSPICIOUS_EMPTY)}</p>'
        card = (
            f'<div class="card stagger">'
            f'<div class="card-hd"><h2>Suspicious domains</h2><p>{sub_copy}</p></div>'
            f'<div class="card-bd">{inner}</div></div>'
        )
        return (card, True, SdTabStats())

    rs = pd.to_numeric(df.get("risk_score"), errors="coerce")
    df["_rs"] = rs

    n_rows = len(df)
    orig = df.get("original_domain")
    if orig is not None:
        n_brands = int(
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
    mon_n, el_n, crit_n = _sd_risk_severity_counts(df["_rs"])
    has_rs = bool(df["_rs"].notna().any())
    max_rs_f: float | None = float(max_rs) if has_rs and pd.notna(max_rs) else None

    tag_cnt: Counter[str] = Counter()
    if "risk_threat_profile" in df.columns:
        for cell in df["risk_threat_profile"].dropna().astype(str):
            for part in re.split(r"[,;]", cell):
                t = part.strip().lower()
                if t:
                    tag_cnt[t] += 1

    stats = SdTabStats(
        row_count=n_rows,
        brand_roots=n_brands,
        max_rs=max_rs_f,
        monitored=mon_n,
        elevated=el_n,
        critical=crit_n,
        tag_variety=len(tag_cnt),
    )

    kpi_pairs: list[tuple[str, str]] = [
        (str(n_rows), "Total records"),
        (str(n_brands), "Brand roots"),
    ]
    crit_idx: set[int] = set()
    if has_rs and max_rs_f is not None:
        max_display = (
            str(int(max_rs_f))
            if max_rs_f == int(max_rs_f)
            else str(round(max_rs_f, 2))
        )
        kpi_pairs.append((max_display, "Max risk score"))
        kpi_pairs.append((str(crit_n), f"Risk ≥ {SD_RISK_CRITICAL_MIN}"))
        crit_idx = {len(kpi_pairs) - 1}
    kpis_html = _v4_kpis_grid(kpi_pairs, crit_idx)

    sev_block = ""
    if has_rs:
        sev_block = _v4_bars_html(
            "Risk severity distribution (risk score)",
            [
                (f"Monitored (≤ {SD_RISK_MONITORED_MAX})", float(mon_n)),
                (
                    f"Elevated ({SD_RISK_ELEVATED_MIN}–{SD_RISK_ELEVATED_MAX})",
                    float(el_n),
                ),
                (f"Critical (≥ {SD_RISK_CRITICAL_MIN})", float(crit_n)),
            ],
            "bf--teal",
            max_bars=3,
        )

    pills_block = ""
    if tag_cnt:
        top = tag_cnt.most_common(16)
        pills = "".join(
            f'<span class="pill">{html.escape(k)} <span class="pill-ct">{v}</span></span>'
            for k, v in top
        )
        pills_block = (
            f'<div class="shd">Threat profile tags</div><div class="pills">{pills}</div>'
        )

    country_block = ""
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
            country_block = _v4_bars_html(
                "Top countries (record count)",
                list(zip(vc.index.tolist(), vc.values.tolist())),
                "bf--teal",
            )
        else:
            country_block = f'<p class="empty-msg">{html.escape(MSG_METRIC_NONE)}</p>'

    sort_df = df.sort_values("_rs", ascending=False, na_position="last")
    show_n = len(sort_df) if len(sort_df) <= 10 else 10
    sub = sort_df.head(show_n)
    col_keys = [
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
    th_labels = {
        "domain": "Domain",
        "original_domain": "Original",
        "risk_score": "Risk",
        "risk_threat_profile": "Threat",
        "create_date": "Created",
        "country": "Country",
        "registrar": "Registrar",
    }
    thead = "<tr>" + "".join(
        f"<th>{html.escape(th_labels.get(c, c))}</th>" for c in col_keys
    ) + "</tr>"
    trs = []
    for _, row in sub.iterrows():
        tds = []
        for c in col_keys:
            v = row.get(c)
            if c == "risk_score":
                inner = _v4_risk_meter_cell(v)
            elif c == "risk_threat_profile":
                inner = _v4_threat_tags_cell(v)
            elif c == "domain":
                s = _sd_table_cell_str(v)
                inner = f"<strong>{html.escape(s[:500])}</strong>" if s else ""
            else:
                s = _sd_table_cell_str(v)
                inner = html.escape(s[:500]) if s else ""
            tds.append(f"<td>{inner}</td>")
        trs.append("<tr>" + "".join(tds) + "</tr>")
    cap = (
        "All records sorted by risk score."
        if len(sort_df) <= 10
        else "Ten highest-risk domains (by risk score)."
    )
    table_html = (
        f'<div class="shd">Highest-risk domains</div>'
        f'<p class="tcap">{html.escape(cap)}</p>'
        f'<div class="tw"><table class="dt"><thead>{thead}</thead>'
        f'<tbody>{"".join(trs)}</tbody></table></div>'
    )

    body = f"{kpis_html}{sev_block}{pills_block}{country_block}{table_html}"
    card = (
        f'<div class="card stagger">'
        f'<div class="card-hd"><h2>Suspicious domains</h2><p>{sub_copy}</p></div>'
        f'<div class="card-bd">{body}</div></div>'
    )
    return (card, True, stats)


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


def _compute_executive_summary_metrics(
    zipf: zipfile.ZipFile, profile: ThreatProfile
) -> ExecutiveSummaryMetrics:
    m = ExecutiveSummaryMetrics()

    # —— Suspicious domains ——
    member_sd = _find_zip_member_by_suffix(zipf, SUFFIX_SUSPICIOUS)
    if member_sd:
        df_sd = _read_excel_sheet(zipf, member_sd, "Suspicious domains")
        if df_sd is not None and "domain" in df_sd.columns:
            dfc = df_sd.copy()
            dfc["_domain"] = dfc["domain"].astype(str).str.strip()
            dfc = dfc[dfc["_domain"].str.len() > 0]
            # Row count with non-empty domain; always set (including 0) so the tile always shows.
            m.sd_typosquat = len(dfc)
            if len(dfc) > 0:
                rs = pd.to_numeric(dfc.get("risk_score"), errors="coerce")
                dfc["_rs"] = rs
                if dfc["_rs"].notna().any():
                    _, _, crit_n = _sd_risk_severity_counts(dfc["_rs"])
                    if crit_n > 0:
                        m.sd_high_risk = crit_n

    # —— Leaked credentials ——
    member_lc = _find_zip_member_by_suffix(zipf, SUFFIX_CREDENTIALS)
    if not member_lc:
        return m
    breaches = _read_excel_sheet(zipf, member_lc, "Breaches")
    if breaches is None or not {"Email", "Breach", "Date", "Data Leaked"}.issubset(
        set(breaches.columns)
    ):
        return m
    b = breaches.copy()
    b["_em"] = b["Email"].map(_normalize_email)
    data_rows = b[b["_em"].notna() | b["Breach"].notna()]
    if len(data_rows) == 0:
        return m
    b = data_rows

    if "Email" in b.columns:
        n_em = (
            b["Email"]
            .dropna()
            .astype(str)
            .str.strip()
            .str.lower()
            .replace("", pd.NA)
            .dropna()
            .nunique()
        )
        if int(n_em) > 0:
            m.lc_distinct_accounts = int(n_em)

    dr = _lc_kpi_value_date_range(b)
    if dr != MSG_METRIC_NONE:
        m.lc_timeline = dr

    exec_emails = [_normalize_email(e) for e in (profile.organization_emails or [])]
    exec_emails = [e for e in exec_emails if e]
    if exec_emails:
        exec_set = set(exec_emails)
        sub = b[b["_em"].isin(exec_set)]
        x = int(sub["_em"].nunique()) if len(sub) else 0
        if x > 0:
            m.lc_exec_num = x
            m.lc_exec_den = len(exec_set)

    return m


def _load_ai_findings_payload(profile: ThreatProfile) -> dict[str, Any] | None:
    basename = (profile.ai_exposure_findings_json or "").strip()
    if not basename or profile.ai_exposure_job_status != ThreatProfile.AI_EXPOSURE_JOB_READY:
        return None
    ai_path = os.path.join(settings.CTU_REPORTS_PATH, basename)
    if not os.path.isfile(ai_path):
        return None
    try:
        with open(ai_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("Could not load AI findings JSON: %s", e)
        return None
    if not isinstance(data, dict):
        return None
    return data


def _parse_ai_exec_metrics_from_payload(
    payload: dict[str, Any],
) -> tuple[int | None, int | None]:
    combined = payload.get("combined_score")
    if not isinstance(combined, dict):
        combined = {}
    ts = combined.get("total_score")
    try:
        if ts is None:
            score: int | None = None
        else:
            score = int(round(float(ts)))
    except (TypeError, ValueError):
        score = None
    assets = payload.get("assets")
    if not isinstance(assets, list):
        n_assets = None
    else:
        n_assets = len(assets)
        if n_assets == 0:
            n_assets = None
    return score, n_assets


def _css_id_safe(s: str) -> str:
    t = re.sub(r"[^a-zA-Z0-9_-]+", "_", (s or "rpt").strip())
    return (t[:56] or "rpt").strip("_") or "rpt"


def _gauge_ring_offset(score: int) -> str:
    c = 264.0
    sc = max(0, min(100, int(score)))
    return f"{c * (1.0 - sc / 100.0):.2f}"


def _ai_dash_from_payload(payload: dict[str, Any] | None) -> AiDashStats | None:
    if not payload or not isinstance(payload, dict):
        return None
    combined = payload.get("combined_score") or {}
    if not isinstance(combined, dict):
        combined = {}
    try:
        score = int(round(float(combined.get("total_score") or 0)))
    except (TypeError, ValueError):
        score = 0
    risk_label = str(combined.get("risk_label") or "").strip()
    risk_level = str(combined.get("risk_level") or "").strip().lower()
    assets = payload.get("assets")
    if not isinstance(assets, list):
        return AiDashStats(score=score, risk_label=risk_label, risk_level=risk_level)
    high = mod = low_a = clean = 0
    total_findings = secrets = 0
    with_findings = 0
    for block in assets:
        if not isinstance(block, dict):
            continue
        sc = block.get("score") or {}
        if not isinstance(sc, dict):
            sc = {}
        rl = (sc.get("risk_level") or "low").lower()
        finds = block.get("findings") or []
        secs = block.get("secrets") or []
        if not isinstance(finds, list):
            finds = []
        if not isinstance(secs, list):
            secs = []
        fc = len(finds)
        total_findings += fc
        secrets += len(secs)
        has = fc > 0 or len(secs) > 0
        if has:
            with_findings += 1
        if rl == "high":
            high += 1
        elif rl == "moderate":
            mod += 1
        elif rl == "low":
            if has:
                low_a += 1
            else:
                clean += 1
        else:
            clean += 1
    return AiDashStats(
        score=score,
        assets=len(assets),
        high=high,
        moderate=mod,
        low_active=low_a,
        clean=clean,
        total_findings=total_findings,
        secrets=secrets,
        with_findings=with_findings,
        risk_label=risk_label,
        risk_level=risk_level,
    )


def _ai_exposure_hero_risk_title(risk_level: str, risk_label: str) -> str:
    """
    v4-style title fragment after em dash, e.g. "High Risk", "Moderate Risk".
    Prefers combined_score.risk_level; falls back to risk_label + " Risk".
    """
    lv = (risk_level or "").lower().strip()
    by_level = {
        "high": "High Risk",
        "moderate": "Moderate Risk",
        "low": "Low Risk",
    }
    if lv in by_level:
        return by_level[lv]
    lab = (risk_label or "").strip()
    if not lab:
        return "Unknown Risk"
    low = lab.lower()
    if low.endswith(" risk"):
        return " ".join(w.capitalize() for w in lab.split())
    return f"{lab} Risk"


def _pct_part(n: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return max(0.0, min(100.0, 100.0 * n / total))


def _build_exec_panel_v4(
    profile: ThreatProfile,
    report_id: str,
    sd: SdTabStats | None,
    lc: LcTabStats | None,
    ai: AiDashStats | None,
    *,
    show_sd: bool,
    show_lc: bool,
    show_ai: bool,
) -> str:
    """Executive Summary tab: v4 hero row + three dashboard cards."""
    sid = _css_id_safe(report_id)
    gid_ai = f"{sid}_gai"
    parts: list[str] = []

    hero_cells: list[str] = []
    has_ai_hero = bool(ai is not None and show_ai)
    has_sd = bool(sd and show_sd and sd.row_count > 0)

    if has_ai_hero and ai is not None:
        off = _gauge_ring_offset(min(100, max(0, int(ai.score))))
        risk_title = _ai_exposure_hero_risk_title(ai.risk_level, ai.risk_label)
        ai_intro = (
            f"Composite score across {html.escape(str(ai.assets))} assessed assets. "
            if ai.assets > 0
            else "Composite AI exposure score from the latest findings payload. "
        )
        ai_para = (
            "<p>"
            + ai_intro
            + "Reflects public attack-surface findings from the AI exposure assessment.</p>"
        )
        hero_cells.append(
            f'<div class="hero hero--primary">'
            f'<div class="gauge">'
            f'<svg viewBox="0 0 104 104" aria-hidden="true">'
            f'<circle cx="52" cy="52" r="42" fill="none" stroke="rgba(255,255,255,0.04)" stroke-width="5"/>'
            f'<circle class="gauge-ring" cx="52" cy="52" r="42" fill="none" '
            f'stroke="url(#{gid_ai})" stroke-width="5" stroke-dasharray="264" '
            f'stroke-dashoffset="{off}" stroke-linecap="round" transform="rotate(-90 52 52)"/>'
            f'<defs><linearGradient id="{gid_ai}" x1="0" y1="0" x2="1" y2="1">'
            f'<stop offset="0%" stop-color="#14B8A6"/><stop offset="100%" stop-color="#60A5FA"/>'
            f"</linearGradient></defs></svg>"
            f'<div class="gauge-center">'
            f'<div class="gauge-num" style="color:var(--accent)">{html.escape(str(ai.score))}</div>'
            f'<div class="gauge-label" style="color:var(--text-4)">Score</div></div></div>'
            f'<div class="hero-text"><h3>AI Exposure — {html.escape(risk_title)}</h3>'
            f"{ai_para}"
            f"</div></div>"
        )
        if has_sd and sd is not None:
            vis = 264.0 * max(
                0.08, min(0.95, (sd.critical * 2.5) / max(sd.row_count, 1))
            )
            sd_off = f"{264.0 - vis:.2f}"
            hero_cells.append(
                f'<div class="hero hero--secondary">'
                f'<div class="gauge">'
                f'<svg viewBox="0 0 104 104" aria-hidden="true">'
                f'<circle cx="52" cy="52" r="42" fill="none" stroke="var(--surface-2)" stroke-width="5"/>'
                f'<circle class="gauge-ring--partial" cx="52" cy="52" r="42" fill="none" '
                f'stroke="var(--critical)" stroke-width="5" stroke-dasharray="264" '
                f'stroke-dashoffset="{sd_off}" stroke-linecap="round" transform="rotate(-90 52 52)"/>'
                f"</svg>"
                f'<div class="gauge-center">'
                f'<div class="gauge-num" style="color:var(--critical)">{html.escape(str(sd.critical))}</div>'
                f'<div class="gauge-label" style="color:var(--text-4)">Critical</div></div></div>'
                f'<div class="hero-text"><h3>High-Risk Domains Detected</h3>'
                f"<p>{html.escape(str(sd.critical))} of {html.escape(str(sd.row_count))} typosquat-related "
                f"records scored ≥ {SD_RISK_CRITICAL_MIN} on risk score.</p>"
                f"</div></div>"
            )
    elif has_sd and sd is not None:
        vis = 264.0 * max(
            0.1, min(0.95, (sd.critical * 2.5) / max(sd.row_count, 1))
        )
        sd_off = f"{264.0 - vis:.2f}"
        hero_cells.append(
            f'<div class="hero hero--primary" style="grid-column:1/-1">'
            f'<div class="gauge">'
            f'<svg viewBox="0 0 104 104" aria-hidden="true">'
            f'<circle cx="52" cy="52" r="42" fill="none" stroke="rgba(255,255,255,0.04)" stroke-width="5"/>'
            f'<circle class="gauge-ring--partial" cx="52" cy="52" r="42" fill="none" '
            f'stroke="var(--critical)" stroke-width="5" stroke-dasharray="264" '
            f'stroke-dashoffset="{sd_off}" stroke-linecap="round" transform="rotate(-90 52 52)"/>'
            f"</svg>"
            f'<div class="gauge-center">'
            f'<div class="gauge-num" style="color:var(--accent)">{html.escape(str(sd.row_count))}</div>'
            f'<div class="gauge-label" style="color:var(--text-4)">Records</div></div></div>'
            f'<div class="hero-text"><h3>Suspicious Domain Surface</h3>'
            f"<p>{html.escape(str(sd.row_count))} typosquat-related records; "
            f"{html.escape(str(sd.critical))} at or above critical threshold "
            f"(≥ {SD_RISK_CRITICAL_MIN}).</p>"
            f"</div></div>"
        )

    if hero_cells:
        grid_style = ""
        if len(hero_cells) == 1 and has_ai_hero:
            grid_style = ' style="grid-template-columns:1fr"'
        parts.append(
            f'<div class="hero-row stagger"{grid_style}>{"".join(hero_cells)}</div>'
        )

    dash_cards: list[str] = []

    if show_sd and sd is not None:
        tot_sd = max(1, sd.monitored + sd.elevated + sd.critical)
        p_crit = _pct_part(sd.critical, tot_sd)
        p_el = _pct_part(sd.elevated, tot_sd)
        p_mon = max(0.0, 100.0 - p_crit - p_el)
        mx = (
            "—"
            if sd.max_rs is None
            else (
                str(int(sd.max_rs))
                if sd.max_rs == int(sd.max_rs)
                else str(round(float(sd.max_rs), 1))
            )
        )
        dash_cards.append(
            f'<div class="dash-card dash-card--domains">'
            f'<div class="dash-header">'
            f'<div class="dash-title">Suspicious domains</div>'
            f'<div class="dash-icon dash-icon--domains">'
            f'<svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">'
            f'<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>'
            f'<path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/>'
            f"</svg></div></div>"
            f'<div class="dash-hero-num">{html.escape(str(sd.row_count))}</div>'
            f'<div class="dash-hero-label">Typosquat-related domain records</div>'
            f'<div class="dash-severity">'
            f'<div class="dash-sev-seg" style="width:{p_crit:.1f}%;background:var(--critical)"></div>'
            f'<div class="dash-sev-seg" style="width:{p_el:.1f}%;background:var(--warn)"></div>'
            f'<div class="dash-sev-seg" style="width:{p_mon:.1f}%;background:var(--accent)"></div>'
            f"</div>"
            f'<div class="dash-sev-legend">'
            f'<span class="dash-sev-item"><span class="dash-sev-dot" style="background:var(--critical)"></span>'
            f'Critical {html.escape(str(sd.critical))}</span>'
            f'<span class="dash-sev-item"><span class="dash-sev-dot" style="background:var(--warn)"></span>'
            f'Elevated {html.escape(str(sd.elevated))}</span>'
            f'<span class="dash-sev-item"><span class="dash-sev-dot" style="background:var(--accent)"></span>'
            f'Monitored {html.escape(str(sd.monitored))}</span>'
            f"</div>"
            f'<div class="dash-stats">'
            f"<div><div class=\"dash-stat-num dash-stat-num--crit\">"
            f'{html.escape(str(sd.critical))}</div>'
            f'<div class="dash-stat-label">Risk ≥ {SD_RISK_CRITICAL_MIN}</div></div>'
            f'<div><div class="dash-stat-num">{html.escape(mx)}</div>'
            f'<div class="dash-stat-label">Max risk score</div></div>'
            f'<div><div class="dash-stat-num">{html.escape(str(sd.tag_variety))}</div>'
            f'<div class="dash-stat-label">Threat tag types</div></div>'
            f'<div><div class="dash-stat-num">{html.escape(str(sd.brand_roots))}</div>'
            f'<div class="dash-stat-label">Brand roots</div></div>'
            f"</div></div>"
        )

    if show_lc and lc is not None:
        mini_inner, mini_leg = _lc_mini_bars_markup(lc.year_bars)
        mini_block = ""
        if mini_inner:
            mini_block = (
                f'<div class="dash-mini-bars">{mini_inner}</div>'
                f'<div class="dash-mini-legend">{mini_leg}</div>'
            )
        exec_cell = "—"
        if lc.exec_den > 0 and lc.exec_distinct_hit > 0:
            exec_cell = (
                f'{html.escape(str(lc.exec_distinct_hit))} '
                f'<span style="font-size:12px;color:var(--text-4);font-weight:500">of</span> '
                f"{html.escape(str(lc.exec_den))}"
            )
        elif lc.exec_den > 0:
            exec_cell = f"0 <span style=\"font-size:12px;color:var(--text-4);font-weight:500\">of</span> {html.escape(str(lc.exec_den))}"
        hero_lc = str(lc.distinct_emails) if lc.distinct_emails > 0 else str(lc.breach_rows)
        dash_cards.append(
            f'<div class="dash-card dash-card--creds">'
            f'<div class="dash-header">'
            f'<div class="dash-title">Leaked credentials</div>'
            f'<div class="dash-icon dash-icon--creds">'
            f'<svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">'
            f'<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>'
            f'<path d="M7 11V7a5 5 0 0110 0v4"/></svg></div></div>'
            f'<div class="dash-hero-num">{html.escape(hero_lc)}</div>'
            f'<div class="dash-hero-label">Distinct accounts with breach exposure</div>'
            f"{mini_block}"
            f'<div class="dash-stats">'
            f'<div><div class="dash-stat-num">{html.escape(str(lc.breach_rows))}</div>'
            f'<div class="dash-stat-label">Breach incidents</div></div>'
            f'<div><div class="dash-stat-num">{html.escape(str(lc.distinct_breaches))}</div>'
            f'<div class="dash-stat-label">Breach sources</div></div>'
            f'<div><div class="dash-stat-num dash-stat-num--crit">{exec_cell}</div>'
            f'<div class="dash-stat-label">Exec. exposed</div></div>'
            f'<div><div class="dash-stat-num">{html.escape(str(lc.password_leak_rows))}</div>'
            f'<div class="dash-stat-label">Password leaks</div></div>'
            f"</div></div>"
        )

    if show_ai and ai is not None:
        t_ai = max(1, ai.high + ai.moderate + ai.low_active + ai.clean)
        dash_cards.append(
            f'<div class="dash-card dash-card--ai">'
            f'<div class="dash-header">'
            f'<div class="dash-title">AI Exposure</div>'
            f'<div class="dash-icon dash-icon--ai">'
            f'<svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">'
            f'<path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/>'
            f"</svg></div></div>"
            f'<div class="dash-hero-num" style="color:var(--blue)">{html.escape(str(ai.score))}</div>'
            f'<div class="dash-hero-label">Overall AI Exposure score</div>'
            f'<div class="dash-severity">'
            f'<div class="dash-sev-seg" style="width:{_pct_part(ai.high, t_ai):.1f}%;background:var(--critical)"></div>'
            f'<div class="dash-sev-seg" style="width:{_pct_part(ai.moderate, t_ai):.1f}%;background:var(--warn)"></div>'
            f'<div class="dash-sev-seg" style="width:{_pct_part(ai.low_active, t_ai):.1f}%;background:var(--blue)"></div>'
            f'<div class="dash-sev-seg" style="width:{_pct_part(ai.clean, t_ai):.1f}%;background:var(--ok)"></div>'
            f"</div>"
            f'<div class="dash-sev-legend">'
            f'<span class="dash-sev-item"><span class="dash-sev-dot" style="background:var(--critical)"></span>'
            f'High {html.escape(str(ai.high))}</span>'
            f'<span class="dash-sev-item"><span class="dash-sev-dot" style="background:var(--warn)"></span>'
            f'Moderate {html.escape(str(ai.moderate))}</span>'
            f'<span class="dash-sev-item"><span class="dash-sev-dot" style="background:var(--blue)"></span>'
            f'Low {html.escape(str(ai.low_active))}</span>'
            f'<span class="dash-sev-item"><span class="dash-sev-dot" style="background:var(--ok)"></span>'
            f'Clean {html.escape(str(ai.clean))}</span>'
            f"</div>"
            f'<div class="dash-stats">'
            f'<div><div class="dash-stat-num">{html.escape(str(ai.assets))}</div>'
            f'<div class="dash-stat-label">Assets assessed</div></div>'
            f'<div><div class="dash-stat-num">{html.escape(str(ai.total_findings))}</div>'
            f'<div class="dash-stat-label">Total findings</div></div>'
            f'<div><div class="dash-stat-num dash-stat-num--crit">{html.escape(str(ai.secrets))}</div>'
            f'<div class="dash-stat-label">Exposed secrets</div></div>'
            f'<div><div class="dash-stat-num">{html.escape(str(ai.with_findings))}</div>'
            f'<div class="dash-stat-label">With findings</div></div>'
            f"</div></div>"
        )

    if dash_cards:
        parts.append(f'<div class="dash-grid stagger">{"".join(dash_cards)}</div>')

    if not parts:
        org = html.escape(profile.organization_name or "")
        return (
            f'<p class="empty-msg">No executive dashboard metrics are available for {org} '
            f"in this bundle.</p>"
        )
    return "".join(parts)


def _lc_mini_bars_markup(
    year_bars: list[tuple[int, int]],
) -> tuple[str, str]:
    """Returns (inner HTML for .dash-mini-bars, legend HTML)."""
    if not year_bars:
        return ("", "")
    ys = sorted(year_bars, key=lambda x: x[0])[-10:]
    peak = max(c for _, c in ys) or 1
    bars: list[str] = []
    legs: list[str] = []
    for y, c in ys:
        h = max(3, int(round(100 * c / peak)))
        col = "var(--critical)" if c == peak and peak > 0 else "var(--violet)"
        bars.append(
            f'<div class="dash-mini-bar" style="height:{h}%;background:{col}"></div>'
        )
        yy = str(y)
        short = yy[2:] if len(yy) >= 2 else yy
        legs.append(f"<span>'{html.escape(short)}</span>")
    return ("".join(bars), "".join(legs))


def _section_leaked_credentials(
    zipf: zipfile.ZipFile, profile: ThreatProfile
) -> tuple[str, bool, LcTabStats | None]:
    member = _find_zip_member_by_suffix(zipf, SUFFIX_CREDENTIALS)
    if not member:
        return ("", False, None)

    breaches = _read_excel_sheet(zipf, member, "Breaches")
    emails_sheet = _read_excel_sheet(zipf, member, "Emails")

    if breaches is None and emails_sheet is None:
        return ("", False, None)

    parts: list[str] = []
    b_valid_rows: pd.DataFrame | None = None
    stats = LcTabStats()
    org = html.escape(profile.organization_name or "organization")
    sub_copy = f"Breach and exposure intelligence for {org}."

    if breaches is None or len(breaches.columns) == 0:
        inner = f'<p class="empty-msg">{html.escape(MSG_CREDENTIALS_EMPTY)}</p>'
        card = (
            f'<div class="card stagger">'
            f'<div class="card-hd"><h2>Leaked credentials</h2><p>{sub_copy}</p></div>'
            f'<div class="card-bd">{inner}</div></div>'
        )
        return (card, True, stats)

    b = breaches.copy()
    if not {"Email", "Breach", "Date", "Data Leaked"}.issubset(set(b.columns)):
        inner = f'<p class="empty-msg">{html.escape(MSG_CREDENTIALS_EMPTY)}</p>'
        card = (
            f'<div class="card stagger">'
            f'<div class="card-hd"><h2>Leaked credentials</h2><p>{sub_copy}</p></div>'
            f'<div class="card-bd">{inner}</div></div>'
        )
        return (card, True, stats)

    b["_em"] = b["Email"].map(_normalize_email)
    data_rows = b[b["_em"].notna() | b["Breach"].notna()]
    if len(data_rows) == 0:
        inner = f'<p class="empty-msg">{html.escape(MSG_CREDENTIALS_EMPTY)}</p>'
        card = (
            f'<div class="card stagger">'
            f'<div class="card-hd"><h2>Leaked credentials</h2><p>{sub_copy}</p></div>'
            f'<div class="card-bd">{inner}</div></div>'
        )
        return (card, True, stats)

    b = data_rows
    b_valid_rows = b
    n_rows = len(b)
    stats.breach_rows = n_rows

    lc1 = str(n_rows)
    lc2_raw = _lc_kpi_value_distinct_emails(b)
    lc3_raw = _lc_kpi_value_distinct_breaches(b)
    lc4_raw = _lc_kpi_value_date_range(b)
    stats.distinct_emails = (
        int(
            b["Email"]
            .dropna()
            .astype(str)
            .str.strip()
            .str.lower()
            .replace("", pd.NA)
            .dropna()
            .nunique()
        )
        if "Email" in b.columns
        else 0
    )
    stats.distinct_breaches = (
        int(
            b["Breach"]
            .dropna()
            .astype(str)
            .str.strip()
            .replace("", pd.NA)
            .dropna()
            .nunique()
        )
        if "Breach" in b.columns
        else 0
    )
    stats.date_range = lc4_raw if lc4_raw != MSG_METRIC_NONE else ""

    pwd_all = b["Data Leaked"].astype(str).str.contains(
        "password", case=False, na=False
    )
    stats.password_leak_rows = int(pwd_all.sum())

    year_items: list[tuple[str, float]] = []
    if "Date" in b.columns:
        dt = _parse_dates(b["Date"])
        valid_d = dt.notna()
        if valid_d.any():
            yc = dt[valid_d].dt.year.value_counts().sort_index()
            stats.year_bars = [(int(y), int(c)) for y, c in yc.items()]
            year_items = [(str(int(y)), float(c)) for y, c in yc.items()]

    kpi_pairs: list[tuple[str, str]] = [
        (lc1, "Breach incidents"),
        (lc2_raw, "Distinct emails"),
        (lc3_raw, "Breach sources"),
        (
            lc4_raw if lc4_raw != MSG_METRIC_NONE else "—",
            "Date range",
        ),
    ]
    parts.append(_v4_kpis_grid(kpi_pairs))

    if year_items:
        parts.append(_v4_bars_html_peak_years("Breaches by year", year_items))
    else:
        parts.append(
            f'<p class="empty-msg">{html.escape(MSG_METRIC_NONE)}</p>'
        )

    if "Data Leaked" in b.columns:
        cats = _split_data_leaked_categories(b["Data Leaked"])
        if cats:
            top_cats = sorted(cats.items(), key=lambda x: -x[1])[:10]
            chart_items = [(_display_category(k), float(v)) for k, v in top_cats]

            def _cat_fill(name: str) -> str:
                return "bf--red" if "password" in name.lower() else "bf--blue"

            rows = []
            max_v = max(v for _, v in chart_items) or 1.0
            for label, value in chart_items:
                pct = min(100.0, 100.0 * value / max_v)
                fc = _cat_fill(label)
                lab_esc = html.escape(str(label)[:120])
                rows.append(
                    f'<div class="bar"><div class="bar-lbl">{lab_esc}</div>'
                    f'<div class="bar-track"><div class="bar-fill {fc}" style="width:{pct:.1f}%"></div></div>'
                    f'<div class="bar-val">{html.escape(str(int(value)))}</div></div>'
                )
            parts.append(
                f'<div class="shd">Information types exposed</div>'
                f'<div class="bars">{"".join(rows)}</div>'
            )
        else:
            parts.append(
                f'<p class="empty-msg">{html.escape(MSG_METRIC_NONE)}</p>'
            )

    grp = b.groupby("Breach", dropna=False)["_em"].nunique().sort_values(
        ascending=False
    )
    top_b = list(zip(grp.index.astype(str).tolist(), grp.values.tolist()))[:10]
    if top_b:
        max_v = float(max(v for _, v in top_b)) or 1.0
        peak = max(v for _, v in top_b)
        rows = []
        for label, value in top_b:
            pct = min(100.0, 100.0 * float(value) / max_v)
            fc = "bf--red" if value == peak and peak > 0 else "bf--violet"
            lab_esc = html.escape(str(label)[:120])
            rows.append(
                f'<div class="bar"><div class="bar-lbl">{lab_esc}</div>'
                f'<div class="bar-track"><div class="bar-fill {fc}" style="width:{pct:.1f}%"></div></div>'
                f'<div class="bar-val">{html.escape(str(int(value)))}</div></div>'
            )
        parts.append(
            f'<div class="shd">Top breach sources (distinct accounts)</div>'
            f'<div class="bars">{"".join(rows)}</div>'
        )

    exec_emails = [
        _normalize_email(e) for e in (profile.organization_emails or [])
    ]
    exec_emails = [e for e in exec_emails if e]
    parts.append('<div class="shd">Executive account exposure</div>')
    if not exec_emails:
        parts.append(f'<p class="empty-msg">{html.escape(MSG_EXEC_NONE)}</p>')
    else:
        exec_set = set(exec_emails)
        sub = b[b["_em"].isin(exec_set)]
        stats.exec_den = len(exec_set)
        if len(sub) == 0:
            parts.append(
                f'<p class="empty-msg">{html.escape(MSG_EXEC_NO_BREACHES)}</p>'
            )
        else:
            x = int(sub["_em"].nunique())
            y = len(sub)
            stats.exec_distinct_hit = x
            stats.exec_breach_rows = y
            pwd_mask = (
                sub["Data Leaked"]
                .astype(str)
                .str.contains("password", case=False, na=False)
            )
            sub_pwd = sub[pwd_mask]
            z = len(sub_pwd)
            w = int(sub_pwd["_em"].nunique()) if z else 0
            stats.exec_pwd_rows = z
            parts.append("<ul class=\"elist\">")
            parts.append(
                "<li><span class=\"edot\"></span> Information found for "
                f"<strong>{html.escape(str(x))}</strong> executive(s).</li>"
            )
            parts.append(
                "<li><span class=\"edot edot--crit\"></span> "
                f"<strong>{html.escape(str(y))}</strong> breach record(s) identified "
                f"for <strong>{html.escape(str(x))}</strong> executive(s).</li>"
            )
            parts.append(
                "<li><span class=\"edot edot--crit\"></span> "
                f"<strong>{html.escape(str(z))}</strong> password-related leak record(s) "
                f"for <strong>{html.escape(str(w))}</strong> executive(s).</li>"
            )
            parts.append("</ul>")

    if emails_sheet is not None and len(emails_sheet.columns) > 0:
        col = emails_sheet.columns[0]
        n_em = emails_sheet[col].dropna().astype(str).str.strip()
        n_em = n_em[n_em.str.len() > 0]
        if len(n_em) and b_valid_rows is not None and len(b_valid_rows) > 0:
            note = f"Discovered email addresses in workbook: {len(n_em)} row(s)."
            stats.discovered_email_note = note
            parts.append(
                f'<p class="meta">{html.escape(note)}</p>'
            )

    parts.append(
        f'<p class="disc">{html.escape(MSG_CREDENTIALS_DISCLAIMER)}</p>'
    )
    body = "".join(parts)
    card = (
        f'<div class="card stagger">'
        f'<div class="card-hd"><h2>Leaked credentials</h2><p>{sub_copy}</p></div>'
        f'<div class="card-bd">{body}</div></div>'
    )
    return (card, True, stats)


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
            sd_inner, show_sd, sd_stats = _section_suspicious_domains(zipf, profile)
            lc_inner, show_lc, lc_stats = _section_leaked_credentials(zipf, profile)
    except zipfile.BadZipFile as e:
        logger.error("Bad zip for integrated report: %s", e)
        return None
    except Exception as e:
        logger.exception("Integrated report zip read failed: %s", e)
        return None

    ai_payload = _load_ai_findings_payload(profile)
    show_ai = ai_payload is not None
    ai_dash = _ai_dash_from_payload(ai_payload) if ai_payload else None
    ai_inner = ""
    if ai_payload is not None:
        try:
            fragment = render_combined_report_embed_from_payload(ai_payload)
            ai_inner = (
                '<div class="card stagger">'
                '<div class="card-hd"><h2>AI Exposure</h2>'
                "<p>Per-asset findings and remediation guidance from the AI exposure assessment.</p>"
                "</div>"
                f'<div class="card-bd" style="padding-top:8px"><div class="ai-embed">{fragment}</div></div>'
                "</div>"
            )
        except Exception as e:
            logger.warning("AI embed from JSON failed: %s", e)
            ai_inner = (
                '<div class="card stagger">'
                '<div class="card-hd"><h2>AI Exposure</h2></div>'
                '<div class="card-bd">'
                f'<p class="empty-msg">{html.escape(MSG_AI_UNAVAILABLE)}</p>'
                "</div></div>"
            )

    exec_inner = _build_exec_panel_v4(
        profile,
        report_id,
        sd_stats if show_sd else None,
        lc_stats if show_lc else None,
        ai_dash,
        show_sd=show_sd,
        show_lc=show_lc,
        show_ai=show_ai,
    )

    def _tab_badge(key: str) -> str:
        if key == "sd" and sd_stats is not None:
            return f'<span class="tab-n">{html.escape(str(sd_stats.row_count))}</span>'
        if key == "lc" and lc_stats is not None:
            return f'<span class="tab-n">{html.escape(str(lc_stats.breach_rows))}</span>'
        if key == "ai" and ai_dash is not None:
            return f'<span class="tab-n">{html.escape(str(ai_dash.score))}</span>'
        return ""

    tabs: list[tuple[str, str]] = []
    if show_sd or show_lc or show_ai:
        tabs.append(("exec", "Executive Summary"))
    if show_sd:
        tabs.append(("sd", "Suspicious domains"))
    if show_lc:
        tabs.append(("lc", "Leaked credentials"))
    if show_ai:
        tabs.append(("ai", "AI Exposure"))

    panel_html_by_key = {
        "exec": exec_inner,
        "sd": sd_inner,
        "lc": lc_inner,
        "ai": ai_inner,
    }
    tab_buttons = []
    tab_panels_filled = []
    for i, (key, label) in enumerate(tabs):
        selected = i == 0
        badge = _tab_badge(key)
        tab_buttons.append(
            f'<button type="button" class="tab{" active" if selected else ""}" '
            f'data-t="{html.escape(key)}" role="tab" '
            f'aria-selected="{"true" if selected else "false"}" '
            f'aria-controls="panel-{html.escape(key)}">'
            f'{html.escape(label)}{badge}</button>'
        )
        active_cls = " active" if selected else ""
        tab_panels_filled.append(
            f'<div class="panel{active_cls}" data-p="{html.escape(key)}" '
            f'id="panel-{html.escape(key)}" role="tabpanel">'
            f"{panel_html_by_key[key]}</div>"
        )

    tab_bar_html = ""
    panels_wrap = ""
    if tabs:
        tab_bar_html = (
            f'<nav class="tabs" role="tablist">{"".join(tab_buttons)}</nav>'
        )
        panels_wrap = "".join(tab_panels_filled)
    else:
        panels_wrap = '<p class="empty-msg">No report sections are available.</p>'

    org_esc = html.escape(profile.organization_name or "")
    org_plain = profile.organization_name or "Organization"
    gen_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    doc_title = "Threat Profile Report"

    css = integrated_report_v4_stylesheet()

    tab_script = INTEGRATED_REPORT_V4_TAB_SCRIPT

    shield_svg = (
        '<svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" '
        'stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>'
    )
    moon_svg = (
        '<svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>'
    )
    sun_svg = (
        '<svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">'
        '<circle cx="12" cy="12" r="5"/>'
        '<line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/>'
        '<line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>'
        '<line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>'
        '<line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/>'
        '<line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>'
        '<line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>'
    )
    body = (
        '<header class="header">'
        '<div class="header-inner">'
        '<div class="header-left">'
        f'<div class="header-icon">{shield_svg}</div>'
        "<div>"
        f'<div class="header-title">{html.escape(doc_title)}</div>'
        f'<div class="header-sub">{html.escape(org_plain)} — Integrated assessment</div>'
        "</div></div>"
        '<div style="display:flex;align-items:center;gap:16px">'
        '<div class="header-right">'
        f"<span>Organization</span> {org_esc}<br>"
        f"<span>Generated</span> {html.escape(gen_ts)}"
        "</div>"
        '<button class="theme-toggle" id="themeToggle" type="button" '
        'aria-label="Toggle color theme">'
        f"{moon_svg}{sun_svg}</button>"
        "</div></div></header>"
        f'<div class="wrap">{tab_bar_html}{panels_wrap}</div>'
    )

    doc = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(doc_title)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;0,9..40,800;1,9..40,400&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
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
