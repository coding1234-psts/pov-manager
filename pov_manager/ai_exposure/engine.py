"""
Programmatic AI exposure scan (same pipeline as the former standalone web API).
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ai_exposure.scanner.discovery import discover
from ai_exposure.scanner.collector import collect
from ai_exposure.scanner.secrets import scan as scan_secrets
from ai_exposure.scanner.analyzer import analyze
from ai_exposure.scanner.scorer import score, combined_score
from ai_exposure.powerpoint_summary import build_powerpoint_summary

logger = logging.getLogger(__name__)


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", value.strip().lower())
    return cleaned.strip("_") or "target"


def run_ai_exposure_scan(
    domain: str,
    output_dir: str | Path,
    *,
    no_discovery: bool = False,
    file_prefix: str | None = None,
) -> dict[str, Any]:
    """
    Run the full analyzer pipeline for *domain* (Threat Profile primary domain).

    Writes full findings JSON + compact PowerPoint-oriented JSON under *output_dir*
    (typically ``settings.CTU_REPORTS_PATH``).

    Parameters
    ----------
    domain:
        Main customer domain, e.g. ``example.com`` (no scheme required).
    output_dir:
        Directory for output files (created if missing).
    no_discovery:
        If True, scan only the apex host (no CT/DNS discovery).
    file_prefix:
        Optional basename prefix, e.g. threat profile ``unique_id``.

    Returns
    -------
    dict with keys:
        ``payload`` — full scan structure (same shape as former API).
        ``paths`` — ``findings_json``, ``powerpoint_json`` absolute paths.
        ``error`` — optional error string if scan aborted early.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    target = domain.strip().rstrip("/")
    if not target:
        return {
            "payload": None,
            "paths": {},
            "error": "empty_domain",
        }

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    prefix = file_prefix.strip() if file_prefix else _safe_name(target)
    base = f"{prefix}_ai_exposure_{ts}"
    findings_name = f"{base}_findings.json"
    ppt_name = f"{base}_powerpoint.json"

    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    try:
        if no_discovery:
            url = ("https://" + target) if "://" not in target else target
            assets = [
                {
                    "hostname": target.split("://")[-1].split("/")[0].split(":")[0],
                    "url": url,
                    "source": "direct",
                    "live": True,
                }
            ]
        else:
            assets = discover(target)

        if not assets:
            payload = {
                "domain": target,
                "scan_time": scan_time,
                "combined_score": combined_score([]),
                "assets": [],
                "note": "no_live_assets_discovered",
            }
            (out / findings_name).write_text(json.dumps(payload, indent=2))
            summary = build_powerpoint_summary(payload)
            (out / ppt_name).write_text(json.dumps(summary, indent=2))
            return {
                "payload": payload,
                "paths": {
                    "findings_json": str(out / findings_name),
                    "powerpoint_json": str(out / ppt_name),
                },
                "error": None,
            }

        results: list[dict[str, Any]] = []
        for a in assets:
            try:
                c = collect(a["url"])
                f = analyze(c)
                s = scan_secrets(c)
                sc = score(f, s)
                results.append(
                    {
                        "asset": a,
                        "collector_output": c,
                        "findings": f,
                        "secrets": s,
                        "score": sc,
                    }
                )
            except Exception as e:
                logger.exception("AI exposure collect/analyze failed for %s", a.get("url"))
                results.append(
                    {
                        "asset": a,
                        "collector_output": {},
                        "findings": [],
                        "secrets": [],
                        "score": {
                            "total_score": 0,
                            "risk_level": "low",
                            "risk_label": "Low",
                            "risk_color": "#2d7a2d",
                            "score_breakdown": [],
                            "finding_count": 0,
                        },
                        "error": str(e),
                    }
                )

        combined = combined_score([r["score"] for r in results])
        payload = {
            "domain": target,
            "scan_time": scan_time,
            "combined_score": combined,
            "assets": results,
        }

        (out / findings_name).write_text(json.dumps(payload, indent=2))
        summary = build_powerpoint_summary(payload)
        (out / ppt_name).write_text(json.dumps(summary, indent=2))

        return {
            "payload": payload,
            "paths": {
                "findings_json": str(out / findings_name),
                "powerpoint_json": str(out / ppt_name),
            },
            "error": None,
        }
    except Exception as e:
        logger.exception("AI exposure scan failed for %s", target)
        return {
            "payload": None,
            "paths": {},
            "error": str(e),
        }
