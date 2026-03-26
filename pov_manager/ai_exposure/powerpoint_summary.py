"""
Compact JSON for downstream PowerPoint / executive slides.
"""

from __future__ import annotations

import os
from typing import Any

import yaml

_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "config",
    "patterns.yaml",
)

# High-level narrative by overall risk (1–2 sentences each).
RISK_NARRATIVES = {
    "high": (
        "External attack surface shows high AI exposure: prioritize unauthenticated model endpoints, "
        "exposed credentials, and public admin or documentation surfaces."
    ),
    "moderate": (
        "Several externally observable AI-related risks warrant review: tighten authentication, "
        "secrets handling, and unnecessary public AI or playground interfaces."
    ),
    "low": (
        "Observed public AI exposure is limited; continue good practices for keys, rate limits, "
        "and production hardening (e.g. source maps, CSRF on AI forms)."
    ),
}


def _load_remediation_titles() -> list[dict[str, str]]:
    with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    rem = cfg.get("remediation") or {}
    items = []
    for key, block in rem.items():
        if not isinstance(block, dict):
            continue
        title = block.get("title") or key
        priority = block.get("priority") or ""
        first_step = ""
        steps = block.get("steps") or []
        if steps and isinstance(steps[0], str):
            first_step = steps[0]
        # One–two lines: title + truncated first step
        high_level = title
        if first_step:
            snippet = first_step if len(first_step) <= 180 else first_step[:177] + "…"
            high_level = f"{title} — {snippet}"
        items.append(
            {
                "id": key,
                "priority": priority,
                "high_level": high_level,
            }
        )
    return items


def build_powerpoint_summary(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Build summary dict from full findings *payload* (engine / former API shape).
    """
    combined = payload.get("combined_score") or {}
    risk_level = (combined.get("risk_level") or "low").lower()
    narrative = RISK_NARRATIVES.get(risk_level, RISK_NARRATIVES["low"])

    rows: list[dict[str, Any]] = []
    for block in payload.get("assets") or []:
        asset = block.get("asset") or {}
        hostname = asset.get("hostname") or asset.get("url") or ""
        sc = block.get("score") or {}
        for line in sc.get("score_breakdown") or []:
            rows.append(
                {
                    "asset": hostname,
                    "item": line.get("item", ""),
                    "score": line.get("score", 0),
                }
            )

    rows.sort(key=lambda r: -abs(int(r.get("score") or 0)))
    seen = set()
    top5 = []
    for r in rows:
        key = (r["asset"], r["item"])
        if key in seen:
            continue
        seen.add(key)
        top5.append(
            {
                "rank": len(top5) + 1,
                "asset": r["asset"],
                "finding": r["item"],
                "score": r["score"],
            }
        )
        if len(top5) >= 5:
            break

    remediation_static = _load_remediation_titles()

    return {
        "domain": payload.get("domain"),
        "scan_time": payload.get("scan_time"),
        "overall_risk": {
            "total_score": combined.get("total_score", 0),
            "risk_level": combined.get("risk_level"),
            "risk_label": combined.get("risk_label"),
            "description": narrative,
        },
        "asset_scorecard_top_findings": top5,
        "remediation_guidance": remediation_static,
    }
