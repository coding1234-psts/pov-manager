"""
AI exposure jobs aligned with CTU autobrief: queue, worker, and publish gating helpers.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from django.conf import settings
from django.utils import timezone

from ai_exposure.engine import run_ai_exposure_scan
from vdr.models import ThreatProfile

logger = logging.getLogger(__name__)


def schedule_ai_exposure_for_new_autobrief(profile: ThreatProfile) -> None:
    """
    Reset artifact pointers and set queued or skipped for a brand-new autobrief request.
    Do not call on CTU resubmit (keep prior AI job state and artifacts).
    """
    profile.ai_exposure_report_html = None
    profile.ai_exposure_findings_json = None
    profile.ai_exposure_powerpoint_json = None
    profile.ai_exposure_scan_time = None
    profile.ai_exposure_job_error = None
    domain = (profile.organization_domain or "").strip()
    if not domain:
        profile.ai_exposure_job_status = ThreatProfile.AI_EXPOSURE_JOB_SKIPPED
    else:
        profile.ai_exposure_job_status = ThreatProfile.AI_EXPOSURE_JOB_QUEUED


def ai_exposure_job_is_terminal(profile: ThreatProfile) -> bool:
    """True when publish step may proceed (includes legacy empty status)."""
    s = (profile.ai_exposure_job_status or "").strip()
    if not s:
        return True
    return s in ThreatProfile.AI_EXPOSURE_JOB_TERMINAL


def ctu_progress_is_complete(progress: Any) -> bool:
    """CTU status API may return int or str for 100%."""
    if progress is None:
        return False
    try:
        return int(float(progress)) >= 100
    except (TypeError, ValueError):
        return str(progress).strip() in ("100", "100.0")


def persist_ai_exposure_scan_outcome(profile: ThreatProfile, result: dict[str, Any]) -> None:
    """Update profile from engine return dict (ready / failed)."""
    if result.get("error"):
        profile.ai_exposure_job_status = ThreatProfile.AI_EXPOSURE_JOB_FAILED
        err = str(result["error"])
        profile.ai_exposure_job_error = err[:2000] if len(err) > 2000 else err
        profile.save(
            update_fields=[
                "ai_exposure_job_status",
                "ai_exposure_job_error",
                "modified_data",
            ]
        )
        return
    paths = result.get("paths") or {}
    if paths.get("html") and paths.get("findings_json") and paths.get("powerpoint_json"):
        profile.ai_exposure_report_html = os.path.basename(paths["html"])
        profile.ai_exposure_findings_json = os.path.basename(paths["findings_json"])
        profile.ai_exposure_powerpoint_json = os.path.basename(paths["powerpoint_json"])
        profile.ai_exposure_scan_time = timezone.now()
        profile.ai_exposure_job_status = ThreatProfile.AI_EXPOSURE_JOB_READY
        profile.ai_exposure_job_error = None
        profile.save(
            update_fields=[
                "ai_exposure_report_html",
                "ai_exposure_findings_json",
                "ai_exposure_powerpoint_json",
                "ai_exposure_scan_time",
                "ai_exposure_job_status",
                "ai_exposure_job_error",
                "modified_data",
            ]
        )
        return
    profile.ai_exposure_job_status = ThreatProfile.AI_EXPOSURE_JOB_FAILED
    profile.ai_exposure_job_error = "no_output_paths"
    profile.save(
        update_fields=[
            "ai_exposure_job_status",
            "ai_exposure_job_error",
            "modified_data",
        ]
    )


def run_queued_ai_exposure_scan(profile: ThreatProfile) -> None:
    """Execute scan for profile currently marked RUNNING (caller sets RUNNING)."""
    domain = (profile.organization_domain or "").strip()
    if not domain:
        profile.ai_exposure_job_status = ThreatProfile.AI_EXPOSURE_JOB_SKIPPED
        profile.ai_exposure_job_error = None
        profile.save(
            update_fields=[
                "ai_exposure_job_status",
                "ai_exposure_job_error",
                "modified_data",
            ]
        )
        return
    try:
        result = run_ai_exposure_scan(
            domain,
            settings.CTU_REPORTS_PATH,
            file_prefix=str(profile.unique_id),
        )
    except Exception as e:
        logger.exception("AI exposure scan crashed for profile %s", profile.unique_id)
        profile.ai_exposure_job_status = ThreatProfile.AI_EXPOSURE_JOB_FAILED
        msg = str(e)
        profile.ai_exposure_job_error = msg[:2000] if len(msg) > 2000 else msg
        profile.save(
            update_fields=[
                "ai_exposure_job_status",
                "ai_exposure_job_error",
                "modified_data",
            ]
        )
        return
    persist_ai_exposure_scan_outcome(profile, result)
