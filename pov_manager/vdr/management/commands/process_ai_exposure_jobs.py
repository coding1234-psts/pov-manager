import logging

from django.core.management.base import BaseCommand

from vdr.ai_exposure_workflow import run_queued_ai_exposure_scan
from vdr.models import ThreatProfile

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = (
        "Run queued AI exposure scans (aligned with CTU autobrief). "
        "Schedule via cron alongside download_autobrief_documents."
    )

    def handle(self, *args, **options):
        qs = ThreatProfile.objects.filter(
            ai_exposure_job_status=ThreatProfile.AI_EXPOSURE_JOB_QUEUED
        ).order_by("pk")
        count = qs.count()
        if not count:
            self.stdout.write("No queued AI exposure jobs.")
            return
        self.stdout.write(f"Processing up to {count} queued AI exposure job(s).")
        processed = 0
        for profile in qs:
            updated = ThreatProfile.objects.filter(
                pk=profile.pk,
                ai_exposure_job_status=ThreatProfile.AI_EXPOSURE_JOB_QUEUED,
            ).update(ai_exposure_job_status=ThreatProfile.AI_EXPOSURE_JOB_RUNNING)
            if updated != 1:
                continue
            profile.refresh_from_db()
            self.stdout.write(
                f"Running AI exposure for {profile.organization_name!r} ({profile.unique_id})"
            )
            try:
                run_queued_ai_exposure_scan(profile)
            except Exception:
                logger.exception("Unexpected error in AI job for %s", profile.unique_id)
                profile.refresh_from_db()
                profile.ai_exposure_job_status = ThreatProfile.AI_EXPOSURE_JOB_FAILED
                profile.ai_exposure_job_error = "worker_unhandled_exception"
                profile.save(
                    update_fields=[
                        "ai_exposure_job_status",
                        "ai_exposure_job_error",
                        "modified_data",
                    ]
                )
            processed += 1
        self.stdout.write(self.style.SUCCESS(f"Finished AI exposure worker pass ({processed} job(s))."))
