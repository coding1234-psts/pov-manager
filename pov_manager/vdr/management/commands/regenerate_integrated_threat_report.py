import os
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vdr.integrated_threat_report import (
    integrated_report_zip_entry_name,
    replace_integrated_report_in_zip,
    resolve_profile_for_integrated_report,
)


class Command(BaseCommand):
    help = (
        "Rebuild the integrated threat report HTML inside the CTU autobrief zip "
        "(…_integrated_threat_report.html) from the existing zip and current profile."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "report_id",
            type=str,
            help="CTU autobrief report id (same as zip basename without .zip).",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        report_id = (options["report_id"] or "").strip()
        if not report_id:
            raise CommandError("report_id is required.")

        profile = resolve_profile_for_integrated_report(report_id)
        if not profile:
            raise CommandError(
                f"No ThreatProfile with ctu_autobrief_report_id={report_id!r}."
            )

        zip_path = os.path.join(settings.CTU_REPORTS_PATH, f"{report_id}.zip")
        if not os.path.isfile(zip_path):
            raise CommandError(
                f"Zip not found: {zip_path} (expected under CTU_REPORTS_PATH)."
            )

        entry = integrated_report_zip_entry_name(report_id)
        if replace_integrated_report_in_zip(profile, zip_path, report_id):
            self.stdout.write(
                self.style.SUCCESS(
                    f"Replaced {entry!r} inside {os.path.basename(zip_path)}."
                )
            )
        else:
            raise CommandError(
                "Failed to regenerate integrated report (see logs for details)."
            )
