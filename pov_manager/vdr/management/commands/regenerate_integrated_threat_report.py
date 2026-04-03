import os
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vdr.integrated_threat_report import (
    integrated_report_zip_entry_name,
    replace_integrated_report_in_zip,
    resolve_profile_for_integrated_report,
)
from vdr.models import ThreatProfile


class Command(BaseCommand):
    help = (
        "Rebuild the integrated threat report HTML inside the CTU autobrief zip "
        "(…_integrated_threat_report.html) from the existing zip and current profile. "
        "Pass one report_id, or use --all to process every distinct CTU id that has "
        "a profile and a zip file on disk."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "report_id",
            nargs="?",
            default=None,
            type=str,
            help=(
                "CTU autobrief report id (same as zip basename without .zip). "
                "Omit when using --all."
            ),
        )
        parser.add_argument(
            "--all",
            action="store_true",
            help=(
                "Regenerate integrated HTML for each distinct ctu_autobrief_report_id "
                "that has a ThreatProfile and {id}.zip exists under CTU_REPORTS_PATH."
            ),
        )

    def handle(self, *args: Any, **options: Any) -> None:
        do_all = bool(options["all"])
        report_id = (options["report_id"] or "").strip()

        if do_all and report_id:
            raise CommandError("Do not pass report_id together with --all.")

        if do_all:
            self._handle_all()
            return

        if not report_id:
            raise CommandError("Pass a report_id or use --all.")

        self._regenerate_one(report_id)

    def _regenerate_one(self, report_id: str) -> None:
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

    def _handle_all(self) -> None:
        qs = (
            ThreatProfile.objects.exclude(ctu_autobrief_report_id__isnull=True)
            .exclude(ctu_autobrief_report_id="")
            .values_list("ctu_autobrief_report_id", flat=True)
            .distinct()
        )
        ids = sorted({(rid or "").strip() for rid in qs if (rid or "").strip()})
        if not ids:
            self.stdout.write("No ThreatProfile rows with ctu_autobrief_report_id set.")
            return

        ok = skip = fail = 0
        for rid in ids:
            zip_path = os.path.join(settings.CTU_REPORTS_PATH, f"{rid}.zip")
            if not os.path.isfile(zip_path):
                self.stdout.write(
                    self.style.WARNING(f"skip {rid}: zip not found on disk")
                )
                skip += 1
                continue
            profile = resolve_profile_for_integrated_report(rid)
            if not profile:
                self.stdout.write(
                    self.style.WARNING(
                        f"skip {rid}: no ThreatProfile (unexpected after distinct query)"
                    )
                )
                skip += 1
                continue
            entry = integrated_report_zip_entry_name(rid)
            if replace_integrated_report_in_zip(profile, zip_path, rid):
                self.stdout.write(
                    self.style.SUCCESS(
                        f"ok {rid}: replaced {entry!r} in {os.path.basename(zip_path)}"
                    )
                )
                ok += 1
            else:
                self.stdout.write(
                    self.style.ERROR(
                        f"fail {rid}: regeneration failed (see logs for details)"
                    )
                )
                fail += 1

        self.stdout.write(
            f"Done: {ok} replaced, {skip} skipped, {fail} failed (total ids {len(ids)})."
        )
        if fail:
            raise CommandError(f"{fail} report(s) failed to regenerate.")
