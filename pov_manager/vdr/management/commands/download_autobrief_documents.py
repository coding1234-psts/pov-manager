import logging
import re
import zipfile
from os import path
from typing import Any

from django.core.management.base import BaseCommand
from django.conf import settings

from vdr.ai_exposure_workflow import ai_exposure_job_is_terminal, ctu_progress_is_complete
from vdr.ctuapi import report_status, download_report
from vdr.integrated_threat_report import append_integrated_report_to_zip
from vdr.models import ThreatProfile, Vulnerabilities
from vdr.utils import generate_vulnerabilities_excel
from vdr.vdrapi import disable_all_schedules, VDRAPIError

logger = logging.getLogger(__name__)


def _safe_zip_entry_name(name: str, fallback: str = "report") -> str:
    cleaned = re.sub(r"[^\w.\- ]+", "_", name, flags=re.UNICODE).strip()
    return cleaned[:180] if cleaned else fallback


class Command(BaseCommand):
    help = "Checks CTU Autobrief report status; when CTU and AI exposure are terminal, downloads zip and enriches it."

    def add_vulnerabilities_list_in_zip(self, profile, zip_file_path):
        vulnerabilities = Vulnerabilities.objects.filter(threat_profile=profile)

        excel_buffer = generate_vulnerabilities_excel(vulnerabilities)
        try:
            with zipfile.ZipFile(zip_file_path, "a", zipfile.ZIP_DEFLATED) as zipf:
                excel_filename = f"{profile.organization_name} vulnerabilities.xlsx"
                zipf.writestr(excel_filename, excel_buffer.read())
            self.stdout.write(self.style.SUCCESS(f"Excel file added to ZIP as {excel_filename}"))
        except Exception as e:
            self.stderr.write(f"Failed to write Excel to ZIP: {e}")

    def add_ai_exposure_html_to_zip(self, profile, zip_file_path):
        basename = (profile.ai_exposure_report_html or "").strip()
        if not basename or profile.ai_exposure_job_status != ThreatProfile.AI_EXPOSURE_JOB_READY:
            return
        html_path = path.join(settings.CTU_REPORTS_PATH, basename)
        if not path.isfile(html_path):
            logger.warning(
                "AI exposure HTML missing on disk for profile %s: %s",
                profile.unique_id,
                html_path,
            )
            return
        entry = _safe_zip_entry_name(
            f"{profile.organization_name} AI exposure report.html",
            "AI_exposure_report.html",
        )
        try:
            with zipfile.ZipFile(zip_file_path, "a", zipfile.ZIP_DEFLATED) as zipf:
                with open(html_path, "rb") as f:
                    zipf.writestr(entry, f.read())
            self.stdout.write(self.style.SUCCESS(f"AI exposure HTML added to ZIP as {entry}"))
        except Exception as e:
            self.stderr.write(f"Failed to write AI HTML to ZIP: {e}")

    def handle(self, *args: Any, **options: Any) -> None:
        profiles = ThreatProfile.objects.filter(
            status__in=[
                ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_REQUESTED,
                ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_REQUESTED_WITHOUT_VDR,
            ]
        )

        if not profiles.exists():
            self.stdout.write("There are no thread profiles with CTU Autobrief report requested.")
            return

        for profile in profiles:
            self.stdout.write(f"Checking the CTU Autobrief report status for {profile.organization_name}")
            progress = report_status(profile.ctu_autobrief_report_id)
            ctu_done = ctu_progress_is_complete(progress)

            if not ctu_done:
                self.stdout.write(
                    f"The CTU Autobrief report for {profile.organization_name} is still in progress."
                )
                continue

            if not ai_exposure_job_is_terminal(profile):
                self.stdout.write(
                    self.style.WARNING(
                        f"CTU report ready for {profile.organization_name}, "
                        f"waiting for AI exposure job (status={profile.ai_exposure_job_status!r})."
                    )
                )
                continue

            self.stdout.write(
                f"The CTU Autobrief report for {profile.organization_name} is ready "
                f"and AI exposure is terminal ({profile.ai_exposure_job_status!r}). Starting download."
            )

            file_path: str = path.join(
                settings.CTU_REPORTS_PATH, f"{profile.ctu_autobrief_report_id}.zip"
            )
            download_report(profile.ctu_autobrief_report_id, file_path)

            if path.isfile(file_path):
                self.add_vulnerabilities_list_in_zip(profile, file_path)
                self.add_ai_exposure_html_to_zip(profile, file_path)
                if append_integrated_report_to_zip(
                    profile, file_path, profile.ctu_autobrief_report_id
                ):
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"Integrated threat report added to ZIP "
                            f"({profile.ctu_autobrief_report_id}_integrated_threat_report.html)."
                        )
                    )
                else:
                    self.stderr.write(
                        "Warning: Could not add integrated threat report to ZIP "
                        "(see logs)."
                    )

                if profile.status == ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_REQUESTED:
                    profile.status = ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_AVAILABLE

                    if profile.tag_id:
                        self.stdout.write(
                            f"Disabling VDR scan schedules for {profile.organization_name} "
                            f"(Tag ID: {profile.tag_id})..."
                        )
                        try:
                            results = disable_all_schedules(profile.tag_id)
                            logger.info(
                                f"Disabled schedules for {profile.organization_name}: "
                                f"{results['ranges_disabled']} ranges, "
                                f"{results['servers_disabled']} servers, "
                                f"{results['websites_disabled']} websites"
                            )
                            self.stdout.write(
                                self.style.SUCCESS(
                                    f"Successfully disabled {results['ranges_disabled']} range(s), "
                                    f"{results['servers_disabled']} server(s), "
                                    f"and {results['websites_disabled']} website(s) schedules"
                                )
                            )
                        except VDRAPIError as e:
                            logger.error(f"Failed to disable schedules for {profile.organization_name}: {e}")
                            self.stderr.write(
                                f"Warning: Could not disable VDR schedules: {e}. "
                                "Schedules may continue to run."
                            )
                        except Exception as e:
                            logger.error(
                                f"Unexpected error disabling schedules for {profile.organization_name}: {e}"
                            )
                            self.stderr.write(f"Warning: Unexpected error disabling VDR schedules: {e}")

                elif profile.status == ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_REQUESTED_WITHOUT_VDR:
                    profile.status = ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_AVAILABLE_WITHOUT_VDR
                else:
                    profile.status = ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_AVAILABLE_WITHOUT_VDR

                profile.save()
                self.stdout.write(
                    self.style.SUCCESS(
                        f"The CTU Autobrief report for {profile.organization_name} has been downloaded and is available."
                    )
                )
            else:
                self.stderr.write(
                    f"Download failed or file missing for {profile.organization_name} "
                    f"(report id {profile.ctu_autobrief_report_id})."
                )
