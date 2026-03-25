from typing import Any
from os import path
import zipfile
import logging

from django.core.management.base import BaseCommand
from django.conf import settings

from vdr.ctuapi import report_status, download_report
from vdr.models import ThreatProfile, Vulnerabilities
from vdr.utils import generate_vulnerabilities_excel
from vdr.vdrapi import disable_all_schedules, VDRAPIError

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Checks the status of a CTU Autobrief report and downloads it if completed."

    def add_vulnerabilities_list_in_zip(self, profile, zip_file_path):
        vulnerabilities = Vulnerabilities.objects.filter(threat_profile=profile)

        # Generate file with vulnerabilities list
        excel_buffer = generate_vulnerabilities_excel(vulnerabilities)
        try:
            with zipfile.ZipFile(zip_file_path, 'a', zipfile.ZIP_DEFLATED) as zipf:
                excel_filename = f"{profile.organization_name} vulnerabilities.xlsx"
                zipf.writestr(excel_filename, excel_buffer.read())
            self.stdout.write(self.style.SUCCESS(f"Excel file added to ZIP as {excel_filename}"))
        except Exception as e:
            self.stderr.write(f"Failed to write Excel to ZIP: {e}")

    def handle(self, *args: Any, **options: Any) -> None:
        profiles = ThreatProfile.objects.filter(
            status__in=[ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_REQUESTED,
                        ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_REQUESTED_WITHOUT_VDR]
        )

        if not profiles.exists():
            self.stdout.write("There are no thread profiles with CTU Autobrief report requested.")
            return

        for profile in profiles:
            self.stdout.write(f"Checking the CTU Autobrief report status for {profile.organization_name}")
            report_status_percent: int = report_status(profile.ctu_autobrief_report_id)

            if report_status_percent == 100:
                self.stdout.write(
                    f"The CTU Autobrief report for {profile.organization_name} is ready. Starting download."
                )

                file_path: str = path.join(settings.CTU_REPORTS_PATH, f"{profile.ctu_autobrief_report_id}.zip")
                download_report(profile.ctu_autobrief_report_id, file_path)

                if path.isfile(file_path):
                    self.add_vulnerabilities_list_in_zip(profile, file_path)
                    
                    # Update profile status
                    if profile.status == ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_REQUESTED:
                        profile.status = ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_AVAILABLE
                        
                        # Disable VDR scans for profiles with VDR data
                        if profile.tag_id:
                            self.stdout.write(
                                f"Disabling VDR scan schedules for {profile.organization_name} (Tag ID: {profile.tag_id})..."
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
                                logger.error(f"Unexpected error disabling schedules for {profile.organization_name}: {e}")
                                self.stderr.write(
                                    f"Warning: Unexpected error disabling VDR schedules: {e}"
                                )
                        
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
                self.stdout.write(f"The CTU Autobrief report for {profile.organization_name} is still in progress.")