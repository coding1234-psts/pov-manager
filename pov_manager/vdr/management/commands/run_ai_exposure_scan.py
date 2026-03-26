import os

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from ai_exposure.engine import run_ai_exposure_scan
from vdr.models import ThreatProfile


class Command(BaseCommand):
    help = (
        "Run the AI exposure analyzer for a threat profile (by UUID) or a raw domain. "
        "Outputs are written under CTU_REPORTS_PATH."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--profile-uuid",
            type=str,
            default=None,
            help="ThreatProfile.unique_id (UUID)",
        )
        parser.add_argument(
            "--domain",
            type=str,
            default=None,
            help="Override domain (if not using --profile-uuid)",
        )

    def handle(self, *args, **options):
        uuid = options.get("profile_uuid")
        domain = (options.get("domain") or "").strip()

        if uuid:
            profile = ThreatProfile.objects.filter(unique_id=uuid).first()
            if not profile:
                raise CommandError(f"No threat profile with unique_id={uuid}")
            domain = (profile.organization_domain or "").strip()
            if not domain:
                raise CommandError("Threat profile has no organization_domain")
            prefix = str(profile.unique_id)
            self.stdout.write(f"Scanning domain {domain!r} for profile {uuid}")
        elif domain:
            prefix = None
            self.stdout.write(f"Scanning domain {domain!r} (no profile link)")
        else:
            raise CommandError("Provide --profile-uuid or --domain")

        result = run_ai_exposure_scan(
            domain,
            settings.CTU_REPORTS_PATH,
            file_prefix=prefix,
        )
        if result.get("error"):
            raise CommandError(result["error"])
        self.stdout.write(self.style.SUCCESS(f"Done: {result.get('paths')}"))
        if uuid and result.get("paths"):
            p = ThreatProfile.objects.get(unique_id=uuid)
            paths = result["paths"]
            p.ai_exposure_report_html = os.path.basename(paths["html"])
            p.ai_exposure_findings_json = os.path.basename(paths["findings_json"])
            p.ai_exposure_powerpoint_json = os.path.basename(paths["powerpoint_json"])
            p.ai_exposure_scan_time = timezone.now()
            p.save()
