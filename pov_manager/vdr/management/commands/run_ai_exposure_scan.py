from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from ai_exposure.engine import run_ai_exposure_scan
from vdr.ai_exposure_workflow import persist_ai_exposure_scan_outcome
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
        self.stdout.write(self.style.SUCCESS(f"Done: {result.get('paths')}"))
        if uuid:
            p = ThreatProfile.objects.get(unique_id=uuid)
            persist_ai_exposure_scan_outcome(p, result)
        if result.get("error"):
            raise CommandError(result["error"])
