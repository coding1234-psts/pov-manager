import logging

from django.db.models.signals import post_save
from django.dispatch import receiver

from vdr.models import ThreatProfile
from vdr.services import DmarcScanService

logger = logging.getLogger(__name__)

@receiver(post_save, sender=ThreatProfile)
def scan_dmarc_on_threat_profile_save(sender, instance, created, **kwargs):
    """
    Signal handler to scan DMARC when a profile is created or updated
    """
    # Skip if no domains are set
    if not instance.organization_email_domains:
        logger.info(f"No domains to scan for profile {instance.id}")
        return

    service = DmarcScanService()

    try:
        service.scan_threat_profile_domains(instance)
        logger.info(f"DMARC scan completed for profile {instance.id}")
    except Exception as e:
        logger.error(f"Error during DMARC scan for profile {instance.id}: {str(e)}")