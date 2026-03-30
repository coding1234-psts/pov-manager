import logging
import threading
import time
from decimal import Decimal
from io import StringIO
from typing import List, Optional, Tuple

import pandas as pd

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand
from django.db.models import (
    Case,
    CharField,
    Count,
    F,
    IntegerField,
    Value,
    When,
)
from django.db.models.functions import Concat
from django.utils import timezone

from vdr.ai_exposure_workflow import schedule_ai_exposure_for_new_autobrief
from vdr.ctuapi import submit_new_report as ctu_submit_new_report
from vdr.models import ThreatProfile, Vulnerabilities
from vdr.vdrapi import (
    generate_vulnerabilities_report,
    check_vulnerabilities_report_status,
    fetch_report,
)
from vdr.utils import (
    preselect_vulnerabilities,
    generate_dmarc_report,
)

logger = logging.getLogger(__name__)


def get_report(tag_id: str, max_retries: int = 30, sleep_interval: int = 5) -> Optional[StringIO]:
    """
    Fetches a report file by checking its status in intervals.

    Args:
        tag_id: The tag identifier for the report
        max_retries: Maximum number of status check attempts
        sleep_interval: Seconds to wait between status checks

    Returns:
        StringIO buffer containing the report, or None

    Raises:
        TimeoutError: If report generation exceeds the timeout period
    """
    report_id = generate_vulnerabilities_report(tag_id)
    logger.info(f'VDR report ID {report_id}')

    for attempt in range(max_retries):
        status, file_url_location = check_vulnerabilities_report_status(report_id)
        logger.debug(f'Attempt {attempt + 1}/{max_retries}: {status}, {file_url_location}')

        if status == "done" and file_url_location:
            return fetch_report(file_url_location)

        if attempt < max_retries - 1:  # Don't sleep on the last iteration
            logger.info('Waiting for report to be ready...')
            time.sleep(sleep_interval)

    raise TimeoutError(f"Report generation timed out after {max_retries * sleep_interval} seconds.")


def parse_csv_from_buffer(buffer: StringIO) -> pd.DataFrame:
    """Parse CSV data from a buffer into a DataFrame with specific columns."""
    columns = [
        "address", "ip", "location", "severity", "description", "cve_number",
        "remedy", "references", "report_id", "vulnerability_id", "score_cvss",
        "score_cps", "group_description", "group_differentiator", "os_family", "os_name"
    ]
    buffer.seek(0)
    return pd.read_csv(buffer, usecols=columns)


def save_vulnerabilities(threat_profile: ThreatProfile, data: pd.DataFrame) -> None:
    """
    Bulk create vulnerability records from DataFrame data.

    Args:
        threat_profile: The ThreatProfile to associate vulnerabilities with
        data: DataFrame containing vulnerability data
    """
    vulnerabilities = []

    for _, row in data.iterrows():
        asset_type = (Vulnerabilities.ASSET_TYPE_WEBSITE
                      if row['address'].startswith('http')
                      else Vulnerabilities.ASSET_TYPE_SERVER)

        vulnerabilities.append(Vulnerabilities(
            threat_profile=threat_profile,
            address=row['address'],
            ip=row['ip'],
            severity=row['severity'],
            description=row['description'],
            location=row['location'],
            cve_number=row['cve_number'],
            remedy=row['remedy'],
            references=row['references'],
            report_id=row['report_id'],
            vulnerability_id=row['vulnerability_id'],
            score_cvss=Decimal(row['score_cvss']) if pd.notna(row['score_cvss']) else Decimal(0),
            score_cps=Decimal(row['score_cps']) if pd.notna(row['score_cps']) else Decimal(0),
            group_description=row['group_description'],
            group_differentiator=row['group_differentiator'],
            os_family=row['os_family'],
            os_name=row['os_name'],
            asset_type=asset_type
        ))

    Vulnerabilities.objects.bulk_create(vulnerabilities, ignore_conflicts=True)
    logger.info(f'Saved {len(vulnerabilities)} vulnerabilities for {threat_profile.organization_name}')


def get_severity_order_case():
    """Returns a Case expression for severity ordering."""
    return Case(
        When(severity='critical', then=Value(1)),
        When(severity='medium', then=Value(2)),
        When(severity='warning', then=Value(3)),
        When(severity='info', then=Value(4)),
        default=Value(5),
        output_field=IntegerField(),
    )


def top_vulnerabilities(filtered_ids: List[int], asset_type: str, limit: int = 5) -> dict:
    """
    Get top vulnerabilities for a given asset type.

    Args:
        filtered_ids: List of vulnerability IDs to include
        asset_type: Type of asset (SERVER or WEBSITE)
        limit: Maximum number of vulnerabilities to return

    Returns:
        Dictionary containing vulnerability data organized by address, title, and criticality
    """
    address_key = "ips" if asset_type == Vulnerabilities.ASSET_TYPE_SERVER else "address"
    vulns = {
        address_key: [],
        "Vulnerabilities": [],
        "Criticality": [],
    }

    if not filtered_ids:
        return vulns

    severity_mapping = {
        "critical": "critical",
        "medium": "medium",
        "warning": "low",
        "info": "low",
    }

    vulnerabilities = (
        Vulnerabilities.objects
        .filter(id__in=filtered_ids)
        .annotate(
            vulnerability_title=Concat(
                'group_description',
                Value(' '),
                'group_differentiator',
                output_field=CharField()
            ),
            severity_order=get_severity_order_case()
        )
        .order_by('-score_cps', 'severity_order')[:limit]
    )

    for vuln in vulnerabilities:
        severity = severity_mapping.get(vuln.severity.lower(), "low")
        vulns[address_key].append(vuln.address)
        vulns["Vulnerabilities"].append(vuln.vulnerability_title)
        vulns["Criticality"].append(severity)

    return vulns


def total_live_systems(threat_profile: ThreatProfile, asset_type: str) -> int:
    """Count distinct systems/IPs for a threat profile and asset type."""
    return Vulnerabilities.objects.filter(
        threat_profile=threat_profile,
        asset_type=asset_type
    ).values('ip').distinct().count()


def total_vulnerabilities(threat_profile: ThreatProfile, asset_type: str) -> int:
    """Count distinct vulnerabilities for a threat profile and asset type."""
    return Vulnerabilities.objects.filter(
        threat_profile=threat_profile,
        asset_type=asset_type
    ).values('vulnerability_id').distinct().count()


def percent_severities(threat_profile: ThreatProfile, asset_type: str) -> dict:
    """
    Calculate percentage distribution of vulnerability severities.

    Returns:
        Dictionary with 'critical', 'medium', and 'low' percentage values as strings
    """
    vulnerabilities = Vulnerabilities.objects.filter(
        threat_profile=threat_profile,
        asset_type=asset_type
    )

    total = vulnerabilities.count()
    if total == 0:
        return {}

    severity_counts = vulnerabilities.values('severity').annotate(
        total=Count('severity')
    )

    # Build severity count dictionary
    counts = {item['severity']: item['total'] for item in severity_counts}

    critical = counts.get('critical', 0)
    medium = counts.get('medium', 0)
    low = counts.get('warning', 0) + counts.get('info', 0)

    return {
        'critical': str(int((critical / total) * 100)),
        'medium': str(int((medium / total) * 100)),
        'low': str(int((low / total) * 100))
    }


def build_vdr_data(profile: ThreatProfile) -> dict:
    """
    Build VDR data structure for CTU autobrief.

    Args:
        profile: The ThreatProfile to process

    Returns:
        Dictionary containing VDR data for servers and websites
    """
    preselected_server_vulnerabilities = preselect_vulnerabilities(
        threat_profile_id=profile.pk,
        asset_type=Vulnerabilities.ASSET_TYPE_SERVER
    )
    preselected_website_vulnerabilities = preselect_vulnerabilities(
        threat_profile_id=profile.pk,
        asset_type=Vulnerabilities.ASSET_TYPE_WEBSITE
    )

    return {
        'vdr_data': {
            'vdr_server_table': top_vulnerabilities(
                filtered_ids=preselected_server_vulnerabilities,
                asset_type=Vulnerabilities.ASSET_TYPE_SERVER
            ),
            'vdr_live_servers': total_live_systems(
                threat_profile=profile,
                asset_type=Vulnerabilities.ASSET_TYPE_SERVER
            ),
            'vdr_server_vuln': total_vulnerabilities(
                threat_profile=profile,
                asset_type=Vulnerabilities.ASSET_TYPE_SERVER
            ),
            'vdr_server_pie': percent_severities(
                threat_profile=profile,
                asset_type=Vulnerabilities.ASSET_TYPE_SERVER
            ),
            'vdr_website_table': top_vulnerabilities(
                filtered_ids=preselected_website_vulnerabilities,
                asset_type=Vulnerabilities.ASSET_TYPE_WEBSITE
            ),
            'vdr_live_websites': total_live_systems(
                threat_profile=profile,
                asset_type=Vulnerabilities.ASSET_TYPE_WEBSITE
            ),
            'vdr_website_vuln': total_vulnerabilities(
                threat_profile=profile,
                asset_type=Vulnerabilities.ASSET_TYPE_WEBSITE
            ),
            'vdr_website_pie': percent_severities(
                threat_profile=profile,
                asset_type=Vulnerabilities.ASSET_TYPE_WEBSITE
            )
        }
    }


def generate_ctu_autobrief_report(profile: ThreatProfile, has_vdr_data: bool = True) -> str:
    """
    Generate and submit CTU autobrief report.

    Args:
        profile: The ThreatProfile to generate report for
        has_vdr_data: Whether VDR vulnerability data is available (disabled)

    Returns:
        Report ID from CTU submission
    """
    template_pptx = 'Threat_Profile_DMARC_Template.pptx'

    ctu_autobrief_data = profile.ctu_autobrief_data

    if profile.organization_email_domains:
        dmarc_report = generate_dmarc_report(profile)
        ctu_autobrief_data.update(dmarc_report)

    data = {
        'client_name': profile.organization_name,
        'cached_domains': True,
        'domains': [profile.organization_domain],
        'email_domains': profile.organization_email_domains,
        'email_report': False,
        'exec_emails': profile.organization_emails,
        'keywords': [profile.organization_name],
        'manual_emails': [],
        'network_ranges': profile.ip_ranges,
        'search_vt': False,
        'shodan_filters': False,
        'take_domain_screenshots': True,
        'template': 'EBS_AutoSample_v0.4.docx',
        'template_pptx': template_pptx,
        'external_data': ctu_autobrief_data
    }

    logger.info(f'Generating CTU autobrief report with template: {template_pptx}')
    return ctu_submit_new_report(data)


def process_profile(profile: ThreatProfile) -> None:
    """
    Process a threat profile: fetch VDR data, build autobrief data, and submit report.

    Args:
        profile: The ThreatProfile to process
    """
    has_vdr_data = False

    # Attempt to fetch and save VDR vulnerability data
    try:
        report_buffer = get_report(tag_id=profile.tag_id, sleep_interval=40)
        report_df = parse_csv_from_buffer(report_buffer)
        save_vulnerabilities(threat_profile=profile, data=report_df)

        profile.status = ThreatProfile.STATUS_VULNERABILITY_RESULTS_COLLECTED
        profile.save()

        has_vdr_data = True
        logger.info(f'Successfully collected VDR data for {profile.organization_name}')

    except TimeoutError as e:
        logger.warning(f'VDR report timeout for {profile.organization_name}: {e}')
    except Exception as e:
        logger.error(f'Error fetching VDR report for {profile.organization_name}: {e}', exc_info=True)

    # Build CTU autobrief data (runs whether or not VDR data was collected)
    ctu_autobrief_data = build_vdr_data(profile)

    profile.ctu_autobrief_data = ctu_autobrief_data
    profile.status = ThreatProfile.STATUS_CTU_AUTOBRIEF_DATA_PROCESSED
    profile.save()

    # Generate and submit CTU autobrief report
    had_previous_ctu = bool((profile.ctu_autobrief_report_id or "").strip())
    profile.ctu_autobrief_report_id = generate_ctu_autobrief_report(profile, has_vdr_data=has_vdr_data)
    profile.status = ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_REQUESTED
    if profile.ctu_autobrief_report_id and not had_previous_ctu:
        schedule_ai_exposure_for_new_autobrief(profile)
    profile.save()

    logger.info(f'Completed processing for {profile.organization_name}')


class Command(BaseCommand):
    help = "Download VDR reports for threat profiles created 24 hours ago"

    def handle(self, *args, **options):
        self.stdout.write('Task started.')

        cutoff_time = timezone.now() - timezone.timedelta(hours=24)
        profiles = ThreatProfile.objects.filter(
            status=ThreatProfile.STATUS_SCANS_SCHEDULED,
            created_date__lte=cutoff_time
        )

        profile_count = profiles.count()
        if not profile_count:
            self.stdout.write(
                "There are no threat profiles scheduled for scanning created 24 hours ago.",
                ending="\n"
            )
            return

        self.stdout.write(f'Found {profile_count} profile(s) to process.')
        threads = []

        for profile in profiles:
            if not profile.tag_id:
                self.stdout.write(f'Skipping {profile.organization_name}: Tag ID is null')
                continue

            self.stdout.write(f'Processing {profile.organization_name}...')
            thread = threading.Thread(target=process_profile, args=(profile,))
            thread.start()
            threads.append(thread)

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        self.stdout.write(self.style.SUCCESS('Task completed.'))