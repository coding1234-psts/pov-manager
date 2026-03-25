from io import BytesIO
from typing import Dict, List, Optional, Union
from urllib.parse import urljoin

import pandas as pd

from django.conf import settings
from .models import DmarcScanResult, Vulnerabilities


def generate_vulnerabilities_excel(vulnerabilities_queryset):
    """
    Generates an Excel file from a queryset of Vulnerabilities.

    :param vulnerabilities_queryset: Django queryset of Vulnerabilities
    :return: BytesIO object containing Excel data
    """
    # Convert the queryset to a DataFrame
    data = list(vulnerabilities_queryset.values(
        'address', 'ip', 'severity', 'description', 'location', 'cve_number', 'remedy',
        'references', 'score_cvss', 'score_cps', 'group_description',
        'group_differentiator', 'os_family', 'os_name', 'asset_type'
    ))

    # Convert to DataFrame
    df = pd.DataFrame(data)
    df['vulnerability_title'] = ''

    if ('group_description' in df) and ('group_differentiator' in df):
        df['vulnerability_title'] = df.get('group_description') + ' ' + df.get('group_differentiator')

    # Define the desired column order
    desired_order = [
        'address', 'ip', 'vulnerability_title', 'asset_type', 'severity', 'description', 'location',
        'cve_number', 'remedy', 'references', 'score_cvss', 'score_cps', 'group_description',
        'group_differentiator', 'os_family', 'os_name',
    ]

    # Reorder the DataFrame columns
    df = df.reindex(columns=desired_order)

    # Manage column names
    df.columns = [col.replace('_', ' ').title() for col in df.columns]

    df.rename(columns={
        'Cve Number': 'CVE Number',
        'Ip': 'IP',
        'Os Family': 'OS Family',
        'Os Name': 'OS Name',
        'Score Cps': 'CPS Score',
        'Score Cvss': 'CVSS Score'
    }, inplace=True)

    # Use BytesIO buffer instead of HttpResponse
    output = BytesIO()

    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, sheet_name="Vulnerabilities", index=False)

    # Seek to the beginning of the stream before returning
    output.seek(0)
    return output


def preselect_vulnerabilities(threat_profile_id: int, asset_type: str) -> List[int]:
    # Step 1: Fetch vulnerabilities associated with a threat profile
    initial_vulns = Vulnerabilities.objects.filter(
        asset_type=asset_type,
        score_cps__gt=0,
        threat_profile_id=threat_profile_id  # Include this if it's a valid field
    )

    # Step 2: Create a dict to hold the best vulnerability per "Unique" key
    unique_vulns = {}

    for vuln in initial_vulns:
        # Step 3: Generate the Unique key
        unique_key = f"{vuln.address}|{vuln.group_description}|{vuln.group_differentiator}|{vuln.location}"

        # Step 4: Keep the one with highest score_cps
        current_best = unique_vulns.get(unique_key)
        if not current_best or (vuln.score_cps or 0) > (current_best.score_cps or 0):
            unique_vulns[unique_key] = vuln

    # Step 5: Extract IDs of filtered vulnerabilities to use in your raw SQL query
    filtered_ids = [vuln.id for vuln in unique_vulns.values()]

    return filtered_ids


# IP Range validation

def ip_to_int(ip: str) -> int:
    parts = ip.split('.')
    if len(parts) != 4:
        raise ValueError('Invalid IP format')
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


def int_to_ip(ip_int: int) -> str:
    return '.'.join([
        str((ip_int >> 24) & 0xFF),
        str((ip_int >> 16) & 0xFF),
        str((ip_int >> 8) & 0xFF),
        str(ip_int & 0xFF)
    ])


def validate_ip_range(ip_range: str) -> Dict[str, Union[bool, str]]:
    """
    Validates an IP range string (e.g., '89.34.76.10/24').

    Returns a dict with keys:
      - 'valid': bool
      - 'error': Optional[str] (one of 'private', 'network', 'format')
      - 'correctNetwork': Optional[str] (present if error is 'network')
    """
    try:
        ip, subnet_str = ip_range.split('/')
        subnet: int = int(subnet_str)
        if not (0 <= subnet <= 32):
            return {'valid': False, 'error': 'format'}

        octets = ip.split('.')
        if len(octets) != 4:
            return {'valid': False, 'error': 'format'}
        octets_int = list(map(int, octets))
        for o in octets_int:
            if o < 0 or o > 255:
                return {'valid': False, 'error': 'format'}

        ip_int: int = ip_to_int(ip)

        # Private IP ranges check
        if (octets_int[0] == 10) or \
           (octets_int[0] == 172 and 16 <= octets_int[1] <= 31) or \
           (octets_int[0] == 192 and octets_int[1] == 168):
            return {'valid': False, 'error': 'private'}

        mask: int = (0xFFFFFFFF << (32 - subnet)) & 0xFFFFFFFF

        network_int: int = ip_int & mask
        if ip_int != network_int:
            correct_network: str = int_to_ip(network_int) + '/' + str(subnet)
            return {'valid': False, 'error': 'network', 'correctNetwork': correct_network}

        return {'valid': True}

    except Exception:
        return {'valid': False, 'error': 'format'}


def generate_dmarc_report(threat_profile):
    """
    Generate a comprehensive DMARC report for a profile with all domains

    Args:
        threat_profile: Threat profile instance

    Returns:
        dict: Formatted DMARC data for all domains
    """
    dmarc_data = []

    scan_results = DmarcScanResult.objects.filter(
        threat_profile=threat_profile,
        scan_status='success'
    ).order_by('domain')

    for result in scan_results:
        domain_data = {
            "dmarc_domain": result.domain,
            "risk_description": result.summary or "No risk description available.",
            "overall_score": str(result.overall_score) if result.overall_score is not None else "0",
            "Impersonation_score": str(result.impersonation_score) if result.impersonation_score is not None else "0",
            "privacy_score": str(result.privacy_score) if result.privacy_score is not None else "0",
            "branding_score": str(result.branding_score) if result.branding_score is not None else "0",
            "top_findings": result.get_top_findings()
        }

        dmarc_data.append(domain_data)

    return {
        "DMARC_data": dmarc_data
    }
