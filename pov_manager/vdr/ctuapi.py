import requests
from typing import Dict, Any, Optional

from django.conf import settings


def _get_request_headers() -> Dict[str, str]:
    """Generate request headers with current settings."""
    return {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-agent': 'povmanager',
        'x-api-key': settings.CTU_ACCESS_TOKEN,
    }


def submit_new_report(data: Dict[str, Any]) -> Optional[str]:
    """Submits a new report and returns the report ID."""
    url = f'{settings.CTU_BASE_URL}/api/report/new'
    try:
        resp = requests.post(url, json=data, headers=_get_request_headers(), timeout=300)
        report = resp.json()
        return report.get("id")
    except (requests.RequestException, ValueError) as e:
        print(f"Error submitting report: {e}")
        return None


def report_status(report_id: str) -> Optional[str]:
    """Retrieves the status of a report by its ID."""
    url = f'{settings.CTU_BASE_URL}/api/report/{report_id}/status'
    try:
        resp = requests.get(url, headers=_get_request_headers(), timeout=300)
        report = resp.json()
        return report.get(report_id, {}).get('progress')
    except (requests.RequestException, ValueError) as e:
        print(f"Error retrieving report status: {e}")
        return None


def download_report(report_id: str, path: str) -> bool:
    """Downloads a report and saves it to the given path."""
    url = f'{settings.CTU_BASE_URL}/api/report/{report_id}/download'
    chunk_size = 128
    try:
        resp = requests.get(url, headers=_get_request_headers(), stream=True, timeout=300)
        with open(path, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=chunk_size):
                if chunk:
                    f.write(chunk)
        return True
    except (requests.RequestException, IOError) as e:
        print(f"Error downloading report: {e}")
        return False
