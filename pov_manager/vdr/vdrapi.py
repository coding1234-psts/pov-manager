import codecs
import requests
from io import StringIO
from django.conf import settings
from django.utils import timezone
from typing import Tuple, Optional, List, Dict, Any
import logging
import json

logger = logging.getLogger(__name__)

# Constants
REQUEST_TIMEOUT = 300
BASE_URL = 'https://us1.vdr.secureworks.com'
TAGS_ENDPOINT = f'{BASE_URL}/api/v2/tags'
IP_RANGES_ENDPOINT = f'{BASE_URL}/api/v2/ranges'
SERVERS_ENDPOINT = f'{BASE_URL}/api/v2/servers'
WEBSITES_ENDPOINT = f'{BASE_URL}/api/v2/websites'
GENERATE_REPORT_ENDPOINT = f'{BASE_URL}/api/v2/vulnerability-groups/export'
CHECK_REPORT_STATUS_ENDPOINT = f'{BASE_URL}/api/v2/exports'


class VDRAPIError(Exception):
    """Custom exception for VDR API errors"""
    pass


def _get_request_headers() -> dict:
    """Generate request headers with authorization"""
    return {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': f'Bearer {settings.VDR_ACCESS_TOKEN}'
    }


def _handle_response(response: requests.Response) -> dict:
    """
    Handle API response and raise appropriate errors

    Args:
        response: requests Response object

    Returns:
        Parsed JSON response

    Raises:
        VDRAPIError: If the request failed
    """
    try:
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error occurred: {e}, Response: {response.text}")
        raise VDRAPIError(f"API request failed with status {response.status_code}: {response.text}") from e
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error occurred: {e}")
        raise VDRAPIError(f"API request failed: {str(e)}") from e
    except ValueError as e:
        logger.error(f"JSON decode error: {e}, Response: {response.text}")
        raise VDRAPIError("Failed to parse API response") from e


def create_tag(name: str) -> int:
    """
    Create a new tag in VDR

    Args:
        name: Tag label/name

    Returns:
        Created tag ID

    Raises:
        VDRAPIError: If the API request fails
    """
    try:
        resp = requests.post(
            TAGS_ENDPOINT,
            headers=_get_request_headers(),
            json={"kind": "tag", "label": name},
            timeout=REQUEST_TIMEOUT
        )
        tag = _handle_response(resp)
        return tag['id']
    except KeyError as e:
        logger.error(f"Unexpected response structure: missing 'id' field")
        raise VDRAPIError("Invalid response from create_tag API") from e


def delete_tag(tag_id: int) -> None:
    """
    Delete a tag from VDR

    Args:
        tag_id: Tag ID to delete

    Raises:
        VDRAPIError: If the API request fails
    """
    url = f'{TAGS_ENDPOINT}/{tag_id}'

    try:
        resp = requests.delete(
            url,
            headers=_get_request_headers(),
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        logger.info(f"Successfully deleted tag: {tag_id}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to delete tag {tag_id}: {e}")
        raise VDRAPIError(f"Failed to delete tag {tag_id}: {str(e)}") from e


def create_ip_range(iprange: str, tag_id: int) -> dict:
    """
    Create an IP range in VDR with scanning schedule

    Args:
        iprange: IP range string (e.g., "192.168.1.0/24")
        tag_id: Tag ID to associate with this range

    Returns:
        Created IP range object

    Raises:
        VDRAPIError: If the API request fails
    """
    url = f'{IP_RANGES_ENDPOINT}?request_scan=true'

    # Use timezone-aware datetime
    now = timezone.now()
    scan_start = now + timezone.timedelta(hours=2)
    scan_end = now + timezone.timedelta(hours=4)

    schedule_start_time = scan_start.strftime('%H:00')

    payload = {
        "kind": "range",
        "description": "Added via API",
        "range": iprange,
        "teamId": settings.VDR_TEAM_ID,
        "schedule": {
            "period": "daily",
            "startTime": schedule_start_time
        },
        "discoverySchedule": {
            "period": "daily",
            "startTime": {
                "fromHour": int(scan_start.strftime('%H')),
                "untilHour": int(scan_end.strftime('%H'))
            }
        },
        "tagIds": [str(tag_id)]
    }

    try:
        resp = requests.post(
            url,
            headers=_get_request_headers(),
            json=payload,
            timeout=REQUEST_TIMEOUT
        )
        return _handle_response(resp)
    except Exception as e:
        logger.error(f"Failed to create IP range {iprange}: {e}")
        raise


def get_ranges_by_tag(tag_id: int) -> List[Dict[str, Any]]:
    """
    Get all IP ranges associated with a specific tag

    Args:
        tag_id: Tag ID to query ranges for

    Returns:
        List of IP range objects

    Raises:
        VDRAPIError: If the API request fails
    """
    params = {'q': json.dumps({"tag": {"id": int(tag_id)}})}

    try:
        resp = requests.get(
            IP_RANGES_ENDPOINT,
            headers=_get_request_headers(),
            params=params,
            timeout=REQUEST_TIMEOUT
        )
        response_data = _handle_response(resp)
        return response_data.get("items", [])
    except Exception as e:
        logger.error(f"Failed to get ranges for tag {tag_id}: {e}")
        raise


def delete_range(range_id: str) -> None:
    """
    Delete a specific IP range

    Args:
        range_id: Range ID to delete

    Raises:
        VDRAPIError: If the API request fails
    """
    url = f'{IP_RANGES_ENDPOINT}/{range_id}'

    try:
        resp = requests.delete(
            url,
            headers=_get_request_headers(),
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        logger.info(f"Successfully deleted range: {range_id}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to delete range {range_id}: {e}")
        raise VDRAPIError(f"Failed to delete range {range_id}: {str(e)}") from e


def get_ranges_and_delete_all(tag_id: int) -> int:
    """
    Get all IP ranges for a tag and delete them all

    Args:
        tag_id: Tag ID to query and delete ranges for

    Returns:
        Number of ranges deleted

    Raises:
        VDRAPIError: If any API request fails
    """
    ranges = get_ranges_by_tag(tag_id)
    deleted_count = 0

    for range_item in ranges:
        range_id = range_item.get("id")
        if range_id:
            try:
                delete_range(range_id)
                deleted_count += 1
            except VDRAPIError as e:
                logger.warning(f"Failed to delete range {range_id}, continuing: {e}")

    logger.info(f"Deleted {deleted_count} ranges for tag {tag_id}")
    return deleted_count


def get_servers_by_tag(tag_id: int) -> List[Dict[str, Any]]:
    """
    Get all servers associated with a specific tag

    Args:
        tag_id: Tag ID to query servers for

    Returns:
        List of server objects

    Raises:
        VDRAPIError: If the API request fails
    """
    params = {'q': json.dumps({"tag": {"id": int(tag_id)}})}

    try:
        resp = requests.get(
            SERVERS_ENDPOINT,
            headers=_get_request_headers(),
            params=params,
            timeout=REQUEST_TIMEOUT
        )
        response_data = _handle_response(resp)
        return response_data.get("items", [])
    except Exception as e:
        logger.error(f"Failed to get servers for tag {tag_id}: {e}")
        raise


def delete_server(server_id: str) -> None:
    """
    Delete a specific server

    Args:
        server_id: Server ID to delete

    Raises:
        VDRAPIError: If the API request fails
    """
    url = f'{SERVERS_ENDPOINT}/{server_id}'

    try:
        resp = requests.delete(
            url,
            headers=_get_request_headers(),
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        logger.info(f"Successfully deleted server: {server_id}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to delete server {server_id}: {e}")
        raise VDRAPIError(f"Failed to delete server {server_id}: {str(e)}") from e


def get_servers_and_delete_all(tag_id: int) -> int:
    """
    Get all servers for a tag and delete them all

    Args:
        tag_id: Tag ID to query and delete servers for

    Returns:
        Number of servers deleted

    Raises:
        VDRAPIError: If any API request fails
    """
    servers = get_servers_by_tag(tag_id)
    deleted_count = 0

    for server_item in servers:
        server_id = server_item.get("id")
        if server_id:
            try:
                delete_server(server_id)
                deleted_count += 1
            except VDRAPIError as e:
                logger.warning(f"Failed to delete server {server_id}, continuing: {e}")

    logger.info(f"Deleted {deleted_count} servers for tag {tag_id}")
    return deleted_count


def get_websites_by_tag(tag_id: int) -> List[Dict[str, Any]]:
    """
    Get all websites associated with a specific tag

    Args:
        tag_id: Tag ID to query websites for

    Returns:
        List of website objects

    Raises:
        VDRAPIError: If the API request fails
    """
    params = {'q': json.dumps({"tag": {"id": int(tag_id)}})}

    try:
        resp = requests.get(
            WEBSITES_ENDPOINT,
            headers=_get_request_headers(),
            params=params,
            timeout=REQUEST_TIMEOUT
        )
        response_data = _handle_response(resp)
        return response_data.get("items", [])
    except Exception as e:
        logger.error(f"Failed to get websites for tag {tag_id}: {e}")
        raise


def delete_website(website_id: str) -> None:
    """
    Delete a specific website

    Args:
        website_id: Website ID to delete

    Raises:
        VDRAPIError: If the API request fails
    """
    url = f'{WEBSITES_ENDPOINT}/{website_id}'

    try:
        resp = requests.delete(
            url,
            headers=_get_request_headers(),
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        logger.info(f"Successfully deleted website: {website_id}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to delete website {website_id}: {e}")
        raise VDRAPIError(f"Failed to delete website {website_id}: {str(e)}") from e


def get_websites_and_delete_all(tag_id: int) -> int:
    """
    Get all websites for a tag and delete them all

    Args:
        tag_id: Tag ID to query and delete websites for

    Returns:
        Number of websites deleted

    Raises:
        VDRAPIError: If any API request fails
    """
    websites = get_websites_by_tag(tag_id)
    deleted_count = 0

    for website_item in websites:
        website_id = website_item.get("id")
        if website_id:
            try:
                delete_website(website_id)
                deleted_count += 1
            except VDRAPIError as e:
                logger.warning(f"Failed to delete website {website_id}, continuing: {e}")

    logger.info(f"Deleted {deleted_count} websites for tag {tag_id}")
    return deleted_count


def disable_range_schedule(range_id: str, limit: int = 200) -> None:
    """
    Disable the discovery schedule for a specific IP range

    Args:
        range_id: Range ID to disable schedule for
        limit: Query limit parameter (default: 200)

    Raises:
        VDRAPIError: If the API request fails
    """
    url = f'{IP_RANGES_ENDPOINT}/{range_id}'
    
    payload = {
        "kind": "range",
        "id": range_id,
        "fields": "schedule",
        "description": "Schedule disabled via API",
        "schedule": {
            "period": "none"
        }
    }
    
    try:
        resp = requests.patch(
            url,
            headers=_get_request_headers(),
            json=payload,
            params={'limit': limit},
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        logger.info(f"Successfully disabled schedule for range: {range_id}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to disable schedule for range {range_id}: {e}")
        raise VDRAPIError(f"Failed to disable range schedule {range_id}: {str(e)}") from e


def disable_server_schedule(server_id: str, limit: int = 1000) -> None:
    """
    Disable the vulnerability scan schedule for a specific server

    Args:
        server_id: Server ID to disable schedule for
        limit: Query limit parameter (default: 1000)

    Raises:
        VDRAPIError: If the API request fails
    """
    url = f'{SERVERS_ENDPOINT}/{server_id}'
    
    payload = {
        "kind": "server",
        "id": server_id,
        "fields": "schedule",
        "schedule": {
            "period": "none",
            "kill_time": "never"
        }
    }
    
    try:
        resp = requests.patch(
            url,
            headers=_get_request_headers(),
            json=payload,
            params={'limit': limit},
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        logger.info(f"Successfully disabled schedule for server: {server_id}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to disable schedule for server {server_id}: {e}")
        raise VDRAPIError(f"Failed to disable server schedule {server_id}: {str(e)}") from e


def disable_website_schedule(website_id: str, limit: int = 1000) -> None:
    """
    Disable the scan schedule for a specific website

    Args:
        website_id: Website ID to disable schedule for
        limit: Query limit parameter (default: 1000)

    Raises:
        VDRAPIError: If the API request fails
    """
    url = f'{WEBSITES_ENDPOINT}/{website_id}'
    
    payload = {
        "kind": "website",
        "id": website_id,
        "fields": "schedule",
        "schedule": {
            "period": "none",
            "kill_time": "never"
        }
    }
    
    try:
        resp = requests.patch(
            url,
            headers=_get_request_headers(),
            json=payload,
            params={'limit': limit},
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        logger.info(f"Successfully disabled schedule for website: {website_id}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to disable schedule for website {website_id}: {e}")
        raise VDRAPIError(f"Failed to disable website schedule {website_id}: {str(e)}") from e


def disable_all_range_schedules(tag_id: int) -> int:
    """
    Get all IP ranges for a tag and disable their discovery schedules

    Args:
        tag_id: Tag ID to query and disable range schedules for

    Returns:
        Number of range schedules disabled

    Raises:
        VDRAPIError: If any API request fails
    """
    ranges = get_ranges_by_tag(tag_id)
    disabled_count = 0
    
    for range_item in ranges:
        range_id = range_item.get("id")
        if range_id:
            try:
                disable_range_schedule(range_id)
                disabled_count += 1
            except VDRAPIError as e:
                logger.warning(f"Failed to disable schedule for range {range_id}, continuing: {e}")
    
    logger.info(f"Disabled {disabled_count} range schedules for tag {tag_id}")
    return disabled_count


def disable_all_server_schedules(tag_id: int) -> int:
    """
    Get all servers for a tag and disable their scan schedules

    Args:
        tag_id: Tag ID to query and disable server schedules for

    Returns:
        Number of server schedules disabled

    Raises:
        VDRAPIError: If any API request fails
    """
    servers = get_servers_by_tag(tag_id)
    disabled_count = 0
    
    for server_item in servers:
        server_id = server_item.get("id")
        if server_id:
            try:
                disable_server_schedule(server_id)
                disabled_count += 1
            except VDRAPIError as e:
                logger.warning(f"Failed to disable schedule for server {server_id}, continuing: {e}")
    
    logger.info(f"Disabled {disabled_count} server schedules for tag {tag_id}")
    return disabled_count


def disable_all_website_schedules(tag_id: int) -> int:
    """
    Get all websites for a tag and disable their scan schedules

    Args:
        tag_id: Tag ID to query and disable website schedules for

    Returns:
        Number of website schedules disabled

    Raises:
        VDRAPIError: If any API request fails
    """
    websites = get_websites_by_tag(tag_id)
    disabled_count = 0
    
    for website_item in websites:
        website_id = website_item.get("id")
        if website_id:
            try:
                disable_website_schedule(website_id)
                disabled_count += 1
            except VDRAPIError as e:
                logger.warning(f"Failed to disable schedule for website {website_id}, continuing: {e}")
    
    logger.info(f"Disabled {disabled_count} website schedules for tag {tag_id}")
    return disabled_count


def disable_all_schedules(tag_id: int) -> Dict[str, int]:
    """
    Disable all scan schedules (ranges, servers, websites) for a tag
    This stops all ongoing and future scans while preserving the discovered assets

    Args:
        tag_id: Tag ID to disable all schedules for

    Returns:
        Dictionary with counts of disabled schedules

    Raises:
        VDRAPIError: If any API request fails
    """
    results = {
        'ranges_disabled': 0,
        'servers_disabled': 0,
        'websites_disabled': 0
    }
    
    try:
        results['ranges_disabled'] = disable_all_range_schedules(tag_id)
        results['servers_disabled'] = disable_all_server_schedules(tag_id)
        results['websites_disabled'] = disable_all_website_schedules(tag_id)
        
        logger.info(f"Disabled all schedules for tag {tag_id}: {results}")
        return results
    except Exception as e:
        logger.error(f"Error during schedule disabling for tag {tag_id}: {e}")
        raise


def cleanup_tag_resources(tag_id: int, delete_tag_after: bool = False) -> Dict[str, int]:
    """
    Delete all resources (ranges, servers, websites) associated with a tag
    Optionally delete the tag itself after cleanup

    Args:
        tag_id: Tag ID to cleanup
        delete_tag_after: If True, delete the tag after deleting all resources

    Returns:
        Dictionary with counts of deleted resources

    Raises:
        VDRAPIError: If any API request fails
    """
    results = {
        'ranges_deleted': 0,
        'servers_deleted': 0,
        'websites_deleted': 0,
        'tag_deleted': False
    }

    try:
        results['ranges_deleted'] = get_ranges_and_delete_all(tag_id)
        results['servers_deleted'] = get_servers_and_delete_all(tag_id)
        results['websites_deleted'] = get_websites_and_delete_all(tag_id)

        if delete_tag_after:
            delete_tag(tag_id)
            results['tag_deleted'] = True

        logger.info(f"Cleanup completed for tag {tag_id}: {results}")
        return results
    except Exception as e:
        logger.error(f"Error during cleanup of tag {tag_id}: {e}")
        raise


def generate_vulnerabilities_report(tag_id: int) -> str:
    """
    Generate a vulnerability report for a specific tag

    Args:
        tag_id: Tag ID to generate report for

    Returns:
        Report request ID

    Raises:
        VDRAPIError: If the API request fails
    """
    payload = {
        "kind": "export",
        "fileFormat": "csv",
        "query": {"tag": {"id": str(tag_id)}}
    }

    try:
        resp = requests.post(
            GENERATE_REPORT_ENDPOINT,
            headers=_get_request_headers(),
            json=payload,
            timeout=REQUEST_TIMEOUT
        )
        report_request = _handle_response(resp)
        return report_request['id']
    except KeyError as e:
        logger.error(f"Unexpected response structure: missing 'id' field")
        raise VDRAPIError("Invalid response from generate_vulnerabilities_report API") from e


def check_vulnerabilities_report_status(report_request_id: str) -> Tuple[str, Optional[str]]:
    """
    Check the status of a vulnerability report generation request

    Args:
        report_request_id: Report request ID

    Returns:
        Tuple of (status, file_url_location)
        file_url_location will be None if report is not ready

    Raises:
        VDRAPIError: If the API request fails
    """
    url = f'{CHECK_REPORT_STATUS_ENDPOINT}/{report_request_id}'

    try:
        resp = requests.get(
            url,
            headers=_get_request_headers(),
            timeout=REQUEST_TIMEOUT
        )
        report_request = _handle_response(resp)

        status = report_request.get("status")
        file_url_location = report_request.get("fileLocation")

        if status is None:
            raise VDRAPIError("Status field missing from report status response")

        return status, file_url_location
    except Exception as e:
        logger.error(f"Failed to check report status for {report_request_id}: {e}")
        raise


def fetch_report(file_url_location: str) -> StringIO:
    """
    Download a generated vulnerability report

    Args:
        file_url_location: Relative URL path to the report file

    Returns:
        StringIO buffer containing the CSV report

    Raises:
        VDRAPIError: If the download fails

    Note:
        For large reports, consider streaming to a file instead of loading into memory
    """
    url = f'{BASE_URL}/{file_url_location}'

    try:
        resp = requests.get(
            url,
            headers=_get_request_headers(),
            stream=True,
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()

        buffer = StringIO()
        # Use codecs to properly handle multi-byte characters across chunk boundaries
        encoding = resp.encoding or 'utf-8'
        decoder = codecs.getincrementaldecoder(encoding)(errors='strict')

        for chunk in resp.iter_content(chunk_size=8192, decode_unicode=False):
            if chunk:
                decoded = decoder.decode(chunk, False)
                buffer.write(decoded)

        # Flush any remaining bytes
        buffer.write(decoder.decode(b'', True))
        buffer.seek(0)
        return buffer

    except (UnicodeDecodeError, LookupError) as e:
        logger.error(f"Failed to decode report content from {file_url_location}: {e}")
        raise VDRAPIError(f"Failed to decode report content: {str(e)}") from e
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch report from {file_url_location}: {e}")
        raise VDRAPIError(f"Failed to download report: {str(e)}") from e