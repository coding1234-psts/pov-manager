"""
Unit tests for VDR API client
Tests all API interaction functions with mocked HTTP requests
"""
import pytest
from unittest import mock
from io import StringIO
import requests
from vdr.vdrapi import (
    VDRAPIError,
    _get_request_headers,
    _handle_response,
    create_tag,
    delete_tag,
    create_ip_range,
    get_ranges_by_tag,
    delete_range,
    get_ranges_and_delete_all,
    get_servers_by_tag,
    delete_server,
    get_servers_and_delete_all,
    get_websites_by_tag,
    delete_website,
    get_websites_and_delete_all,
    disable_range_schedule,
    disable_server_schedule,
    disable_website_schedule,
    disable_all_schedules,
    cleanup_tag_resources,
    generate_vulnerabilities_report,
    check_vulnerabilities_report_status,
    fetch_report,
)


@pytest.mark.unit
class TestRequestHelpers:
    """Test helper functions for API requests"""

    @mock.patch('vdr.vdrapi.settings')
    def test_get_request_headers(self, mock_settings):
        """Test request header generation"""
        mock_settings.VDR_ACCESS_TOKEN = 'test_token_12345'
        
        headers = _get_request_headers()
        
        assert headers['Content-Type'] == 'application/json'
        assert headers['Accept'] == 'application/json'
        assert headers['Authorization'] == 'Bearer test_token_12345'

    def test_handle_response_success(self):
        """Test successful response handling"""
        mock_response = mock.Mock()
        mock_response.json.return_value = {'id': 123, 'status': 'success'}
        mock_response.raise_for_status = mock.Mock()
        
        result = _handle_response(mock_response)
        
        assert result == {'id': 123, 'status': 'success'}
        mock_response.raise_for_status.assert_called_once()

    def test_handle_response_http_error(self):
        """Test HTTP error handling"""
        mock_response = mock.Mock()
        mock_response.status_code = 404
        mock_response.text = 'Not found'
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError()
        
        with pytest.raises(VDRAPIError) as exc_info:
            _handle_response(mock_response)
        
        assert 'API request failed with status 404' in str(exc_info.value)

    def test_handle_response_json_decode_error(self):
        """Test JSON decode error handling"""
        mock_response = mock.Mock()
        mock_response.raise_for_status = mock.Mock()
        mock_response.json.side_effect = ValueError('Invalid JSON')
        mock_response.text = 'Invalid response'
        
        with pytest.raises(VDRAPIError) as exc_info:
            _handle_response(mock_response)
        
        assert 'Failed to parse API response' in str(exc_info.value)

    def test_handle_response_network_error(self):
        """Test network error handling"""
        mock_response = mock.Mock()
        mock_response.raise_for_status.side_effect = requests.exceptions.ConnectionError('Network error')
        
        with pytest.raises(VDRAPIError) as exc_info:
            _handle_response(mock_response)
        
        assert 'API request failed' in str(exc_info.value)


@pytest.mark.unit
class TestTagOperations:
    """Test tag creation and deletion"""

    @mock.patch('vdr.vdrapi.requests.post')
    @mock.patch('vdr.vdrapi._get_request_headers')
    def test_create_tag_success(self, mock_headers, mock_post):
        """Test successful tag creation"""
        mock_headers.return_value = {'Authorization': 'Bearer token'}
        mock_response = mock.Mock()
        mock_response.json.return_value = {'id': 12345, 'label': 'test_tag'}
        mock_response.raise_for_status = mock.Mock()
        mock_post.return_value = mock_response
        
        tag_id = create_tag('test_tag')
        
        assert tag_id == 12345
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[1]['json'] == {"kind": "tag", "label": "test_tag"}

    @mock.patch('vdr.vdrapi.requests.post')
    @mock.patch('vdr.vdrapi._get_request_headers')
    def test_create_tag_missing_id(self, mock_headers, mock_post):
        """Test tag creation with missing ID in response"""
        mock_headers.return_value = {'Authorization': 'Bearer token'}
        mock_response = mock.Mock()
        mock_response.json.return_value = {'label': 'test_tag'}  # Missing 'id'
        mock_response.raise_for_status = mock.Mock()
        mock_post.return_value = mock_response
        
        with pytest.raises(VDRAPIError) as exc_info:
            create_tag('test_tag')
        
        assert 'Invalid response from create_tag API' in str(exc_info.value)

    @mock.patch('vdr.vdrapi.requests.delete')
    @mock.patch('vdr.vdrapi._get_request_headers')
    def test_delete_tag_success(self, mock_headers, mock_delete):
        """Test successful tag deletion"""
        mock_headers.return_value = {'Authorization': 'Bearer token'}
        mock_response = mock.Mock()
        mock_response.raise_for_status = mock.Mock()
        mock_delete.return_value = mock_response
        
        delete_tag(12345)
        
        mock_delete.assert_called_once()
        assert '12345' in mock_delete.call_args[0][0]

    @mock.patch('vdr.vdrapi.requests.delete')
    @mock.patch('vdr.vdrapi._get_request_headers')
    def test_delete_tag_failure(self, mock_headers, mock_delete):
        """Test tag deletion failure"""
        mock_headers.return_value = {'Authorization': 'Bearer token'}
        mock_response = mock.Mock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError('404')
        mock_delete.return_value = mock_response
        
        with pytest.raises(VDRAPIError) as exc_info:
            delete_tag(12345)
        
        assert 'Failed to delete tag' in str(exc_info.value)


@pytest.mark.unit
class TestIPRangeOperations:
    """Test IP range operations"""

    @mock.patch('vdr.vdrapi.requests.post')
    @mock.patch('vdr.vdrapi._get_request_headers')
    @mock.patch('vdr.vdrapi.settings')
    def test_create_ip_range_success(self, mock_settings, mock_headers, mock_post):
        """Test successful IP range creation"""
        mock_settings.VDR_TEAM_ID = 'team123'
        mock_headers.return_value = {'Authorization': 'Bearer token'}
        mock_response = mock.Mock()
        mock_response.json.return_value = {'id': 'range123', 'range': '8.8.8.0/24'}
        mock_response.raise_for_status = mock.Mock()
        mock_post.return_value = mock_response
        
        result = create_ip_range('8.8.8.0/24', 12345)
        
        assert result['id'] == 'range123'
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[1]['json']['range'] == '8.8.8.0/24'
        assert '12345' in call_args[1]['json']['tagIds']

    @mock.patch('vdr.vdrapi.requests.get')
    @mock.patch('vdr.vdrapi._get_request_headers')
    def test_get_ranges_by_tag(self, mock_headers, mock_get):
        """Test fetching ranges by tag"""
        mock_headers.return_value = {'Authorization': 'Bearer token'}
        mock_response = mock.Mock()
        mock_response.json.return_value = {
            'items': [
                {'id': 'range1', 'range': '8.8.8.0/24'},
                {'id': 'range2', 'range': '1.1.1.0/24'}
            ]
        }
        mock_response.raise_for_status = mock.Mock()
        mock_get.return_value = mock_response
        
        ranges = get_ranges_by_tag(12345)
        
        assert len(ranges) == 2
        assert ranges[0]['id'] == 'range1'

    @mock.patch('vdr.vdrapi.requests.delete')
    @mock.patch('vdr.vdrapi._get_request_headers')
    def test_delete_range_success(self, mock_headers, mock_delete):
        """Test successful range deletion"""
        mock_headers.return_value = {'Authorization': 'Bearer token'}
        mock_response = mock.Mock()
        mock_response.raise_for_status = mock.Mock()
        mock_delete.return_value = mock_response
        
        delete_range('range123')
        
        mock_delete.assert_called_once()

    @mock.patch('vdr.vdrapi.delete_range')
    @mock.patch('vdr.vdrapi.get_ranges_by_tag')
    def test_get_ranges_and_delete_all(self, mock_get_ranges, mock_delete_range):
        """Test deleting all ranges for a tag"""
        mock_get_ranges.return_value = [
            {'id': 'range1'},
            {'id': 'range2'},
            {'id': 'range3'}
        ]
        
        deleted_count = get_ranges_and_delete_all(12345)
        
        assert deleted_count == 3
        assert mock_delete_range.call_count == 3


@pytest.mark.unit
class TestServerOperations:
    """Test server operations"""

    @mock.patch('vdr.vdrapi.requests.get')
    @mock.patch('vdr.vdrapi._get_request_headers')
    def test_get_servers_by_tag(self, mock_headers, mock_get):
        """Test fetching servers by tag"""
        mock_headers.return_value = {'Authorization': 'Bearer token'}
        mock_response = mock.Mock()
        mock_response.json.return_value = {
            'items': [
                {'id': 'server1', 'ip': '192.168.1.1'},
                {'id': 'server2', 'ip': '192.168.1.2'}
            ]
        }
        mock_response.raise_for_status = mock.Mock()
        mock_get.return_value = mock_response
        
        servers = get_servers_by_tag(12345)
        
        assert len(servers) == 2

    @mock.patch('vdr.vdrapi.requests.delete')
    @mock.patch('vdr.vdrapi._get_request_headers')
    def test_delete_server_success(self, mock_headers, mock_delete):
        """Test successful server deletion"""
        mock_headers.return_value = {'Authorization': 'Bearer token'}
        mock_response = mock.Mock()
        mock_response.raise_for_status = mock.Mock()
        mock_delete.return_value = mock_response
        
        delete_server('server123')
        
        mock_delete.assert_called_once()

    @mock.patch('vdr.vdrapi.delete_server')
    @mock.patch('vdr.vdrapi.get_servers_by_tag')
    def test_get_servers_and_delete_all(self, mock_get_servers, mock_delete_server):
        """Test deleting all servers for a tag"""
        mock_get_servers.return_value = [
            {'id': 'server1'},
            {'id': 'server2'}
        ]
        
        deleted_count = get_servers_and_delete_all(12345)
        
        assert deleted_count == 2
        assert mock_delete_server.call_count == 2


@pytest.mark.unit
class TestWebsiteOperations:
    """Test website operations"""

    @mock.patch('vdr.vdrapi.requests.get')
    @mock.patch('vdr.vdrapi._get_request_headers')
    def test_get_websites_by_tag(self, mock_headers, mock_get):
        """Test fetching websites by tag"""
        mock_headers.return_value = {'Authorization': 'Bearer token'}
        mock_response = mock.Mock()
        mock_response.json.return_value = {
            'items': [
                {'id': 'website1', 'url': 'https://example.com'}
            ]
        }
        mock_response.raise_for_status = mock.Mock()
        mock_get.return_value = mock_response
        
        websites = get_websites_by_tag(12345)
        
        assert len(websites) == 1

    @mock.patch('vdr.vdrapi.requests.delete')
    @mock.patch('vdr.vdrapi._get_request_headers')
    def test_delete_website_success(self, mock_headers, mock_delete):
        """Test successful website deletion"""
        mock_headers.return_value = {'Authorization': 'Bearer token'}
        mock_response = mock.Mock()
        mock_response.raise_for_status = mock.Mock()
        mock_delete.return_value = mock_response
        
        delete_website('website123')
        
        mock_delete.assert_called_once()

    @mock.patch('vdr.vdrapi.delete_website')
    @mock.patch('vdr.vdrapi.get_websites_by_tag')
    def test_get_websites_and_delete_all(self, mock_get_websites, mock_delete_website):
        """Test deleting all websites for a tag"""
        mock_get_websites.return_value = [
            {'id': 'website1'},
            {'id': 'website2'},
            {'id': 'website3'}
        ]
        
        deleted_count = get_websites_and_delete_all(12345)
        
        assert deleted_count == 3
        assert mock_delete_website.call_count == 3


@pytest.mark.unit
class TestScheduleOperations:
    """Test schedule disable operations"""

    @mock.patch('vdr.vdrapi.requests.patch')
    @mock.patch('vdr.vdrapi._get_request_headers')
    def test_disable_range_schedule(self, mock_headers, mock_patch):
        """Test disabling range schedule"""
        mock_headers.return_value = {'Authorization': 'Bearer token'}
        mock_response = mock.Mock()
        mock_response.raise_for_status = mock.Mock()
        mock_patch.return_value = mock_response
        
        disable_range_schedule('range123')
        
        mock_patch.assert_called_once()
        call_args = mock_patch.call_args
        assert call_args[1]['json']['schedule']['period'] == 'none'

    @mock.patch('vdr.vdrapi.requests.patch')
    @mock.patch('vdr.vdrapi._get_request_headers')
    def test_disable_server_schedule(self, mock_headers, mock_patch):
        """Test disabling server schedule"""
        mock_headers.return_value = {'Authorization': 'Bearer token'}
        mock_response = mock.Mock()
        mock_response.raise_for_status = mock.Mock()
        mock_patch.return_value = mock_response
        
        disable_server_schedule('server123')
        
        mock_patch.assert_called_once()

    @mock.patch('vdr.vdrapi.requests.patch')
    @mock.patch('vdr.vdrapi._get_request_headers')
    def test_disable_website_schedule(self, mock_headers, mock_patch):
        """Test disabling website schedule"""
        mock_headers.return_value = {'Authorization': 'Bearer token'}
        mock_response = mock.Mock()
        mock_response.raise_for_status = mock.Mock()
        mock_patch.return_value = mock_response
        
        disable_website_schedule('website123')
        
        mock_patch.assert_called_once()

    @mock.patch('vdr.vdrapi.disable_all_website_schedules')
    @mock.patch('vdr.vdrapi.disable_all_server_schedules')
    @mock.patch('vdr.vdrapi.disable_all_range_schedules')
    def test_disable_all_schedules(self, mock_ranges, mock_servers, mock_websites):
        """Test disabling all schedules for a tag"""
        mock_ranges.return_value = 2
        mock_servers.return_value = 3
        mock_websites.return_value = 1
        
        results = disable_all_schedules(12345)
        
        assert results['ranges_disabled'] == 2
        assert results['servers_disabled'] == 3
        assert results['websites_disabled'] == 1


@pytest.mark.unit
class TestCleanupOperations:
    """Test cleanup operations"""

    @mock.patch('vdr.vdrapi.delete_tag')
    @mock.patch('vdr.vdrapi.get_websites_and_delete_all')
    @mock.patch('vdr.vdrapi.get_servers_and_delete_all')
    @mock.patch('vdr.vdrapi.get_ranges_and_delete_all')
    def test_cleanup_tag_resources_with_tag_deletion(
        self, mock_ranges, mock_servers, mock_websites, mock_delete_tag
    ):
        """Test cleanup with tag deletion"""
        mock_ranges.return_value = 2
        mock_servers.return_value = 3
        mock_websites.return_value = 1
        
        results = cleanup_tag_resources(12345, delete_tag_after=True)
        
        assert results['ranges_deleted'] == 2
        assert results['servers_deleted'] == 3
        assert results['websites_deleted'] == 1
        assert results['tag_deleted'] is True
        mock_delete_tag.assert_called_once_with(12345)

    @mock.patch('vdr.vdrapi.delete_tag')
    @mock.patch('vdr.vdrapi.get_websites_and_delete_all')
    @mock.patch('vdr.vdrapi.get_servers_and_delete_all')
    @mock.patch('vdr.vdrapi.get_ranges_and_delete_all')
    def test_cleanup_tag_resources_without_tag_deletion(
        self, mock_ranges, mock_servers, mock_websites, mock_delete_tag
    ):
        """Test cleanup without tag deletion"""
        mock_ranges.return_value = 1
        mock_servers.return_value = 1
        mock_websites.return_value = 1
        
        results = cleanup_tag_resources(12345, delete_tag_after=False)
        
        assert results['tag_deleted'] is False
        mock_delete_tag.assert_not_called()


@pytest.mark.unit
class TestReportOperations:
    """Test vulnerability report operations"""

    @mock.patch('vdr.vdrapi.requests.post')
    @mock.patch('vdr.vdrapi._get_request_headers')
    def test_generate_vulnerabilities_report(self, mock_headers, mock_post):
        """Test vulnerability report generation"""
        mock_headers.return_value = {'Authorization': 'Bearer token'}
        mock_response = mock.Mock()
        mock_response.json.return_value = {'id': 'report123'}
        mock_response.raise_for_status = mock.Mock()
        mock_post.return_value = mock_response
        
        report_id = generate_vulnerabilities_report(12345)
        
        assert report_id == 'report123'
        call_args = mock_post.call_args
        assert call_args[1]['json']['fileFormat'] == 'csv'

    @mock.patch('vdr.vdrapi.requests.get')
    @mock.patch('vdr.vdrapi._get_request_headers')
    def test_check_report_status_done(self, mock_headers, mock_get):
        """Test checking report status when done"""
        mock_headers.return_value = {'Authorization': 'Bearer token'}
        mock_response = mock.Mock()
        mock_response.json.return_value = {
            'status': 'done',
            'fileLocation': 'reports/file123.csv'
        }
        mock_response.raise_for_status = mock.Mock()
        mock_get.return_value = mock_response
        
        status, location = check_vulnerabilities_report_status('report123')
        
        assert status == 'done'
        assert location == 'reports/file123.csv'

    @mock.patch('vdr.vdrapi.requests.get')
    @mock.patch('vdr.vdrapi._get_request_headers')
    def test_check_report_status_pending(self, mock_headers, mock_get):
        """Test checking report status when pending"""
        mock_headers.return_value = {'Authorization': 'Bearer token'}
        mock_response = mock.Mock()
        mock_response.json.return_value = {
            'status': 'pending',
            'fileLocation': None
        }
        mock_response.raise_for_status = mock.Mock()
        mock_get.return_value = mock_response
        
        status, location = check_vulnerabilities_report_status('report123')
        
        assert status == 'pending'
        assert location is None

    @mock.patch('vdr.vdrapi.requests.get')
    @mock.patch('vdr.vdrapi._get_request_headers')
    def test_fetch_report_success(self, mock_headers, mock_get):
        """Test fetching a report file"""
        mock_headers.return_value = {'Authorization': 'Bearer token'}
        mock_response = mock.Mock()
        mock_response.encoding = 'utf-8'
        mock_response.raise_for_status = mock.Mock()
        mock_response.iter_content.return_value = [
            b'address,ip,severity\n',
            b'192.168.1.1,192.168.1.1,critical\n'
        ]
        mock_get.return_value = mock_response
        
        result = fetch_report('reports/file123.csv')
        
        assert isinstance(result, StringIO)
        content = result.read()
        assert 'address,ip,severity' in content
        assert '192.168.1.1' in content

    @mock.patch('vdr.vdrapi.requests.get')
    @mock.patch('vdr.vdrapi._get_request_headers')
    def test_fetch_report_decode_error(self, mock_headers, mock_get):
        """Test fetch report with decode error"""
        mock_headers.return_value = {'Authorization': 'Bearer token'}
        mock_response = mock.Mock()
        mock_response.encoding = 'utf-8'
        mock_response.raise_for_status = mock.Mock()
        mock_response.iter_content.return_value = [b'\xff\xfe']  # Invalid UTF-8
        mock_get.return_value = mock_response
        
        with pytest.raises(VDRAPIError) as exc_info:
            fetch_report('reports/file123.csv')
        
        assert 'Failed to decode report content' in str(exc_info.value)


