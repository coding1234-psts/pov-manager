"""
Unit tests for CTU API client
Tests CTU autobrief API interaction functions with mocked HTTP requests
"""
import pytest
from unittest import mock
import requests
from vdr.ctuapi import (
    submit_new_report,
    report_status,
    download_report,
)


@pytest.mark.unit
class TestCTUAPISubmitReport:
    """Test CTU report submission"""

    @mock.patch('vdr.ctuapi.requests.post')
    @mock.patch('vdr.ctuapi.settings')
    def test_submit_new_report_success(self, mock_settings, mock_post):
        """Test successful report submission"""
        mock_settings.CTU_BASE_URL = 'https://ctu.example.com'
        mock_settings.CTU_ACCESS_TOKEN = 'test_token'
        
        mock_response = mock.Mock()
        mock_response.json.return_value = {'id': 'report_12345'}
        mock_post.return_value = mock_response
        
        test_data = {
            'client_name': 'Test Client',
            'domains': ['example.com'],
            'email_domains': ['example.com']
        }
        
        report_id = submit_new_report(test_data)
        
        assert report_id == 'report_12345'
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[1]['json'] == test_data
        assert call_args[1]['headers']['x-api-key'] == 'test_token'

    @mock.patch('vdr.ctuapi.requests.post')
    @mock.patch('vdr.ctuapi.settings')
    def test_submit_new_report_no_id_in_response(self, mock_settings, mock_post):
        """Test report submission when response has no ID"""
        mock_settings.CTU_BASE_URL = 'https://ctu.example.com'
        mock_settings.CTU_ACCESS_TOKEN = 'test_token'
        
        mock_response = mock.Mock()
        mock_response.json.return_value = {'status': 'created'}  # Missing 'id'
        mock_post.return_value = mock_response
        
        report_id = submit_new_report({'client_name': 'Test'})
        
        assert report_id is None

    @mock.patch('vdr.ctuapi.requests.post')
    @mock.patch('vdr.ctuapi.settings')
    def test_submit_new_report_request_exception(self, mock_settings, mock_post):
        """Test report submission with request exception"""
        mock_settings.CTU_BASE_URL = 'https://ctu.example.com'
        mock_settings.CTU_ACCESS_TOKEN = 'test_token'
        
        mock_post.side_effect = requests.RequestException('Connection error')
        
        report_id = submit_new_report({'client_name': 'Test'})
        
        assert report_id is None

    @mock.patch('vdr.ctuapi.requests.post')
    @mock.patch('vdr.ctuapi.settings')
    def test_submit_new_report_json_decode_error(self, mock_settings, mock_post):
        """Test report submission with JSON decode error"""
        mock_settings.CTU_BASE_URL = 'https://ctu.example.com'
        mock_settings.CTU_ACCESS_TOKEN = 'test_token'
        
        mock_response = mock.Mock()
        mock_response.json.side_effect = ValueError('Invalid JSON')
        mock_post.return_value = mock_response
        
        report_id = submit_new_report({'client_name': 'Test'})
        
        assert report_id is None


@pytest.mark.unit
class TestCTUAPIReportStatus:
    """Test CTU report status checking"""

    @mock.patch('vdr.ctuapi.requests.get')
    @mock.patch('vdr.ctuapi.settings')
    def test_report_status_success(self, mock_settings, mock_get):
        """Test successful status check"""
        mock_settings.CTU_BASE_URL = 'https://ctu.example.com'
        mock_settings.CTU_ACCESS_TOKEN = 'test_token'
        
        mock_response = mock.Mock()
        mock_response.json.return_value = {
            'report_12345': {'progress': 'completed'}
        }
        mock_get.return_value = mock_response
        
        status = report_status('report_12345')
        
        assert status == 'completed'
        mock_get.assert_called_once()

    @mock.patch('vdr.ctuapi.requests.get')
    @mock.patch('vdr.ctuapi.settings')
    def test_report_status_in_progress(self, mock_settings, mock_get):
        """Test status check for in-progress report"""
        mock_settings.CTU_BASE_URL = 'https://ctu.example.com'
        mock_settings.CTU_ACCESS_TOKEN = 'test_token'
        
        mock_response = mock.Mock()
        mock_response.json.return_value = {
            'report_12345': {'progress': 'processing'}
        }
        mock_get.return_value = mock_response
        
        status = report_status('report_12345')
        
        assert status == 'processing'

    @mock.patch('vdr.ctuapi.requests.get')
    @mock.patch('vdr.ctuapi.settings')
    def test_report_status_missing_report_id(self, mock_settings, mock_get):
        """Test status check when report ID not in response"""
        mock_settings.CTU_BASE_URL = 'https://ctu.example.com'
        mock_settings.CTU_ACCESS_TOKEN = 'test_token'
        
        mock_response = mock.Mock()
        mock_response.json.return_value = {}  # Missing report_id
        mock_get.return_value = mock_response
        
        status = report_status('report_12345')
        
        assert status is None

    @mock.patch('vdr.ctuapi.requests.get')
    @mock.patch('vdr.ctuapi.settings')
    def test_report_status_request_exception(self, mock_settings, mock_get):
        """Test status check with request exception"""
        mock_settings.CTU_BASE_URL = 'https://ctu.example.com'
        mock_settings.CTU_ACCESS_TOKEN = 'test_token'
        
        mock_get.side_effect = requests.RequestException('Network error')
        
        status = report_status('report_12345')
        
        assert status is None

    @mock.patch('vdr.ctuapi.requests.get')
    @mock.patch('vdr.ctuapi.settings')
    def test_report_status_json_decode_error(self, mock_settings, mock_get):
        """Test status check with JSON decode error"""
        mock_settings.CTU_BASE_URL = 'https://ctu.example.com'
        mock_settings.CTU_ACCESS_TOKEN = 'test_token'
        
        mock_response = mock.Mock()
        mock_response.json.side_effect = ValueError('Invalid JSON')
        mock_get.return_value = mock_response
        
        status = report_status('report_12345')
        
        assert status is None


@pytest.mark.unit
class TestCTUAPIDownloadReport:
    """Test CTU report download"""

    @mock.patch('vdr.ctuapi.requests.get')
    @mock.patch('vdr.ctuapi.settings')
    @mock.patch('builtins.open', new_callable=mock.mock_open)
    def test_download_report_success(self, mock_open, mock_settings, mock_get):
        """Test successful report download"""
        mock_settings.CTU_BASE_URL = 'https://ctu.example.com'
        mock_settings.CTU_ACCESS_TOKEN = 'test_token'
        
        mock_response = mock.Mock()
        mock_response.iter_content.return_value = [b'chunk1', b'chunk2', b'chunk3']
        mock_get.return_value = mock_response
        
        result = download_report('report_12345', '/tmp/report.zip')
        
        assert result is True
        mock_get.assert_called_once()
        mock_open.assert_called_once_with('/tmp/report.zip', 'wb')
        
        # Verify chunks were written
        handle = mock_open()
        assert handle.write.call_count == 3

    @mock.patch('vdr.ctuapi.requests.get')
    @mock.patch('vdr.ctuapi.settings')
    @mock.patch('builtins.open', new_callable=mock.mock_open)
    def test_download_report_with_empty_chunks(self, mock_open, mock_settings, mock_get):
        """Test download with some empty chunks"""
        mock_settings.CTU_BASE_URL = 'https://ctu.example.com'
        mock_settings.CTU_ACCESS_TOKEN = 'test_token'
        
        mock_response = mock.Mock()
        mock_response.iter_content.return_value = [b'chunk1', b'', b'chunk2', None, b'chunk3']
        mock_get.return_value = mock_response
        
        result = download_report('report_12345', '/tmp/report.zip')
        
        assert result is True
        # Should only write non-empty chunks
        handle = mock_open()
        assert handle.write.call_count == 3

    @mock.patch('vdr.ctuapi.requests.get')
    @mock.patch('vdr.ctuapi.settings')
    def test_download_report_request_exception(self, mock_settings, mock_get):
        """Test download with request exception"""
        mock_settings.CTU_BASE_URL = 'https://ctu.example.com'
        mock_settings.CTU_ACCESS_TOKEN = 'test_token'
        
        mock_get.side_effect = requests.RequestException('Connection failed')
        
        result = download_report('report_12345', '/tmp/report.zip')
        
        assert result is False

    @mock.patch('vdr.ctuapi.requests.get')
    @mock.patch('vdr.ctuapi.settings')
    @mock.patch('builtins.open', new_callable=mock.mock_open)
    def test_download_report_io_error(self, mock_open, mock_settings, mock_get):
        """Test download with IO error"""
        mock_settings.CTU_BASE_URL = 'https://ctu.example.com'
        mock_settings.CTU_ACCESS_TOKEN = 'test_token'
        
        mock_response = mock.Mock()
        mock_response.iter_content.return_value = [b'chunk1']
        mock_get.return_value = mock_response
        
        mock_open.side_effect = IOError('Disk full')
        
        result = download_report('report_12345', '/tmp/report.zip')
        
        assert result is False

    @mock.patch('vdr.ctuapi.requests.get')
    @mock.patch('vdr.ctuapi.settings')
    def test_download_report_headers(self, mock_settings, mock_get):
        """Test that correct headers are sent in download request"""
        mock_settings.CTU_BASE_URL = 'https://ctu.example.com'
        mock_settings.CTU_ACCESS_TOKEN = 'test_api_key_xyz'
        
        mock_response = mock.Mock()
        mock_response.iter_content.return_value = []
        mock_get.return_value = mock_response
        
        with mock.patch('builtins.open', mock.mock_open()):
            download_report('report_12345', '/tmp/test.zip')
        
        call_args = mock_get.call_args
        headers = call_args[1]['headers']
        assert headers['x-api-key'] == 'test_api_key_xyz'
        assert headers['Content-Type'] == 'application/json'
        assert headers['User-agent'] == 'povmanager'

    @mock.patch('vdr.ctuapi.requests.get')
    @mock.patch('vdr.ctuapi.settings')
    def test_download_report_timeout(self, mock_settings, mock_get):
        """Test download with timeout parameter"""
        mock_settings.CTU_BASE_URL = 'https://ctu.example.com'
        mock_settings.CTU_ACCESS_TOKEN = 'test_token'
        
        mock_response = mock.Mock()
        mock_response.iter_content.return_value = []
        mock_get.return_value = mock_response
        
        with mock.patch('builtins.open', mock.mock_open()):
            download_report('report_12345', '/tmp/test.zip')
        
        call_args = mock_get.call_args
        assert call_args[1]['timeout'] == 300


