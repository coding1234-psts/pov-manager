"""
Pytest configuration and fixtures for VDR tests
Provides shared fixtures and configuration for all tests
"""
import pytest
from django.conf import settings
from django.test import Client
from vdr.tests.factories import (
    ThreatProfileFactory,
    VulnerabilitiesFactory,
)


@pytest.fixture
def api_client():
    """Fixture for Django test client"""
    return Client()


@pytest.fixture
def threat_profile(db):
    """Fixture for creating a basic threat profile"""
    return ThreatProfileFactory()


@pytest.fixture
def threat_profile_with_ip_ranges(db):
    """Fixture for threat profile with IP ranges"""
    return ThreatProfileFactory(
        ip_ranges=['8.8.8.0/24', '1.1.1.0/24']
    )


@pytest.fixture
def threat_profile_with_tag(db):
    """Fixture for threat profile with VDR tag"""
    return ThreatProfileFactory(
        tag_id='12345',
        status='TAG_CREATED'
    )


@pytest.fixture
def vulnerability(db, threat_profile):
    """Fixture for creating a single vulnerability"""
    return VulnerabilitiesFactory(threat_profile=threat_profile)


@pytest.fixture
def multiple_vulnerabilities(db, threat_profile):
    """Fixture for creating multiple vulnerabilities"""
    return [
        VulnerabilitiesFactory(threat_profile=threat_profile)
        for _ in range(5)
    ]


@pytest.fixture(autouse=True)
def setup_test_settings(settings):
    """Auto-use fixture to set up test-specific settings"""
    settings.VDR_ACCESS_TOKEN = 'test_vdr_token'
    settings.VDR_TEAM_ID = 'test_team_123'
    settings.CTU_ACCESS_TOKEN = 'test_ctu_token'
    settings.CTU_BASE_URL = 'https://ctu.test.example.com'
    settings.CTU_REPORTS_PATH = '/tmp/test_reports'


@pytest.fixture
def mock_vdr_api_responses():
    """Fixture providing common VDR API mock responses"""
    return {
        'create_tag': {'id': 12345, 'label': 'test_tag'},
        'create_range': {'id': 'range_123', 'range': '8.8.8.0/24'},
        'get_ranges': {
            'items': [
                {'id': 'range_1', 'range': '8.8.8.0/24'},
                {'id': 'range_2', 'range': '1.1.1.0/24'}
            ]
        },
        'get_servers': {
            'items': [
                {'id': 'server_1', 'ip': '192.168.1.1'},
                {'id': 'server_2', 'ip': '192.168.1.2'}
            ]
        },
        'get_websites': {
            'items': [
                {'id': 'website_1', 'url': 'https://example.com'}
            ]
        },
        'generate_report': {'id': 'report_12345'},
        'report_status': {'status': 'done', 'fileLocation': 'reports/file.csv'}
    }


@pytest.fixture
def mock_ctu_api_responses():
    """Fixture providing common CTU API mock responses"""
    return {
        'submit_report': {'id': 'ctu_report_12345'},
        'report_status': {
            'ctu_report_12345': {'progress': 'completed'}
        }
    }

