"""
Unit tests for VDR management commands
Tests data processing and business logic in download_reports command
"""
import pytest
from unittest import mock
from decimal import Decimal
from io import StringIO
import pandas as pd
from django.test import TestCase
from django.core.management import call_command
from django.utils import timezone
from vdr.models import ThreatProfile, Vulnerabilities
from vdr.tests.factories import (
    ThreatProfileFactory,
    ThreatProfileScansScheduledFactory,
    VulnerabilitiesFactory,
    ServerVulnerabilityFactory,
    WebsiteVulnerabilityFactory,
)
from vdr.management.commands.download_reports import (
    get_report,
    parse_csv_from_buffer,
    save_vulnerabilities,
    build_vdr_data,
    top_vulnerabilities,
    total_live_systems,
    total_vulnerabilities,
    percent_severities,
    get_severity_order_case,
    generate_ctu_autobrief_report,
    process_profile,
)


@pytest.mark.unit
class TestGetReport:
    """Test report fetching with retry logic"""

    @mock.patch('vdr.management.commands.download_reports.fetch_report')
    @mock.patch('vdr.management.commands.download_reports.check_vulnerabilities_report_status')
    @mock.patch('vdr.management.commands.download_reports.generate_vulnerabilities_report')
    def test_get_report_success_first_try(self, mock_generate, mock_check, mock_fetch):
        """Test successful report fetch on first try"""
        mock_generate.return_value = 'report_123'
        mock_check.return_value = ('done', 'reports/file.csv')
        mock_fetch.return_value = StringIO('test,data\n1,2')
        
        result = get_report('tag_123')
        
        assert isinstance(result, StringIO)
        mock_generate.assert_called_once_with('tag_123')
        mock_check.assert_called_once()
        mock_fetch.assert_called_once_with('reports/file.csv')

    @mock.patch('vdr.management.commands.download_reports.time.sleep')
    @mock.patch('vdr.management.commands.download_reports.fetch_report')
    @mock.patch('vdr.management.commands.download_reports.check_vulnerabilities_report_status')
    @mock.patch('vdr.management.commands.download_reports.generate_vulnerabilities_report')
    def test_get_report_success_after_retries(self, mock_generate, mock_check, mock_fetch, mock_sleep):
        """Test successful report fetch after retries"""
        mock_generate.return_value = 'report_123'
        mock_check.side_effect = [
            ('pending', None),
            ('processing', None),
            ('done', 'reports/file.csv')
        ]
        mock_fetch.return_value = StringIO('test,data\n1,2')
        
        result = get_report('tag_123', max_retries=3, sleep_interval=1)
        
        assert isinstance(result, StringIO)
        assert mock_check.call_count == 3
        assert mock_sleep.call_count == 2  # Don't sleep on last iteration

    @mock.patch('vdr.management.commands.download_reports.time.sleep')
    @mock.patch('vdr.management.commands.download_reports.check_vulnerabilities_report_status')
    @mock.patch('vdr.management.commands.download_reports.generate_vulnerabilities_report')
    def test_get_report_timeout(self, mock_generate, mock_check, mock_sleep):
        """Test report fetch timeout"""
        mock_generate.return_value = 'report_123'
        mock_check.return_value = ('pending', None)
        
        with pytest.raises(TimeoutError) as exc_info:
            get_report('tag_123', max_retries=3, sleep_interval=1)
        
        assert 'timed out' in str(exc_info.value)
        assert mock_check.call_count == 3


@pytest.mark.unit
class TestParseCsvFromBuffer:
    """Test CSV parsing function"""

    def test_parse_csv_valid_data(self):
        """Test parsing valid CSV data"""
        csv_data = """address,ip,location,severity,description,cve_number,remedy,references,report_id,vulnerability_id,score_cvss,score_cps,group_description,group_differentiator,os_family,os_name
192.168.1.1,192.168.1.1,/admin,critical,SQL Injection,CVE-2023-1234,Patch it,https://example.com,1001,VULN-1,9.8,0.95,SQL Injection,in login form,Linux,Ubuntu 20.04
"""
        buffer = StringIO(csv_data)
        df = parse_csv_from_buffer(buffer)
        
        assert len(df) == 1
        assert df.iloc[0]['address'] == '192.168.1.1'
        assert df.iloc[0]['severity'] == 'critical'
        assert df.iloc[0]['cve_number'] == 'CVE-2023-1234'

    def test_parse_csv_multiple_rows(self):
        """Test parsing CSV with multiple rows"""
        csv_data = """address,ip,location,severity,description,cve_number,remedy,references,report_id,vulnerability_id,score_cvss,score_cps,group_description,group_differentiator,os_family,os_name
192.168.1.1,192.168.1.1,/admin,critical,Test1,CVE-1,Fix1,ref1,1001,V1,9.8,0.95,Desc1,Diff1,Linux,Ubuntu
192.168.1.2,192.168.1.2,/user,medium,Test2,CVE-2,Fix2,ref2,1002,V2,5.5,0.50,Desc2,Diff2,Windows,Win10
"""
        buffer = StringIO(csv_data)
        df = parse_csv_from_buffer(buffer)
        
        assert len(df) == 2
        assert df.iloc[0]['address'] == '192.168.1.1'
        assert df.iloc[1]['address'] == '192.168.1.2'


@pytest.mark.django_db
@pytest.mark.unit
class TestSaveVulnerabilities(TestCase):
    """Test vulnerability saving function"""

    def test_save_vulnerabilities_servers(self):
        """Test saving server vulnerabilities"""
        profile = ThreatProfileFactory()
        
        data = pd.DataFrame([{
            'address': '192.168.1.1',
            'ip': '192.168.1.1',
            'severity': 'critical',
            'description': 'Test vulnerability',
            'location': '/path',
            'cve_number': 'CVE-2023-1',
            'remedy': 'Fix it',
            'references': 'http://example.com',
            'report_id': 1001,
            'vulnerability_id': 'VULN-1',
            'score_cvss': 9.8,
            'score_cps': 0.95,
            'group_description': 'SQL Injection',
            'group_differentiator': 'in form',
            'os_family': 'Linux',
            'os_name': 'Ubuntu 20.04'
        }])
        
        save_vulnerabilities(profile, data)
        
        assert Vulnerabilities.objects.count() == 1
        vuln = Vulnerabilities.objects.first()
        assert vuln.address == '192.168.1.1'
        assert vuln.asset_type == Vulnerabilities.ASSET_TYPE_SERVER

    def test_save_vulnerabilities_websites(self):
        """Test saving website vulnerabilities"""
        profile = ThreatProfileFactory()
        
        data = pd.DataFrame([{
            'address': 'https://example.com',
            'ip': '93.184.216.34',
            'severity': 'medium',
            'description': 'XSS vulnerability',
            'location': '/page',
            'cve_number': 'CVE-2023-2',
            'remedy': 'Sanitize input',
            'references': 'http://ref.com',
            'report_id': 1002,
            'vulnerability_id': 'VULN-2',
            'score_cvss': 6.5,
            'score_cps': 0.60,
            'group_description': 'XSS',
            'group_differentiator': 'reflected',
            'os_family': '',
            'os_name': ''
        }])
        
        save_vulnerabilities(profile, data)
        
        vuln = Vulnerabilities.objects.first()
        assert vuln.asset_type == Vulnerabilities.ASSET_TYPE_WEBSITE
        assert vuln.address.startswith('http')

    def test_save_vulnerabilities_handles_nan(self):
        """Test saving vulnerabilities with NaN values"""
        profile = ThreatProfileFactory()
        
        data = pd.DataFrame([{
            'address': '192.168.1.1',
            'ip': '192.168.1.1',
            'severity': 'info',
            'description': 'Low priority',
            'location': '/path',
            'cve_number': '',
            'remedy': '',
            'references': '',
            'report_id': 1003,
            'vulnerability_id': 'VULN-3',
            'score_cvss': pd.NA,  # NaN value
            'score_cps': pd.NA,   # NaN value
            'group_description': 'Info',
            'group_differentiator': 'minor',
            'os_family': 'Linux',
            'os_name': 'Ubuntu'
        }])
        
        save_vulnerabilities(profile, data)
        
        vuln = Vulnerabilities.objects.first()
        assert vuln.score_cvss == Decimal('0')
        assert vuln.score_cps == Decimal('0')


@pytest.mark.django_db
@pytest.mark.unit
class TestVulnerabilityAggregation(TestCase):
    """Test vulnerability aggregation functions"""

    def setUp(self):
        """Set up test data"""
        self.profile = ThreatProfileFactory()

    def test_total_live_systems_servers(self):
        """Test counting live server systems"""
        ServerVulnerabilityFactory(threat_profile=self.profile, ip='192.168.1.1')
        ServerVulnerabilityFactory(threat_profile=self.profile, ip='192.168.1.1')
        ServerVulnerabilityFactory(threat_profile=self.profile, ip='192.168.1.2')
        
        count = total_live_systems(self.profile, Vulnerabilities.ASSET_TYPE_SERVER)
        assert count == 2  # Two unique IPs

    def test_total_live_systems_websites(self):
        """Test counting live website systems"""
        WebsiteVulnerabilityFactory(threat_profile=self.profile, ip='93.184.216.34')
        WebsiteVulnerabilityFactory(threat_profile=self.profile, ip='93.184.216.34')
        WebsiteVulnerabilityFactory(threat_profile=self.profile, ip='8.8.8.8')
        
        count = total_live_systems(self.profile, Vulnerabilities.ASSET_TYPE_WEBSITE)
        assert count == 2

    def test_total_vulnerabilities(self):
        """Test counting total vulnerabilities"""
        for i in range(5):
            ServerVulnerabilityFactory(
                threat_profile=self.profile,
                vulnerability_id=f'VULN-{i}'
            )
        
        count = total_vulnerabilities(self.profile, Vulnerabilities.ASSET_TYPE_SERVER)
        assert count == 5

    def test_percent_severities_distribution(self):
        """Test severity percentage calculation"""
        # Create 10 vulnerabilities with different severities
        for _ in range(5):
            VulnerabilitiesFactory(
                threat_profile=self.profile,
                severity='critical',
                asset_type=Vulnerabilities.ASSET_TYPE_SERVER
            )
        for _ in range(3):
            VulnerabilitiesFactory(
                threat_profile=self.profile,
                severity='medium',
                asset_type=Vulnerabilities.ASSET_TYPE_SERVER
            )
        for _ in range(2):
            VulnerabilitiesFactory(
                threat_profile=self.profile,
                severity='warning',
                asset_type=Vulnerabilities.ASSET_TYPE_SERVER
            )
        
        percentages = percent_severities(self.profile, Vulnerabilities.ASSET_TYPE_SERVER)
        
        assert percentages['critical'] == '50'  # 5/10 = 50%
        assert percentages['medium'] == '30'    # 3/10 = 30%
        assert percentages['low'] == '20'       # 2/10 = 20%

    def test_percent_severities_empty(self):
        """Test severity percentages with no vulnerabilities"""
        percentages = percent_severities(self.profile, Vulnerabilities.ASSET_TYPE_SERVER)
        assert percentages == {}

    def test_top_vulnerabilities(self):
        """Test fetching top vulnerabilities"""
        vulns = []
        for i in range(10):
            vuln = VulnerabilitiesFactory(
                threat_profile=self.profile,
                score_cps=Decimal(f'0.{90-i}'),  # Decreasing scores
                severity='critical',
                asset_type=Vulnerabilities.ASSET_TYPE_SERVER,
                group_description=f'Vuln Type {i}',
                group_differentiator=f'Location {i}'
            )
            vulns.append(vuln)
        
        # Get IDs for filtering
        filtered_ids = [v.id for v in vulns]
        
        result = top_vulnerabilities(
            filtered_ids,
            Vulnerabilities.ASSET_TYPE_SERVER,
            limit=5
        )
        
        assert len(result['ips']) == 5
        assert len(result['Vulnerabilities']) == 5
        assert len(result['Criticality']) == 5


@pytest.mark.django_db
@pytest.mark.unit
class TestBuildVdrData(TestCase):
    """Test VDR data building function"""

    def test_build_vdr_data_structure(self):
        """Test that build_vdr_data returns correct structure"""
        profile = ThreatProfileFactory()
        
        # Create some test vulnerabilities
        ServerVulnerabilityFactory(
            threat_profile=profile,
            score_cps=Decimal('0.8'),
            severity='critical'
        )
        WebsiteVulnerabilityFactory(
            threat_profile=profile,
            score_cps=Decimal('0.7'),
            severity='medium'
        )
        
        result = build_vdr_data(profile)
        
        assert 'vdr_data' in result
        vdr_data = result['vdr_data']
        
        # Check server data
        assert 'vdr_server_table' in vdr_data
        assert 'vdr_live_servers' in vdr_data
        assert 'vdr_server_vuln' in vdr_data
        assert 'vdr_server_pie' in vdr_data
        
        # Check website data
        assert 'vdr_website_table' in vdr_data
        assert 'vdr_live_websites' in vdr_data
        assert 'vdr_website_vuln' in vdr_data
        assert 'vdr_website_pie' in vdr_data


@pytest.mark.django_db
@pytest.mark.unit
class TestGenerateCtuAutobriefReport(TestCase):
    """Test CTU autobrief report generation"""

    @mock.patch('vdr.management.commands.download_reports.ctu_submit_new_report')
    def test_generate_ctu_report_with_vdr_data(self, mock_submit):
        """Test report generation with VDR data"""
        mock_submit.return_value = 'report_123'
        
        profile = ThreatProfileFactory(
            organization_name='Test Org',
            organization_domain='test.com',
            organization_email_domains=['test.com'],
            organization_emails=['admin@test.com'],
            ip_ranges=['8.8.8.0/24'],
            ctu_autobrief_data={'test': 'data'}
        )
        
        report_id = generate_ctu_autobrief_report(profile, has_vdr_data=True)
        
        assert report_id == 'report_123'
        mock_submit.assert_called_once()
        call_args = mock_submit.call_args[0][0]
        assert call_args['client_name'] == 'Test Org'
        assert call_args['template_pptx'] == 'Threat_Profile_VDR.pptx'
        assert call_args['external_data'] == {'test': 'data'}

    @mock.patch('vdr.management.commands.download_reports.ctu_submit_new_report')
    def test_generate_ctu_report_without_vdr_data(self, mock_submit):
        """Test report generation without VDR data"""
        mock_submit.return_value = 'report_456'
        
        profile = ThreatProfileFactory(
            organization_name='Test Org 2'
        )
        
        report_id = generate_ctu_autobrief_report(profile, has_vdr_data=False)
        
        assert report_id == 'report_456'
        call_args = mock_submit.call_args[0][0]
        assert call_args['template_pptx'] == 'Threat_Profile_No_VDR.pptx'


@pytest.mark.django_db
@pytest.mark.unit
class TestProcessProfile(TestCase):
    """Test profile processing orchestration"""

    @mock.patch('vdr.management.commands.download_reports.generate_ctu_autobrief_report')
    @mock.patch('vdr.management.commands.download_reports.build_vdr_data')
    @mock.patch('vdr.management.commands.download_reports.save_vulnerabilities')
    @mock.patch('vdr.management.commands.download_reports.parse_csv_from_buffer')
    @mock.patch('vdr.management.commands.download_reports.get_report')
    def test_process_profile_success(
        self, mock_get_report, mock_parse, mock_save, mock_build, mock_generate
    ):
        """Test successful profile processing"""
        profile = ThreatProfileScansScheduledFactory(tag_id='12345')
        
        mock_get_report.return_value = StringIO('test,data')
        mock_parse.return_value = pd.DataFrame()
        mock_build.return_value = {'vdr_data': {}}
        mock_generate.return_value = 'report_789'
        
        process_profile(profile)
        
        profile.refresh_from_db()
        assert profile.status == ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_REQUESTED
        assert profile.ctu_autobrief_report_id == 'report_789'

    @mock.patch('vdr.management.commands.download_reports.generate_ctu_autobrief_report')
    @mock.patch('vdr.management.commands.download_reports.build_vdr_data')
    @mock.patch('vdr.management.commands.download_reports.get_report')
    def test_process_profile_vdr_timeout(self, mock_get_report, mock_build, mock_generate):
        """Test profile processing when VDR times out"""
        profile = ThreatProfileScansScheduledFactory(tag_id='12345')
        
        mock_get_report.side_effect = TimeoutError('Timeout')
        mock_build.return_value = {'vdr_data': {}}
        mock_generate.return_value = 'report_999'
        
        process_profile(profile)
        
        profile.refresh_from_db()
        # Should still complete but without VDR data
        assert profile.status == ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_REQUESTED


@pytest.mark.django_db
@pytest.mark.unit
class TestDownloadReportsCommand(TestCase):
    """Test the management command itself"""

    def test_command_no_profiles(self):
        """Test command with no profiles to process"""
        out = StringIO()
        call_command('download_reports', stdout=out)
        
        output = out.getvalue()
        assert 'no threat profiles' in output.lower()

    @mock.patch('vdr.management.commands.download_reports.process_profile')
    def test_command_with_profiles(self, mock_process):
        """Test command with profiles to process"""
        # Create a profile created more than 24 hours ago
        old_date = timezone.now() - timezone.timedelta(hours=25)
        profile = ThreatProfileScansScheduledFactory(
            tag_id='12345',
            created_date=old_date
        )
        
        # Manually set created_date since auto_now_add doesn't allow it
        ThreatProfile.objects.filter(id=profile.id).update(created_date=old_date)
        
        out = StringIO()
        call_command('download_reports', stdout=out)
        
        output = out.getvalue()
        assert 'Found 1 profile' in output or 'Processing' in output
        mock_process.assert_called()

    @mock.patch('vdr.management.commands.download_reports.process_profile')
    def test_command_skips_profiles_without_tag(self, mock_process):
        """Test command skips profiles without tag_id"""
        old_date = timezone.now() - timezone.timedelta(hours=25)
        profile = ThreatProfileScansScheduledFactory(
            tag_id=None,  # No tag ID
            created_date=old_date
        )
        ThreatProfile.objects.filter(id=profile.id).update(created_date=old_date)
        
        out = StringIO()
        call_command('download_reports', stdout=out)
        
        output = out.getvalue()
        if 'Skipping' in output:
            assert 'Tag ID is null' in output
        mock_process.assert_not_called()


