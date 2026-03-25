"""
Unit tests for VDR utility functions
Tests IP validation, conversion, and vulnerability processing functions
"""
import pytest
from decimal import Decimal
from io import BytesIO
import pandas as pd
from django.test import TestCase
from vdr.utils import (
    ip_to_int,
    int_to_ip,
    validate_ip_range,
    generate_vulnerabilities_excel,
    preselect_vulnerabilities,
)
from vdr.models import ThreatProfile, Vulnerabilities


@pytest.mark.unit
class TestIPConversion:
    """Test IP address conversion functions"""

    def test_ip_to_int_valid(self):
        """Test converting valid IP addresses to integers"""
        assert ip_to_int('0.0.0.0') == 0
        assert ip_to_int('255.255.255.255') == 4294967295
        assert ip_to_int('192.168.1.1') == 3232235777
        assert ip_to_int('10.0.0.1') == 167772161

    def test_ip_to_int_invalid_format(self):
        """Test IP to int conversion with invalid formats"""
        # Only missing octets raise ValueError, not invalid values
        with pytest.raises(ValueError):
            ip_to_int('192.168.1')
        with pytest.raises(ValueError):
            ip_to_int('192.168')
        with pytest.raises(ValueError):
            ip_to_int('invalid')

    def test_int_to_ip_valid(self):
        """Test converting integers to IP addresses"""
        assert int_to_ip(0) == '0.0.0.0'
        assert int_to_ip(4294967295) == '255.255.255.255'
        assert int_to_ip(3232235777) == '192.168.1.1'
        assert int_to_ip(167772161) == '10.0.0.1'

    def test_ip_conversion_round_trip(self):
        """Test converting IP to int and back"""
        test_ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1', '8.8.8.8']
        for ip in test_ips:
            assert int_to_ip(ip_to_int(ip)) == ip


@pytest.mark.unit
class TestIPRangeValidation:
    """Test IP range validation function"""

    def test_valid_public_ip_ranges(self):
        """Test validation of valid public IP ranges"""
        valid_ranges = [
            '89.34.76.0/24',
            '8.8.8.0/24',
            '1.1.1.0/24',
            '200.100.0.0/16',  # Fixed: network address for /16
            '11.0.0.0/8',  # Not in private range
        ]
        for ip_range in valid_ranges:
            result = validate_ip_range(ip_range)
            assert result['valid'] is True, f"Failed for {ip_range}"
            assert 'error' not in result or result.get('error') is None

    def test_private_ip_range_10(self):
        """Test detection of 10.x.x.x private ranges"""
        result = validate_ip_range('10.0.0.0/8')
        assert result['valid'] is False
        assert result['error'] == 'private'

    def test_private_ip_range_192_168(self):
        """Test detection of 192.168.x.x private ranges"""
        result = validate_ip_range('192.168.1.0/24')
        assert result['valid'] is False
        assert result['error'] == 'private'

    def test_private_ip_range_172_16_31(self):
        """Test detection of 172.16-31.x.x private ranges"""
        private_172_ranges = [
            '172.16.0.0/12',
            '172.20.0.0/16',
            '172.31.0.0/16',
        ]
        for ip_range in private_172_ranges:
            result = validate_ip_range(ip_range)
            assert result['valid'] is False, f"Failed for {ip_range}"
            assert result['error'] == 'private'

    def test_non_network_address(self):
        """Test detection of non-network addresses"""
        result = validate_ip_range('89.34.76.10/24')
        assert result['valid'] is False
        assert result['error'] == 'network'
        assert result['correctNetwork'] == '89.34.76.0/24'

    def test_non_network_address_various_subnets(self):
        """Test network address correction for various subnets"""
        # Note: Private IPs return 'private' error, not 'network' error
        # Only test with public IPs here
        test_cases = [
            ('8.8.8.5/24', '8.8.8.0/24'),
            ('1.1.1.128/25', '1.1.1.128/25'),  # This is correct network address
            ('200.100.50.200/16', '200.100.0.0/16'),
        ]
        for input_range, expected_network in test_cases:
            result = validate_ip_range(input_range)
            if result['valid']:
                # It's already the network address
                assert input_range == expected_network
            else:
                assert result.get('correctNetwork') == expected_network, f"Failed for {input_range}"

    def test_invalid_subnet_mask(self):
        """Test invalid subnet masks"""
        invalid_ranges = [
            '192.168.1.0/33',  # Subnet too large
            '192.168.1.0/-1',  # Negative subnet
            '192.168.1.0/abc',  # Non-numeric
        ]
        for ip_range in invalid_ranges:
            result = validate_ip_range(ip_range)
            assert result['valid'] is False
            assert result['error'] == 'format'

    def test_invalid_ip_format(self):
        """Test invalid IP formats"""
        invalid_ips = [
            '256.1.1.0/24',  # Octet too large
            '192.168.1/24',  # Missing octet
            '192.168.1.1.1/24',  # Too many octets
            'not.an.ip/24',  # Non-numeric octets
            '192.168.-1.0/24',  # Negative octet
        ]
        for ip_range in invalid_ips:
            result = validate_ip_range(ip_range)
            assert result['valid'] is False
            assert result['error'] == 'format'

    def test_missing_slash(self):
        """Test IP without CIDR notation"""
        result = validate_ip_range('192.168.1.0')
        assert result['valid'] is False
        assert result['error'] == 'format'

    def test_boundary_subnet_masks(self):
        """Test boundary subnet masks /0 and /32"""
        result_0 = validate_ip_range('0.0.0.0/0')
        assert result_0['valid'] is True

        result_32 = validate_ip_range('8.8.8.8/32')
        assert result_32['valid'] is True

    def test_edge_case_172_ranges(self):
        """Test edge cases around 172.16-31 range"""
        # 172.15.x.x is NOT private
        result = validate_ip_range('172.15.0.0/16')
        assert result['valid'] is True

        # 172.32.x.x is NOT private
        result = validate_ip_range('172.32.0.0/16')
        assert result['valid'] is True


@pytest.mark.django_db
@pytest.mark.unit
class TestVulnerabilityProcessing(TestCase):
    """Test vulnerability processing functions"""

    def setUp(self):
        """Set up test data"""
        self.threat_profile = ThreatProfile.objects.create(
            organization_name='Test Organization',
            vivun_activity='123456'
        )

    def test_generate_vulnerabilities_excel_empty_queryset(self):
        """Test Excel generation with empty queryset"""
        empty_queryset = Vulnerabilities.objects.none()
        excel_buffer = generate_vulnerabilities_excel(empty_queryset)
        
        assert isinstance(excel_buffer, BytesIO)
        excel_buffer.seek(0)
        df = pd.read_excel(excel_buffer)
        assert len(df) == 0

    def test_generate_vulnerabilities_excel_with_data(self):
        """Test Excel generation with vulnerability data"""
        # Create test vulnerabilities
        Vulnerabilities.objects.create(
            threat_profile=self.threat_profile,
            address='192.168.1.1',
            ip='192.168.1.1',
            severity='critical',
            description='Test vulnerability',
            location='/test/path',
            cve_number='CVE-2023-1234',
            remedy='Apply patch',
            references='https://example.com',
            score_cvss=Decimal('9.8'),
            score_cps=Decimal('0.95'),
            group_description='SQL Injection',
            group_differentiator='in login form',
            os_family='Linux',
            os_name='Ubuntu 20.04',
            asset_type=Vulnerabilities.ASSET_TYPE_SERVER
        )

        queryset = Vulnerabilities.objects.all()
        excel_buffer = generate_vulnerabilities_excel(queryset)
        
        assert isinstance(excel_buffer, BytesIO)
        excel_buffer.seek(0)
        df = pd.read_excel(excel_buffer)
        assert len(df) == 1
        assert 'Vulnerability Title' in df.columns
        assert 'CVE Number' in df.columns
        assert 'CVSS Score' in df.columns
        assert df.iloc[0]['CVE Number'] == 'CVE-2023-1234'

    def test_preselect_vulnerabilities_server_type(self):
        """Test vulnerability preselection for server assets"""
        # Create multiple vulnerabilities with different CPS scores
        Vulnerabilities.objects.create(
            threat_profile=self.threat_profile,
            address='192.168.1.1',
            ip='192.168.1.1',
            severity='critical',
            description='Test vuln 1',
            location='/path1',
            group_description='SQL Injection',
            group_differentiator='in form',
            score_cps=Decimal('0.5'),
            asset_type=Vulnerabilities.ASSET_TYPE_SERVER
        )
        
        Vulnerabilities.objects.create(
            threat_profile=self.threat_profile,
            address='192.168.1.1',
            ip='192.168.1.1',
            severity='critical',
            description='Test vuln 2',
            location='/path1',
            group_description='SQL Injection',
            group_differentiator='in form',
            score_cps=Decimal('0.8'),  # Higher score - should be selected
            asset_type=Vulnerabilities.ASSET_TYPE_SERVER
        )

        filtered_ids = preselect_vulnerabilities(
            threat_profile_id=self.threat_profile.pk,
            asset_type=Vulnerabilities.ASSET_TYPE_SERVER
        )
        
        assert len(filtered_ids) == 1
        # Verify the higher CPS score vulnerability was selected
        vuln = Vulnerabilities.objects.get(id=filtered_ids[0])
        assert vuln.score_cps == Decimal('0.8')

    def test_preselect_vulnerabilities_website_type(self):
        """Test vulnerability preselection for website assets"""
        Vulnerabilities.objects.create(
            threat_profile=self.threat_profile,
            address='https://example.com',
            ip='93.184.216.34',
            severity='medium',
            description='XSS vulnerability',
            location='/page',
            group_description='XSS',
            group_differentiator='reflected',
            score_cps=Decimal('0.6'),
            asset_type=Vulnerabilities.ASSET_TYPE_WEBSITE
        )

        filtered_ids = preselect_vulnerabilities(
            threat_profile_id=self.threat_profile.pk,
            asset_type=Vulnerabilities.ASSET_TYPE_WEBSITE
        )
        
        assert len(filtered_ids) == 1

    def test_preselect_vulnerabilities_filters_zero_cps(self):
        """Test that vulnerabilities with zero CPS score are filtered out"""
        Vulnerabilities.objects.create(
            threat_profile=self.threat_profile,
            address='192.168.1.1',
            ip='192.168.1.1',
            severity='info',
            description='Low priority finding',
            location='/path',
            group_description='Info disclosure',
            group_differentiator='minor',
            score_cps=Decimal('0'),  # Should be filtered out
            asset_type=Vulnerabilities.ASSET_TYPE_SERVER
        )

        filtered_ids = preselect_vulnerabilities(
            threat_profile_id=self.threat_profile.pk,
            asset_type=Vulnerabilities.ASSET_TYPE_SERVER
        )
        
        assert len(filtered_ids) == 0

    def test_preselect_vulnerabilities_unique_key_grouping(self):
        """Test that vulnerabilities are grouped by unique key"""
        # Create vulnerabilities with same unique key but different locations
        base_data = {
            'threat_profile': self.threat_profile,
            'address': '192.168.1.1',
            'ip': '192.168.1.1',
            'severity': 'critical',
            'group_description': 'SQL Injection',
            'group_differentiator': 'in login',
            'asset_type': Vulnerabilities.ASSET_TYPE_SERVER,
        }
        
        # Same unique key, lower score
        Vulnerabilities.objects.create(
            **base_data,
            location='/admin/login',
            score_cps=Decimal('0.7'),
            description='Vuln 1'
        )
        
        # Same unique key, higher score - should be selected
        Vulnerabilities.objects.create(
            **base_data,
            location='/admin/login',
            score_cps=Decimal('0.9'),
            description='Vuln 2'
        )

        filtered_ids = preselect_vulnerabilities(
            threat_profile_id=self.threat_profile.pk,
            asset_type=Vulnerabilities.ASSET_TYPE_SERVER
        )
        
        # Should only return 1 - the one with highest CPS
        assert len(filtered_ids) == 1
        vuln = Vulnerabilities.objects.get(id=filtered_ids[0])
        assert vuln.score_cps == Decimal('0.9')


