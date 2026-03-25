"""
Unit tests for VDR models
Tests model creation, validation, and relationships
"""
import pytest
from decimal import Decimal
from django.test import TestCase
from django.db import IntegrityError
from vdr.models import ThreatProfile, Vulnerabilities
from vdr.tests.factories import (
    ThreatProfileFactory,
    ThreatProfileWithTagFactory,
    VulnerabilitiesFactory,
    ServerVulnerabilityFactory,
    WebsiteVulnerabilityFactory,
)


@pytest.mark.django_db
@pytest.mark.unit
class TestThreatProfileModel(TestCase):
    """Test ThreatProfile model functionality"""

    def test_create_threat_profile_minimal(self):
        """Test creating a threat profile with minimal required fields"""
        profile = ThreatProfile.objects.create(
            organization_name='Test Org',
            vivun_activity='123456'
        )
        
        assert profile.organization_name == 'Test Org'
        assert profile.vivun_activity == '123456'
        assert profile.status == ThreatProfile.STATUS_CREATED
        assert profile.unique_id is not None
        assert profile.organization_emails == []
        assert profile.organization_email_domains == []
        assert profile.ip_ranges == []

    def test_threat_profile_uuid_generation(self):
        """Test that unique_id is automatically generated"""
        profile1 = ThreatProfileFactory()
        profile2 = ThreatProfileFactory()
        
        assert profile1.unique_id is not None
        assert profile2.unique_id is not None
        assert profile1.unique_id != profile2.unique_id

    def test_threat_profile_uuid_uniqueness(self):
        """Test that unique_id is unique across profiles"""
        profile1 = ThreatProfileFactory()
        profile2 = ThreatProfileFactory()
        
        # Try to create a profile with duplicate UUID
        with pytest.raises(IntegrityError):
            ThreatProfile.objects.create(
                organization_name='Duplicate',
                vivun_activity='999999',
                unique_id=profile1.unique_id
            )

    def test_threat_profile_status_choices(self):
        """Test all status choices are valid"""
        valid_statuses = [
            ThreatProfile.STATUS_CREATED,
            ThreatProfile.STATUS_TAG_CREATED,
            ThreatProfile.STATUS_SCANS_SCHEDULED,
            ThreatProfile.STATUS_VULNERABILITY_RESULTS_COLLECTED,
            ThreatProfile.STATUS_VULNERABILITY_RESULTS_PROCESSED,
            ThreatProfile.STATUS_CTU_AUTOBRIEF_DATA_PROCESSED,
            ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_REQUESTED,
            ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_AVAILABLE,
            ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_REQUESTED_WITHOUT_VDR,
            ThreatProfile.STATUS_CTU_AUTOBRIEF_REPORT_AVAILABLE_WITHOUT_VDR,
        ]
        
        for status in valid_statuses:
            profile = ThreatProfileFactory(status=status)
            assert profile.status == status

    def test_threat_profile_array_fields(self):
        """Test ArrayField operations"""
        profile = ThreatProfileFactory()
        
        # Test email domains
        profile.organization_email_domains.append('newdomain.com')
        profile.save()
        profile.refresh_from_db()
        assert 'newdomain.com' in profile.organization_email_domains
        
        # Test emails
        profile.organization_emails.append('new@example.com')
        profile.save()
        profile.refresh_from_db()
        assert 'new@example.com' in profile.organization_emails
        
        # Test IP ranges
        profile.ip_ranges.append('8.8.8.0/24')
        profile.save()
        profile.refresh_from_db()
        assert '8.8.8.0/24' in profile.ip_ranges

    def test_threat_profile_json_field(self):
        """Test JSONField for ctu_autobrief_data"""
        profile = ThreatProfileFactory()
        
        test_data = {
            'vdr_data': {
                'servers': 10,
                'websites': 5
            },
            'custom_field': 'test_value'
        }
        
        profile.ctu_autobrief_data = test_data
        profile.save()
        profile.refresh_from_db()
        
        assert profile.ctu_autobrief_data == test_data
        assert profile.ctu_autobrief_data['vdr_data']['servers'] == 10

    def test_threat_profile_get_status_display(self):
        """Test status display method"""
        profile = ThreatProfileFactory(status=ThreatProfile.STATUS_CREATED)
        assert profile.get_status_display() == 'Profile created'
        
        profile.status = ThreatProfile.STATUS_TAG_CREATED
        assert profile.get_status_display() == 'VDR Tag created'

    def test_threat_profile_timestamps(self):
        """Test automatic timestamp fields"""
        profile = ThreatProfileFactory()
        
        assert profile.created_date is not None
        assert profile.modified_data is not None
        
        original_created = profile.created_date
        original_modified = profile.modified_data
        
        # Modify and save
        profile.organization_name = 'Updated Name'
        profile.save()
        
        assert profile.created_date == original_created
        assert profile.modified_data >= original_modified

    def test_threat_profile_vivun_activity_default(self):
        """Test vivun_activity default value"""
        profile = ThreatProfile.objects.create(
            organization_name='Test'
        )
        assert profile.vivun_activity == '000000'


@pytest.mark.django_db
@pytest.mark.unit
class TestVulnerabilitiesModel(TestCase):
    """Test Vulnerabilities model functionality"""

    def test_create_vulnerability_minimal(self):
        """Test creating vulnerability with minimal fields"""
        profile = ThreatProfileFactory()
        vuln = Vulnerabilities.objects.create(
            threat_profile=profile,
            address='192.168.1.1'
        )
        
        assert vuln.threat_profile == profile
        assert vuln.address == '192.168.1.1'
        assert vuln.asset_type is None

    def test_vulnerability_asset_types(self):
        """Test asset type choices"""
        profile = ThreatProfileFactory()
        
        server_vuln = Vulnerabilities.objects.create(
            threat_profile=profile,
            address='192.168.1.1',
            asset_type=Vulnerabilities.ASSET_TYPE_SERVER
        )
        assert server_vuln.asset_type == 'server'
        
        website_vuln = Vulnerabilities.objects.create(
            threat_profile=profile,
            address='https://example.com',
            asset_type=Vulnerabilities.ASSET_TYPE_WEBSITE
        )
        assert website_vuln.asset_type == 'website'

    def test_vulnerability_decimal_fields(self):
        """Test Decimal field precision"""
        vuln = VulnerabilitiesFactory(
            score_cvss=Decimal('9.85'),
            score_cps=Decimal('0.95432')
        )
        
        vuln.refresh_from_db()
        assert vuln.score_cvss == Decimal('9.85')
        assert vuln.score_cps == Decimal('0.95432')

    def test_vulnerability_foreign_key_relationship(self):
        """Test foreign key relationship with ThreatProfile"""
        profile = ThreatProfileFactory()
        vuln1 = VulnerabilitiesFactory(threat_profile=profile)
        vuln2 = VulnerabilitiesFactory(threat_profile=profile)
        
        assert vuln1.threat_profile == profile
        assert vuln2.threat_profile == profile
        assert profile.vulnerabilities_set.count() == 2

    def test_vulnerability_cascade_deletion(self):
        """Test that vulnerabilities are deleted when threat profile is deleted"""
        profile = ThreatProfileFactory()
        vuln1 = VulnerabilitiesFactory(threat_profile=profile)
        vuln2 = VulnerabilitiesFactory(threat_profile=profile)
        
        vuln1_id = vuln1.id
        vuln2_id = vuln2.id
        
        profile.delete()
        
        assert not Vulnerabilities.objects.filter(id=vuln1_id).exists()
        assert not Vulnerabilities.objects.filter(id=vuln2_id).exists()

    def test_vulnerability_text_fields(self):
        """Test text field storage"""
        vuln = VulnerabilitiesFactory(
            description='A' * 500,
            remedy='B' * 500,
            references='C' * 500,
            location='D' * 500
        )
        
        vuln.refresh_from_db()
        assert len(vuln.description) == 500
        assert len(vuln.remedy) == 500
        assert len(vuln.references) == 500
        assert len(vuln.location) == 500

    def test_vulnerability_with_factories(self):
        """Test using factories for different vulnerability types"""
        server_vuln = ServerVulnerabilityFactory()
        assert server_vuln.asset_type == Vulnerabilities.ASSET_TYPE_SERVER
        assert not server_vuln.address.startswith('http')
        
        website_vuln = WebsiteVulnerabilityFactory()
        assert website_vuln.asset_type == Vulnerabilities.ASSET_TYPE_WEBSITE
        assert website_vuln.address.startswith('http')

    def test_vulnerability_null_fields(self):
        """Test that nullable fields can be null"""
        profile = ThreatProfileFactory()
        vuln = Vulnerabilities.objects.create(
            threat_profile=profile,
            address='192.168.1.1',
            ip=None,
            severity=None,
            cve_number=None,
            score_cvss=None,
            score_cps=None
        )
        
        assert vuln.ip is None
        assert vuln.severity is None
        assert vuln.cve_number is None
        assert vuln.score_cvss is None
        assert vuln.score_cps is None

    def test_vulnerability_group_differentiator_max_length(self):
        """Test group_differentiator max length constraint"""
        vuln = VulnerabilitiesFactory(
            group_differentiator='A' * 200
        )
        assert len(vuln.group_differentiator) == 200

    def test_multiple_vulnerabilities_same_profile(self):
        """Test creating multiple vulnerabilities for same profile"""
        profile = ThreatProfileFactory()
        vulns = [
            VulnerabilitiesFactory(threat_profile=profile) 
            for _ in range(10)
        ]
        
        assert len(vulns) == 10
        assert all(v.threat_profile == profile for v in vulns)
        assert profile.vulnerabilities_set.count() == 10


