"""
Unit tests for VDR forms
Tests form validation and data handling
"""
import pytest
from django.test import TestCase
from vdr.forms import ThreatProfileForm
from vdr.models import ThreatProfile


@pytest.mark.django_db
@pytest.mark.unit
class TestThreatProfileForm(TestCase):
    """Test ThreatProfile form validation"""

    def test_form_valid_data(self):
        """Test form with valid data"""
        form_data = {
            'organization_name': 'Test Organization',
            'organization_domain': 'testorg.com',
            'organization_email_domains': ['testorg.com', 'example.com'],
            'organization_emails': ['admin@testorg.com', 'security@testorg.com'],
            'ip_ranges': ['8.8.8.0/24', '1.1.1.0/24'],
            'se_email': 'se@sophos.com',
            'vivun_activity': '123456'
        }
        
        form = ThreatProfileForm(data=form_data)
        assert form.is_valid()

    def test_form_missing_required_field(self):
        """Test form without required organization_name"""
        form_data = {
            'organization_domain': 'testorg.com',
            'se_email': 'se@sophos.com',
            'vivun_activity': '123456'
        }
        
        form = ThreatProfileForm(data=form_data)
        assert not form.is_valid()
        assert 'organization_name' in form.errors

    def test_form_minimal_data(self):
        """Test form with minimal required data"""
        form_data = {
            'organization_name': 'Minimal Org',
            'vivun_activity': '000000'
        }
        
        form = ThreatProfileForm(data=form_data)
        assert form.is_valid()

    def test_form_invalid_email(self):
        """Test form with invalid email"""
        form_data = {
            'organization_name': 'Test Org',
            'se_email': 'not-a-valid-email',
            'vivun_activity': '123456'
        }
        
        form = ThreatProfileForm(data=form_data)
        assert not form.is_valid()
        assert 'se_email' in form.errors

    def test_form_save_creates_instance(self):
        """Test that form save creates a ThreatProfile instance"""
        form_data = {
            'organization_name': 'Save Test Org',
            'organization_domain': 'savetest.com',
            'se_email': 'se@sophos.com',
            'vivun_activity': '654321'
        }
        
        form = ThreatProfileForm(data=form_data)
        assert form.is_valid()
        
        instance = form.save(commit=False)
        assert isinstance(instance, ThreatProfile)
        assert instance.organization_name == 'Save Test Org'

    def test_form_fields_match_model(self):
        """Test that form fields match expected fields"""
        form = ThreatProfileForm()
        expected_fields = [
            'organization_name',
            'organization_email_domains',
            'organization_domain',
            'organization_emails',
            'ip_ranges',
            'se_email',
            'vivun_activity'
        ]
        
        for field in expected_fields:
            assert field in form.fields

    def test_form_empty_arrays(self):
        """Test form with empty array fields"""
        form_data = {
            'organization_name': 'Test Org',
            'organization_email_domains': [],
            'organization_emails': [],
            'ip_ranges': [],
            'vivun_activity': '123456'
        }
        
        form = ThreatProfileForm(data=form_data)
        assert form.is_valid()


