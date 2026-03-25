"""
Factory classes for creating test instances of VDR models
Using factory_boy for clean test data generation
"""
import factory
from factory.django import DjangoModelFactory
from decimal import Decimal
from vdr.models import ThreatProfile, Vulnerabilities


class ThreatProfileFactory(DjangoModelFactory):
    """Factory for creating ThreatProfile test instances"""
    
    class Meta:
        model = ThreatProfile
    
    organization_name = factory.Sequence(lambda n: f'Test Organization {n}')
    organization_domain = factory.Sequence(lambda n: f'testorg{n}.com')
    organization_email_domains = factory.LazyFunction(lambda: ['example.com', 'test.com'])
    organization_emails = factory.LazyFunction(lambda: ['admin@example.com', 'security@example.com'])
    ip_ranges = factory.LazyFunction(lambda: ['8.8.8.0/24', '1.1.1.0/24'])
    se_email = factory.Faker('email')
    tag_id = factory.Sequence(lambda n: str(10000 + n))
    status = ThreatProfile.STATUS_CREATED
    ctu_autobrief_data = factory.Dict({})
    ctu_autobrief_report_id = None
    vivun_activity = factory.Sequence(lambda n: f'{100000 + n:06d}')
    created_by = None


class ThreatProfileWithTagFactory(ThreatProfileFactory):
    """Factory for ThreatProfile with TAG_CREATED status"""
    
    status = ThreatProfile.STATUS_TAG_CREATED
    tag_id = factory.Sequence(lambda n: str(20000 + n))


class ThreatProfileScansScheduledFactory(ThreatProfileFactory):
    """Factory for ThreatProfile with scans scheduled"""
    
    status = ThreatProfile.STATUS_SCANS_SCHEDULED
    tag_id = factory.Sequence(lambda n: str(30000 + n))


class VulnerabilitiesFactory(DjangoModelFactory):
    """Factory for creating Vulnerabilities test instances"""
    
    class Meta:
        model = Vulnerabilities
    
    threat_profile = factory.SubFactory(ThreatProfileFactory)
    address = factory.Faker('ipv4')
    ip = factory.SelfAttribute('address')
    severity = 'critical'
    description = factory.Faker('text', max_nb_chars=200)
    location = factory.Faker('file_path')
    cve_number = factory.Sequence(lambda n: f'CVE-2023-{1000 + n}')
    remedy = factory.Faker('text', max_nb_chars=150)
    references = factory.Faker('url')
    report_id = factory.Faker('random_int', min=1000, max=9999)
    vulnerability_id = factory.Sequence(lambda n: f'VULN-{n}')
    score_cvss = factory.LazyFunction(lambda: Decimal('7.5'))
    score_cps = factory.LazyFunction(lambda: Decimal('0.75'))
    group_description = factory.Iterator(['SQL Injection', 'XSS', 'CSRF', 'RCE'])
    group_differentiator = factory.Iterator(['in login form', 'in admin panel', 'in API'])
    os_family = factory.Iterator(['Linux', 'Windows', 'Unix'])
    os_name = factory.Iterator(['Ubuntu 20.04', 'Windows Server 2019', 'CentOS 7'])
    asset_type = Vulnerabilities.ASSET_TYPE_SERVER


class ServerVulnerabilityFactory(VulnerabilitiesFactory):
    """Factory for server vulnerabilities"""
    
    asset_type = Vulnerabilities.ASSET_TYPE_SERVER
    address = factory.Faker('ipv4')


class WebsiteVulnerabilityFactory(VulnerabilitiesFactory):
    """Factory for website vulnerabilities"""
    
    asset_type = Vulnerabilities.ASSET_TYPE_WEBSITE
    address = factory.Faker('url')


class CriticalVulnerabilityFactory(VulnerabilitiesFactory):
    """Factory for critical vulnerabilities"""
    
    severity = 'critical'
    score_cvss = factory.LazyFunction(lambda: Decimal('9.5'))
    score_cps = factory.LazyFunction(lambda: Decimal('0.95'))


class MediumVulnerabilityFactory(VulnerabilitiesFactory):
    """Factory for medium severity vulnerabilities"""
    
    severity = 'medium'
    score_cvss = factory.LazyFunction(lambda: Decimal('5.5'))
    score_cps = factory.LazyFunction(lambda: Decimal('0.50'))


class LowVulnerabilityFactory(VulnerabilitiesFactory):
    """Factory for low/warning vulnerabilities"""
    
    severity = 'warning'
    score_cvss = factory.LazyFunction(lambda: Decimal('3.0'))
    score_cps = factory.LazyFunction(lambda: Decimal('0.25'))


