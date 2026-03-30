from uuid import uuid4
from django.db import models
from django.contrib.postgres.fields import ArrayField
from core.models import User


class ThreatProfile(models.Model):
    STATUS_CREATED = 'CREATED'
    STATUS_TAG_CREATED = 'TAG_CREATED'
    STATUS_SCANS_SCHEDULED = 'SCANS_SCHEDULED'
    STATUS_VULNERABILITY_RESULTS_COLLECTED = 'VULNERABILITY_RESULTS_COLLECTED'
    STATUS_VULNERABILITY_RESULTS_PROCESSED = 'VULNERABILITY_RESULTS_PROCESSED'
    STATUS_CTU_AUTOBRIEF_DATA_PROCESSED = 'CTU_AUTOBRIEF_DATA_PROCESSED'
    STATUS_CTU_AUTOBRIEF_REPORT_REQUESTED = 'CTU_AUTOBRIEF_REPORT_REQUESTED'
    STATUS_CTU_AUTOBRIEF_REPORT_AVAILABLE = 'CTU_AUTOBRIEF_REPORT_AVAILABLE'

    STATUS_CTU_AUTOBRIEF_REPORT_REQUESTED_WITHOUT_VDR = 'CTU_AUTOBRIEF_REPORT_REQUESTED_WITHOUT_VDR'
    STATUS_CTU_AUTOBRIEF_REPORT_AVAILABLE_WITHOUT_VDR = 'CTU_AUTOBRIEF_REPORT_AVAILABLE_WITHOUT_VDR'

    STATUS_CHOICES = (
        (STATUS_CREATED, 'Profile created'),
        (STATUS_TAG_CREATED, 'VDR Tag created'),
        (STATUS_SCANS_SCHEDULED, 'Scans scheduled'),
        (STATUS_VULNERABILITY_RESULTS_COLLECTED, 'Vulnerability results collected'),
        (STATUS_VULNERABILITY_RESULTS_PROCESSED, 'Vulnerability results processed'),
        (STATUS_CTU_AUTOBRIEF_DATA_PROCESSED, 'CTU Autobrief data processed'),
        (STATUS_CTU_AUTOBRIEF_REPORT_REQUESTED, 'CTU Autobrief report requested'),
        (STATUS_CTU_AUTOBRIEF_REPORT_AVAILABLE, 'CTU Autobrief report available'),

        (STATUS_CTU_AUTOBRIEF_REPORT_REQUESTED_WITHOUT_VDR, 'CTU Autobrief report requested without VDR'),
        (STATUS_CTU_AUTOBRIEF_REPORT_AVAILABLE_WITHOUT_VDR, 'CTU Autobrief report available without VDR')
    )

    AI_EXPOSURE_JOB_QUEUED = 'queued'
    AI_EXPOSURE_JOB_RUNNING = 'running'
    AI_EXPOSURE_JOB_READY = 'ready'
    AI_EXPOSURE_JOB_FAILED = 'failed'
    AI_EXPOSURE_JOB_SKIPPED = 'skipped'
    AI_EXPOSURE_JOB_CHOICES = (
        ('', 'Not set (legacy)'),
        (AI_EXPOSURE_JOB_QUEUED, 'Queued'),
        (AI_EXPOSURE_JOB_RUNNING, 'Running'),
        (AI_EXPOSURE_JOB_READY, 'Ready'),
        (AI_EXPOSURE_JOB_FAILED, 'Failed'),
        (AI_EXPOSURE_JOB_SKIPPED, 'Skipped (no domain)'),
    )
    AI_EXPOSURE_JOB_TERMINAL = frozenset({
        AI_EXPOSURE_JOB_READY,
        AI_EXPOSURE_JOB_FAILED,
        AI_EXPOSURE_JOB_SKIPPED,
    })

    unique_id = models.UUIDField(default=uuid4, editable=False, unique=True)
    organization_name = models.CharField(max_length=200, null=False, blank=False)
    organization_email_domains = ArrayField(base_field=models.CharField(max_length=200, null=True, blank=True),
                                            null=True,
                                            blank=True,
                                            default=list)
    organization_domain = models.CharField(max_length=200, null=True, blank=True)
    organization_emails = ArrayField(base_field=models.EmailField(max_length=200, null=True, blank=True),
                                     null=True,
                                     blank=True,
                                     default=list)
    ip_ranges = ArrayField(base_field=models.CharField(max_length=200, null=True, blank=True),
                           null=True,
                           blank=True,
                           default=list)
    se_email = models.EmailField(max_length=200, null=True, blank=True)
    tag_id = models.CharField(max_length=50, null=True, blank=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default=STATUS_CREATED, null=False, blank=False)
    ctu_autobrief_data = models.JSONField(default=dict, null=True, blank=True)
    ctu_autobrief_report_id = models.CharField(max_length=50, null=True, blank=True)
    ai_exposure_scan_time = models.DateTimeField(null=True, blank=True)
    ai_exposure_report_html = models.CharField(
        max_length=255, null=True, blank=True,
        help_text='Basename of HTML report under CTU_REPORTS_PATH',
    )
    ai_exposure_findings_json = models.CharField(
        max_length=255, null=True, blank=True,
        help_text='Basename of full findings JSON under CTU_REPORTS_PATH',
    )
    ai_exposure_powerpoint_json = models.CharField(
        max_length=255, null=True, blank=True,
        help_text='Basename of compact PowerPoint-oriented JSON under CTU_REPORTS_PATH',
    )
    ai_exposure_job_status = models.CharField(
        max_length=20,
        choices=AI_EXPOSURE_JOB_CHOICES,
        default='',
        blank=True,
        help_text='Background AI exposure job state for CTU autobrief alignment',
    )
    ai_exposure_job_error = models.TextField(null=True, blank=True)
    vivun_activity = models.CharField(max_length=6, null=False, blank=False, default='000000')
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    created_date = models.DateTimeField(auto_now_add=True)
    modified_data = models.DateTimeField(auto_now=True)


class Vulnerabilities(models.Model):
    ASSET_TYPE_SERVER = 'server'
    ASSET_TYPE_WEBSITE = 'website'

    ASSET_TYPES_CHOICES = (
        (ASSET_TYPE_SERVER, 'Server'),
        (ASSET_TYPE_WEBSITE, 'Website')
    )

    threat_profile = models.ForeignKey(ThreatProfile, on_delete=models.CASCADE, null=False, blank=False)
    address = models.CharField(max_length=200, null=True, blank=True)
    ip = models.CharField(max_length=100, null=True, blank=True)
    severity = models.CharField(max_length=20, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    location = models.TextField(null=True, blank=True)
    cve_number = models.CharField(max_length=50, null=True, blank=True)
    remedy = models.TextField(null=True, blank=True)
    references = models.TextField(null=True, blank=True)
    report_id = models.IntegerField(null=True, blank=True)
    vulnerability_id = models.CharField(max_length=50, null=True, blank=True)
    score_cvss = models.DecimalField(max_digits=4, decimal_places=2, null=True, blank=True)
    score_cps = models.DecimalField(max_digits=7, decimal_places=5, null=True, blank=True)
    group_description = models.TextField(max_length=300, null=True, blank=True)
    group_differentiator = models.CharField(max_length=200, null=True, blank=True)
    os_family = models.CharField(max_length=100, null=True, blank=True)
    os_name = models.CharField(max_length=100, null=True, blank=True)
    asset_type = models.CharField(max_length=20, choices=ASSET_TYPES_CHOICES, null=True, blank=True)


class DmarcScanResult(models.Model):
    """Stores DMARC scan results for each domain"""

    threat_profile = models.ForeignKey(
        ThreatProfile,
        on_delete=models.CASCADE,
        related_name='dmarc_results'
    )
    domain = models.CharField(max_length=200, db_index=True)

    # Overall metrics
    overall_score = models.IntegerField(null=True, blank=True)
    headline = models.CharField(max_length=100, null=True, blank=True)
    summary = models.TextField(null=True, blank=True)

    # Category scores
    impersonation_score = models.IntegerField(null=True, blank=True)
    privacy_score = models.IntegerField(null=True, blank=True)
    branding_score = models.IntegerField(null=True, blank=True)

    # Detailed results stored as JSON
    impersonation_protocols = models.JSONField(null=True, blank=True, default=dict)
    privacy_protocols = models.JSONField(null=True, blank=True, default=dict)
    branding_protocols = models.JSONField(null=True, blank=True, default=dict)

    # Metadata
    scan_status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('success', 'Success'),
            ('failed', 'Failed'),
            ('timeout', 'Timeout'),
        ],
        default='pending'
    )
    error_message = models.TextField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_scanned_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'dmarc_scan_results'
        unique_together = ['threat_profile', 'domain']
        ordering = ['-updated_at']
        indexes = [
            models.Index(fields=['threat_profile', 'domain']),
            models.Index(fields=['scan_status']),
            models.Index(fields=['last_scanned_at']),
        ]

    def __str__(self):
        return f"{self.domain} - {self.threat_profile} ({self.scan_status})"

    def get_all_issues(self):
        """Extract all danger/warning status items across all protocols"""
        issues = []

        for category_name, protocols in [
            ('Impersonation', self.impersonation_protocols),
            ('Privacy', self.privacy_protocols),
            ('Branding', self.branding_protocols),
        ]:
            if not protocols:
                continue

            for protocol_name, protocol_data in protocols.items():
                records = protocol_data.get('records', [])
                for record in records:
                    if record.get('status') in ['danger', 'warning']:
                        issues.append({
                            'category': category_name,
                            'protocol': protocol_name,
                            'label': record.get('label'),
                            'description': record.get('description'),
                            'status': record.get('status'),
                        })

        return issues

    def get_top_findings(self):
        """
        Extract top findings (danger items only) formatted for output
        Returns list of strings in format:
        "PROTOCOL: LABEL - description"
        """
        findings = []

        for category_name, protocols in [
            ('Impersonation', self.impersonation_protocols),
            ('Privacy', self.privacy_protocols),
            ('Branding', self.branding_protocols),
        ]:
            if not protocols:
                continue

            for protocol_name, protocol_data in protocols.items():
                records = protocol_data.get('records', [])

                for record in records:
                    if record.get('status') == 'danger':
                        label = record.get('label', '')
                        description = record.get('description', '')

                        # Clean up whitespace/newlines
                        description = description.replace("\n", "").strip()

                        # Include protocol name
                        finding = f"{protocol_name}: {label} - {description}"
                        findings.append(finding)

        return findings
