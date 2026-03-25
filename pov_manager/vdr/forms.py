from django.forms import ModelForm
from vdr.models import ThreatProfile


class ThreatProfileForm(ModelForm):
    class Meta:
        model = ThreatProfile
        fields = ['organization_name', 'organization_email_domains', 'organization_domain', 'organization_emails',
                  'ip_ranges', 'se_email', 'vivun_activity']
