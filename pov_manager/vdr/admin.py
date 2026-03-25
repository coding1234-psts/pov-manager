from django.contrib import admin
from vdr.models import ThreatProfile


@admin.register(ThreatProfile)
class ThreatProfileAdmin(admin.ModelAdmin):
    fields = ('unique_id', 'organization_name', 'organization_email_domain', 'organization_domain',
              'se_email', 'tag_id', 'status', 'created_date', 'modified_data')

    readonly_fields = ('unique_id', 'created_date', 'modified_data')
