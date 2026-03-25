import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vdr', '0026_vulnerabilities_description_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='DmarcScanResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain', models.CharField(db_index=True, max_length=200)),
                ('overall_score', models.IntegerField(blank=True, null=True)),
                ('headline', models.CharField(blank=True, max_length=100, null=True)),
                ('summary', models.TextField(blank=True, null=True)),
                ('impersonation_score', models.IntegerField(blank=True, null=True)),
                ('privacy_score', models.IntegerField(blank=True, null=True)),
                ('branding_score', models.IntegerField(blank=True, null=True)),
                ('impersonation_protocols', models.JSONField(blank=True, default=dict, null=True)),
                ('privacy_protocols', models.JSONField(blank=True, default=dict, null=True)),
                ('branding_protocols', models.JSONField(blank=True, default=dict, null=True)),
                ('scan_status', models.CharField(choices=[('pending', 'Pending'), ('success', 'Success'), ('failed', 'Failed'), ('timeout', 'Timeout')], default='pending', max_length=20)),
                ('error_message', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_scanned_at', models.DateTimeField(blank=True, null=True)),
                ('threat_profile', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='dmarc_results', to='vdr.threatprofile')),
            ],
            options={
                'db_table': 'dmarc_scan_results',
                'ordering': ['-updated_at'],
                'indexes': [
                    models.Index(fields=['threat_profile', 'domain'], name='dmarc_scan__threat_p_fd4527_idx'),
                    models.Index(fields=['scan_status'], name='dmarc_scan__scan_st_9dbdb8_idx'),
                    models.Index(fields=['last_scanned_at'], name='dmarc_scan__last_sc_b55d40_idx'),
                ],
                'unique_together': {('threat_profile', 'domain')},
            },
        ),
    ]
