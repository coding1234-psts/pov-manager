from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vdr', '0027_dmarcscanresult'),
    ]

    operations = [
        migrations.AddField(
            model_name='threatprofile',
            name='ai_exposure_scan_time',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='threatprofile',
            name='ai_exposure_report_html',
            field=models.CharField(
                blank=True,
                help_text='Basename of HTML report under CTU_REPORTS_PATH',
                max_length=255,
                null=True,
            ),
        ),
        migrations.AddField(
            model_name='threatprofile',
            name='ai_exposure_findings_json',
            field=models.CharField(
                blank=True,
                help_text='Basename of full findings JSON under CTU_REPORTS_PATH',
                max_length=255,
                null=True,
            ),
        ),
        migrations.AddField(
            model_name='threatprofile',
            name='ai_exposure_powerpoint_json',
            field=models.CharField(
                blank=True,
                help_text='Basename of compact PowerPoint-oriented JSON under CTU_REPORTS_PATH',
                max_length=255,
                null=True,
            ),
        ),
    ]
