from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vdr', '0025_alter_vulnerabilities_os_name'),
    ]

    operations = [
        migrations.AddField(
            model_name='vulnerabilities',
            name='description',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='vulnerabilities',
            name='references',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='vulnerabilities',
            name='remedy',
            field=models.TextField(blank=True, null=True),
        ),
    ]
