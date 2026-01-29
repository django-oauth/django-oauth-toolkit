import logging

from django.db import migrations

import oauth2_provider.generators
import oauth2_provider.models
from oauth2_provider import settings


logger = logging.getLogger()


def forwards_func(apps, schema_editor):
    """
    Forward migration touches every application.client_secret which will cause it to be hashed if not already the case.
    """
    Application = apps.get_model(settings.APPLICATION_MODEL)
    applications = Application._default_manager.all()
    for application in applications:
        application.save(update_fields=['client_secret'])


def reverse_func(apps, schema_editor):
    warning_color_code = "\033[93m"
    end_color_code = "\033[0m"
    msg = f"\n{warning_color_code}The previously hashed client_secret cannot be reverted, and it remains hashed{end_color_code}"
    logger.warning(msg)


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2_provider', '0005_auto_20211222_2352'),
    ]

    operations = [
        migrations.AlterField(
            model_name='application',
            name='client_secret',
            field=oauth2_provider.models.ClientSecretField(blank=True, db_index=True, default=oauth2_provider.generators.generate_client_secret, help_text='Hashed on Save. Copy it now if this is a new secret.', max_length=255),
        ),
        migrations.RunPython(forwards_func, reverse_func),
    ]
