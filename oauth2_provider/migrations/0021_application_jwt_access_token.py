from django.db import migrations, models

from oauth2_provider.settings import oauth2_settings


class Migration(migrations.Migration):
    dependencies = [
        ("oauth2_provider", "0020_cimd_application_fields"),
        migrations.swappable_dependency(oauth2_settings.APPLICATION_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="application",
            name="jwt_access_token",
            field=models.BooleanField(
                default=False,
                help_text=(
                    'Issue RFC 9068 JWT access tokens ("at+jwt") for this application, signed '
                    "with its algorithm, instead of opaque random tokens."
                ),
            ),
        ),
    ]
