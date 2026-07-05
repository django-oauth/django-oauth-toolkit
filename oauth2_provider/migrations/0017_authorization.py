import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

from oauth2_provider.settings import oauth2_settings


class Migration(migrations.Migration):

    dependencies = [
        ("oauth2_provider", "0016_alter_devicegrant_scope"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Authorization",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                (
                    "grant_type",
                    models.CharField(
                        choices=[
                            ("authorization-code", "Authorization code"),
                            ("urn:ietf:params:oauth:grant-type:device_code", "Device Code"),
                            ("implicit", "Implicit"),
                            ("password", "Resource owner password-based"),
                            ("client-credentials", "Client credentials"),
                            ("openid-hybrid", "OpenID connect hybrid"),
                        ],
                        max_length=44,
                    ),
                ),
                ("scope", models.TextField(blank=True)),
                ("created", models.DateTimeField(auto_now_add=True)),
                ("updated", models.DateTimeField(auto_now=True)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                (
                    "application",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=oauth2_settings.APPLICATION_MODEL,
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="%(app_label)s_%(class)s",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "abstract": False,
                "swappable": "OAUTH2_PROVIDER_AUTHORIZATION_MODEL",
            },
        ),
        migrations.AddField(
            model_name="grant",
            name="authorization",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="%(app_label)s_%(class)s",
                to=oauth2_settings.AUTHORIZATION_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="grant",
            name="exchanged_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="accesstoken",
            name="authorization",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.RESTRICT,
                related_name="%(app_label)s_%(class)s",
                to=oauth2_settings.AUTHORIZATION_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="refreshtoken",
            name="authorization",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.RESTRICT,
                related_name="%(app_label)s_%(class)s",
                to=oauth2_settings.AUTHORIZATION_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="idtoken",
            name="authorization",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.RESTRICT,
                related_name="%(app_label)s_%(class)s",
                to=oauth2_settings.AUTHORIZATION_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="devicegrant",
            name="authorization",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="%(app_label)s_%(class)s",
                to=oauth2_settings.AUTHORIZATION_MODEL,
            ),
        ),
    ]
