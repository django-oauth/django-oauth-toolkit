import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

from oauth2_provider.settings import oauth2_settings


class Migration(migrations.Migration):
    dependencies = [
        ("oauth2_provider", "0025_pushed_authorization_requests"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        migrations.swappable_dependency(oauth2_settings.APPLICATION_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="grant",
            name="exchanged_at",
            field=models.DateTimeField(blank=True, null=True, verbose_name="exchanged at"),
        ),
        migrations.CreateModel(
            name="Authorization",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                (
                    "client_id",
                    models.CharField(db_index=True, max_length=255, verbose_name="client ID"),
                ),
                (
                    "grant_type",
                    models.CharField(
                        choices=[
                            ("authorization-code", "Authorization code"),
                            (
                                "urn:ietf:params:oauth:grant-type:device_code",
                                "Device Code",
                            ),
                            ("implicit", "Implicit"),
                            ("password", "Resource owner password-based"),
                            ("client-credentials", "Client credentials"),
                            ("openid-hybrid", "OpenID connect hybrid"),
                        ],
                        max_length=64,
                        verbose_name="grant type",
                    ),
                ),
                ("scope", models.TextField(blank=True, verbose_name="scope")),
                (
                    "authorization_details",
                    models.JSONField(
                        blank=True,
                        default=None,
                        null=True,
                        verbose_name="authorization details",
                    ),
                ),
                (
                    "created",
                    models.DateTimeField(auto_now_add=True, verbose_name="created"),
                ),
                (
                    "updated",
                    models.DateTimeField(auto_now=True, verbose_name="updated"),
                ),
                (
                    "revoked_at",
                    models.DateTimeField(blank=True, null=True, verbose_name="revoked at"),
                ),
                (
                    "application",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="%(app_label)s_%(class)s",
                        to=oauth2_settings.APPLICATION_MODEL,
                        verbose_name="application",
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
                        verbose_name="user",
                    ),
                ),
            ],
            options={
                "abstract": False,
                "swappable": "OAUTH2_PROVIDER_AUTHORIZATION_MODEL",
            },
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
                verbose_name="authorization",
            ),
        ),
        migrations.AddField(
            model_name="devicegrant",
            name="authorization",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="%(app_label)s_%(class)s",
                to=oauth2_settings.AUTHORIZATION_MODEL,
                verbose_name="authorization",
            ),
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
                verbose_name="authorization",
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
                verbose_name="authorization",
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
                verbose_name="authorization",
            ),
        ),
    ]
