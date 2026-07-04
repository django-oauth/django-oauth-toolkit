import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

import oauth2_provider.models


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        migrations.swappable_dependency(settings.OAUTH2_PROVIDER_APPLICATION_MODEL),
        ("tests", "0008_sampledevicegrant"),
    ]

    operations = [
        migrations.CreateModel(
            name="CustomPkAccessToken",
            fields=[
                ("token", models.TextField()),
                (
                    "token_checksum",
                    oauth2_provider.models.TokenChecksumField(db_index=True, max_length=64, unique=True),
                ),
                ("expires", models.DateTimeField()),
                ("scope", models.TextField(blank=True)),
                ("created", models.DateTimeField(auto_now_add=True)),
                ("updated", models.DateTimeField(auto_now=True)),
                (
                    "custom_pk",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "application",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.OAUTH2_PROVIDER_APPLICATION_MODEL,
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
            },
        ),
        migrations.CreateModel(
            name="CustomPkRefreshToken",
            fields=[
                ("token", models.CharField(max_length=255)),
                (
                    "token_family",
                    models.UUIDField(blank=True, editable=False, null=True),
                ),
                ("created", models.DateTimeField(auto_now_add=True)),
                ("updated", models.DateTimeField(auto_now=True)),
                ("revoked", models.DateTimeField(null=True)),
                (
                    "custom_pk",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "access_token",
                    models.OneToOneField(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="refresh_token",
                        to="tests.custompkaccesstoken",
                    ),
                ),
                (
                    "application",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.OAUTH2_PROVIDER_APPLICATION_MODEL,
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="%(app_label)s_%(class)s",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "abstract": False,
                "unique_together": {("token", "revoked")},
            },
        ),
    ]
