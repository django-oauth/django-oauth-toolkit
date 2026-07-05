import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

from oauth2_provider.settings import oauth2_settings


class Migration(migrations.Migration):

    dependencies = [
        ("oauth2_provider", "0017_authorization"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Session",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("sid", models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ("session_key", models.CharField(blank=True, db_index=True, default="", max_length=40)),
                ("authenticated_at", models.DateTimeField()),
                ("expires", models.DateTimeField()),
                ("created", models.DateTimeField(auto_now_add=True)),
                ("updated", models.DateTimeField(auto_now=True)),
                ("terminated_at", models.DateTimeField(blank=True, null=True)),
                (
                    "termination_reason",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("logout", "Logout"),
                            ("rp_logout", "RP-Initiated Logout"),
                            ("expired", "Expired"),
                            ("admin", "Terminated by admin"),
                        ],
                        default="",
                        max_length=32,
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
                "swappable": "OAUTH2_PROVIDER_SESSION_MODEL",
            },
        ),
        migrations.AddField(
            model_name="authorization",
            name="session",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="%(app_label)s_%(class)s",
                to=oauth2_settings.SESSION_MODEL,
            ),
        ),
    ]
