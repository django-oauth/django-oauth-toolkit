import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("tests", "0007_add_localidtoken"),
    ]

    operations = [
        migrations.CreateModel(
            name="SampleDeviceGrant",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("device_code", models.CharField(max_length=100, unique=True)),
                ("user_code", models.CharField(max_length=100)),
                ("scope", models.CharField(max_length=64, null=True)),
                ("interval", models.IntegerField(default=5)),
                ("expires", models.DateTimeField()),
                (
                    "status",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("authorized", "Authorized"),
                            ("authorization-pending", "Authorization pending"),
                            ("expired", "Expired"),
                            ("denied", "Denied"),
                        ],
                        default="authorization-pending",
                        max_length=64,
                    ),
                ),
                ("client_id", models.CharField(db_index=True, max_length=100)),
                ("last_checked", models.DateTimeField(auto_now=True)),
                ("custom_field", models.CharField(blank=True, default="", max_length=255)),
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
                "swappable": "OAUTH2_PROVIDER_DEVICE_GRANT_MODEL",
                "constraints": [
                    models.UniqueConstraint(
                        fields=("device_code",),
                        name="tests_sampledevicegrant_unique_device_code",
                    )
                ],
            },
        ),
    ]
