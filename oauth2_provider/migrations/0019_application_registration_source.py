from django.db import migrations, models


def forwards_set_dcr_source(apps, schema_editor):
    """Preserve provenance: applications flagged dcr_created become source="dcr"."""
    Application = apps.get_model("oauth2_provider", "Application")
    Application.objects.filter(dcr_created=True).update(registration_source="dcr")


def reverse_set_dcr_created(apps, schema_editor):
    """Restore the boolean from the enum so the migration is reversible."""
    Application = apps.get_model("oauth2_provider", "Application")
    Application.objects.filter(registration_source="dcr").update(dcr_created=True)


class Migration(migrations.Migration):
    dependencies = [
        ("oauth2_provider", "0018_resource_indicators"),
    ]

    operations = [
        migrations.AddField(
            model_name="application",
            name="registration_source",
            field=models.CharField(
                choices=[
                    ("manual", "Manual"),
                    ("dcr", "Dynamic Client Registration"),
                    ("cimd", "Client Initiated Metadata Discovery"),
                ],
                default="manual",
                help_text="How this application was registered (manual, DCR per RFC 7591, or CIMD)",
                max_length=32,
            ),
        ),
        migrations.RunPython(forwards_set_dcr_source, reverse_set_dcr_created),
        migrations.RemoveField(
            model_name="application",
            name="dcr_created",
        ),
    ]
