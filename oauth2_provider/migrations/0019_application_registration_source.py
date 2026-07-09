from django.db import migrations, models

from oauth2_provider.settings import oauth2_settings


def forwards_set_dcr_source(apps, schema_editor):
    """Preserve provenance: applications flagged dcr_created become source="dcr"."""
    Application = apps.get_model(oauth2_settings.APPLICATION_MODEL)
    if Application._meta.label_lower != "oauth2_provider.application":
        # The application model is swapped out. The schema operations in this
        # migration are skipped for swapped models, so the swapped app has to add
        # registration_source and backfill it in its own migration (see CHANGELOG).
        return
    db_alias = schema_editor.connection.alias
    Application._default_manager.using(db_alias).filter(dcr_created=True).update(registration_source="dcr")


def reverse_set_dcr_created(apps, schema_editor):
    """Restore the boolean from the enum so the migration is reversible."""
    Application = apps.get_model(oauth2_settings.APPLICATION_MODEL)
    if Application._meta.label_lower != "oauth2_provider.application":
        return
    db_alias = schema_editor.connection.alias
    Application._default_manager.using(db_alias).filter(registration_source="dcr").update(dcr_created=True)


class Migration(migrations.Migration):
    dependencies = [
        ("oauth2_provider", "0018_resource_indicators"),
        migrations.swappable_dependency(oauth2_settings.APPLICATION_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="application",
            name="registration_source",
            field=models.CharField(
                choices=[
                    ("manual", "Manual"),
                    ("dcr", "Dynamic Client Registration"),
                    ("cimd", "Client ID Metadata Document"),
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
