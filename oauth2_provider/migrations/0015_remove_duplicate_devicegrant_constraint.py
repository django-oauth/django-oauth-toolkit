from django.db import migrations, models


DUPLICATE_DEVICE_CODE_CONSTRAINT = "oauth2_provider_devicegrant_unique_device_code"


def remove_duplicate_device_code_constraint(apps, schema_editor):
    try:
        DeviceGrant = apps.get_model("oauth2_provider", "DeviceGrant")
    except LookupError:
        return

    if DeviceGrant._meta.swapped:
        return

    with schema_editor.connection.cursor() as cursor:
        constraints = schema_editor.connection.introspection.get_constraints(
            cursor,
            DeviceGrant._meta.db_table,
        )

    if DUPLICATE_DEVICE_CODE_CONSTRAINT not in constraints:
        return

    schema_editor.remove_constraint(
        DeviceGrant,
        models.UniqueConstraint(
            fields=["device_code"],
            name=DUPLICATE_DEVICE_CODE_CONSTRAINT,
        ),
    )


class Migration(migrations.Migration):
    dependencies = [
        ("oauth2_provider", "0014_alter_help_text"),
    ]

    operations = [
        migrations.RunPython(remove_duplicate_device_code_constraint, migrations.RunPython.noop),
    ]