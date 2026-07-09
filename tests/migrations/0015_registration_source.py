from django.db import migrations, models


def forwards_set_dcr_source(apps, schema_editor):
    db_alias = schema_editor.connection.alias
    for model_name in ("BaseTestApplication", "SampleApplication"):
        Model = apps.get_model("tests", model_name)
        Model._default_manager.using(db_alias).filter(dcr_created=True).update(registration_source="dcr")


def reverse_set_dcr_created(apps, schema_editor):
    db_alias = schema_editor.connection.alias
    for model_name in ("BaseTestApplication", "SampleApplication"):
        Model = apps.get_model("tests", model_name)
        Model._default_manager.using(db_alias).filter(registration_source="dcr").update(dcr_created=True)


REGISTRATION_SOURCE_FIELD = models.CharField(
    choices=[
        ("manual", "Manual"),
        ("dcr", "Dynamic Client Registration"),
        ("cimd", "Client ID Metadata Document"),
    ],
    default="manual",
    help_text="How this application was registered (manual, DCR per RFC 7591, or CIMD)",
    max_length=32,
)


class Migration(migrations.Migration):
    dependencies = [
        ("tests", "0014_custompkaccesstoken_resource_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="basetestapplication",
            name="registration_source",
            field=REGISTRATION_SOURCE_FIELD,
        ),
        migrations.AddField(
            model_name="sampleapplication",
            name="registration_source",
            field=REGISTRATION_SOURCE_FIELD,
        ),
        migrations.RunPython(forwards_set_dcr_source, reverse_set_dcr_created),
        migrations.RemoveField(
            model_name="basetestapplication",
            name="dcr_created",
        ),
        migrations.RemoveField(
            model_name="sampleapplication",
            name="dcr_created",
        ),
    ]
