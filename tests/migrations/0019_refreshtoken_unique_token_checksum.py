import oauth2_provider.models
from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("tests", "0018_refreshtoken_token_family_index"),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name="custompkrefreshtoken",
            unique_together=set(),
        ),
        migrations.AlterUniqueTogether(
            name="samplerefreshtoken",
            unique_together=set(),
        ),
        migrations.AlterField(
            model_name="custompkrefreshtoken",
            name="token_checksum",
            field=oauth2_provider.models.TokenChecksumField(
                db_index=True, max_length=64, unique=True, verbose_name="token checksum"
            ),
        ),
        migrations.AlterField(
            model_name="samplerefreshtoken",
            name="token_checksum",
            field=oauth2_provider.models.TokenChecksumField(
                db_index=True, max_length=64, unique=True, verbose_name="token checksum"
            ),
        ),
    ]
