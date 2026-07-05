from django.db import migrations, models

import oauth2_provider.models


class Migration(migrations.Migration):
    dependencies = [
        ("tests", "0009_custompkaccesstoken_and_more"),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name="samplerefreshtoken",
            unique_together=set(),
        ),
        migrations.AlterField(
            model_name="samplerefreshtoken",
            name="token",
            field=models.TextField(),
        ),
        migrations.AddField(
            model_name="samplerefreshtoken",
            name="token_checksum",
            field=oauth2_provider.models.TokenChecksumField(default="", max_length=64),
            preserve_default=False,
        ),
        migrations.AlterUniqueTogether(
            name="samplerefreshtoken",
            unique_together={("token_checksum", "revoked")},
        ),
        migrations.AlterUniqueTogether(
            name="custompkrefreshtoken",
            unique_together=set(),
        ),
        migrations.AlterField(
            model_name="custompkrefreshtoken",
            name="token",
            field=models.TextField(),
        ),
        migrations.AddField(
            model_name="custompkrefreshtoken",
            name="token_checksum",
            field=oauth2_provider.models.TokenChecksumField(default="", max_length=64),
            preserve_default=False,
        ),
        migrations.AlterUniqueTogether(
            name="custompkrefreshtoken",
            unique_together={("token_checksum", "revoked")},
        ),
    ]
