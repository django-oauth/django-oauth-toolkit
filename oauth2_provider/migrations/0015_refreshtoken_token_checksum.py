import hashlib

from django.db import migrations, models

import oauth2_provider.models
from oauth2_provider.settings import oauth2_settings


def forwards_func(apps, schema_editor):
    """
    Backfill token_checksum for existing refresh tokens.

    The checksum is computed explicitly instead of relying on
    TokenChecksumField.pre_save because bulk_update does not call pre_save.
    """
    RefreshToken = apps.get_model(oauth2_settings.REFRESH_TOKEN_MODEL)
    if RefreshToken._meta.label_lower != "oauth2_provider.refreshtoken":
        # The refresh token model is swapped out. The schema operations in this
        # migration are skipped for swapped models, so the swapped app has to add
        # the field and backfill it in its own migration (see CHANGELOG).
        return
    db_alias = schema_editor.connection.alias
    batch = []
    for refresh_token in RefreshToken._default_manager.using(db_alias).only("pk", "token").iterator():
        refresh_token.token_checksum = hashlib.sha256(refresh_token.token.encode("utf-8")).hexdigest()
        batch.append(refresh_token)
        if len(batch) >= 1000:
            RefreshToken._default_manager.using(db_alias).bulk_update(batch, ["token_checksum"])
            batch = []
    if batch:
        RefreshToken._default_manager.using(db_alias).bulk_update(batch, ["token_checksum"])


class Migration(migrations.Migration):
    dependencies = [
        ("oauth2_provider", "0014_alter_help_text"),
        migrations.swappable_dependency(oauth2_settings.REFRESH_TOKEN_MODEL),
    ]

    operations = [
        # Add the checksum column as nullable first so existing rows migrate cleanly.
        migrations.AddField(
            model_name="refreshtoken",
            name="token_checksum",
            field=oauth2_provider.models.TokenChecksumField(blank=True, null=True, max_length=64),
        ),
        # Drop the old unique_together before widening token: MySQL cannot keep
        # a TEXT column in an index without an explicit prefix length.
        migrations.AlterUniqueTogether(
            name="refreshtoken",
            unique_together=set(),
        ),
        migrations.AlterField(
            model_name="refreshtoken",
            name="token",
            field=models.TextField(),
        ),
        migrations.RunPython(forwards_func, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="refreshtoken",
            name="token_checksum",
            field=oauth2_provider.models.TokenChecksumField(blank=False, max_length=64),
        ),
        migrations.AlterUniqueTogether(
            name="refreshtoken",
            unique_together={("token_checksum", "revoked")},
        ),
    ]
