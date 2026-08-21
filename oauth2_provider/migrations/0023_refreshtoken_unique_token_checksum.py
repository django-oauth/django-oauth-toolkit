from django.db import migrations, models

import oauth2_provider.models
from oauth2_provider.settings import oauth2_settings


BATCH_SIZE = 1000


def delete_duplicate_checksums(apps, schema_editor):
    """
    Drop duplicate refresh tokens so ``token_checksum`` can be made unique.

    The old ``unique_together`` of (token_checksum, revoked) enforced nothing -- NULLs are
    distinct in a unique index on every backend the toolkit supports -- so deployments may
    hold several rows sharing one token value. They cannot all survive a unique column, and
    a revoked duplicate cannot be kept the way the live/revoked split previously allowed, so
    the extras are deleted.

    The survivor is the live row when there is one, so an active client is never logged out;
    otherwise it is the most recently created row. Deleting refresh tokens does not cascade
    into access tokens: ``AccessToken.source_refresh_token`` is ``SET_NULL``, and
    ``RefreshToken.access_token`` is the forward side of its own relation.
    """
    RefreshToken = apps.get_model(oauth2_settings.REFRESH_TOKEN_MODEL)
    if RefreshToken._meta.label_lower != "oauth2_provider.refreshtoken":
        # The refresh token model is swapped out. The schema operations in this migration
        # are skipped for swapped models, so the swapped app has to deduplicate and add the
        # constraint in its own migration (see CHANGELOG).
        return
    db_alias = schema_editor.connection.alias
    manager = RefreshToken._default_manager.using(db_alias)

    duplicated = (
        manager.values("token_checksum")
        .annotate(row_count=models.Count("pk"))
        .filter(row_count__gt=1)
        .values_list("token_checksum", flat=True)
    )
    # Bounded by the number of *duplicated* values rather than the table size, and read in
    # one pass so the aggregate is not re-run for every batch of deletions.
    checksums = list(duplicated)
    for start in range(0, len(checksums), BATCH_SIZE):
        doomed = []
        for checksum in checksums[start : start + BATCH_SIZE]:
            rows = list(manager.filter(token_checksum=checksum).values_list("pk", "revoked", "created"))
            # Live first (``revoked is None``), then most recently created, then highest pk.
            # Sorted in Python rather than with order_by so the NULL-ordering of the
            # ``revoked`` column does not vary by backend.
            survivor = max(rows, key=lambda row: (row[1] is None, row[2], row[0]))[0]
            doomed.extend(pk for pk, _revoked, _created in rows if pk != survivor)
        if doomed:
            manager.filter(pk__in=doomed).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("oauth2_provider", "0022_refreshtoken_token_family_index"),
        migrations.swappable_dependency(oauth2_settings.REFRESH_TOKEN_MODEL),
    ]

    operations = [
        # Drop the old key before deduplicating: (token_checksum, revoked) would otherwise
        # still be in force while rows are removed.
        migrations.AlterUniqueTogether(
            name="refreshtoken",
            unique_together=set(),
        ),
        migrations.RunPython(delete_duplicate_checksums, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="refreshtoken",
            name="token_checksum",
            field=oauth2_provider.models.TokenChecksumField(
                db_index=True, max_length=64, unique=True, verbose_name="token checksum"
            ),
        ),
    ]
