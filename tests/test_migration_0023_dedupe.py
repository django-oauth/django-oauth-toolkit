"""Tests for ``0023_refreshtoken_unique_token_checksum``'s duplicate cleanup (#1816).

The old ``unique_together`` of (token_checksum, revoked) enforced nothing, so existing
installs may hold several refresh tokens sharing one value. Making ``token_checksum``
unique means the extras have to go, and which row survives is the part that matters: a
live row is a credential some client is still using, so it must never lose to a revoked
one.

Each test provisions a throwaway sqlite database on its own alias, exactly as
``test_migration_db_alias.py`` does, so nothing here touches the shared test databases.
"""

import hashlib
from datetime import timedelta

import pytest
from django.db import IntegrityError, connection, connections
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone


ALIAS = "migration_0023"
BEFORE = ("oauth2_provider", "0022_refreshtoken_token_family_index")
AFTER = ("oauth2_provider", "0023_refreshtoken_unique_token_checksum")


@pytest.fixture
def alias(db, settings, tmp_path):
    settings.DATABASE_ROUTERS = []
    connections.databases[ALIAS] = {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": str(tmp_path / "dot-migration-0023.sqlite3"),
        "ATOMIC_REQUESTS": False,
        "AUTOCOMMIT": True,
        "CONN_MAX_AGE": 0,
        "CONN_HEALTH_CHECKS": False,
        "OPTIONS": {},
        "TIME_ZONE": None,
        "USER": "",
        "PASSWORD": "",
        "HOST": "",
        "PORT": "",
        "TEST": {"CHARSET": None, "COLLATION": None, "MIGRATE": True, "MIRROR": None, "NAME": None},
    }
    connection = None
    try:
        connection = connections[ALIAS]
        del connections.databases[ALIAS]
        yield ALIAS
    finally:
        connections.databases.pop(ALIAS, None)
        if connection is not None:
            connection.close()
            del connections[ALIAS]


def _migrate_to(target, using=ALIAS):
    executor = MigrationExecutor(connections[using])
    executor.migrate([target])
    return executor.loader.project_state([target]).apps


def _seed(apps, using=ALIAS):
    User = apps.get_model("auth", "User")
    Application = apps.get_model("oauth2_provider", "Application")
    user = User.objects.using(using).create(username="migration-user")
    application = Application.objects.using(using).create(
        name="migration-test-client",
        client_type="confidential",
        authorization_grant_type="client-credentials",
        client_secret="plain-secret",
    )
    return user, application


def _make_refresh_token(apps, user, application, token, revoked=None, created=None, using=ALIAS):
    RefreshToken = apps.get_model("oauth2_provider", "RefreshToken")
    refresh_token = RefreshToken.objects.using(using).create(
        user=user,
        application=application,
        token=token,
        token_checksum=hashlib.sha256(token.encode("utf-8")).hexdigest(),
        revoked=revoked,
    )
    if created is not None:
        # ``created`` is auto_now_add, so it has to be forced after the insert.
        RefreshToken.objects.using(using).filter(pk=refresh_token.pk).update(created=created)
        refresh_token.created = created
    return refresh_token


def test_live_row_survives_against_revoked_duplicates(alias):
    apps_before = _migrate_to(BEFORE)
    user, application = _seed(apps_before)
    now = timezone.now()

    # The live row is deliberately the *oldest*, so "newest wins" alone would drop it.
    live = _make_refresh_token(apps_before, user, application, "dup", created=now - timedelta(days=3))
    revoked_old = _make_refresh_token(
        apps_before,
        user,
        application,
        "dup",
        revoked=now - timedelta(days=2),
        created=now - timedelta(days=2),
    )
    revoked_new = _make_refresh_token(
        apps_before,
        user,
        application,
        "dup",
        revoked=now - timedelta(days=1),
        created=now - timedelta(days=1),
    )

    apps_after = _migrate_to(AFTER)
    RefreshToken = apps_after.get_model("oauth2_provider", "RefreshToken")
    surviving = list(RefreshToken.objects.using(alias).values_list("pk", flat=True))

    assert surviving == [live.pk]
    assert not RefreshToken.objects.using(alias).filter(pk__in=[revoked_old.pk, revoked_new.pk]).exists()


def test_newest_row_survives_when_none_are_live(alias):
    apps_before = _migrate_to(BEFORE)
    user, application = _seed(apps_before)
    now = timezone.now()

    older = _make_refresh_token(
        apps_before,
        user,
        application,
        "dup",
        revoked=now - timedelta(days=2),
        created=now - timedelta(days=2),
    )
    newer = _make_refresh_token(
        apps_before,
        user,
        application,
        "dup",
        revoked=now - timedelta(days=1),
        created=now - timedelta(days=1),
    )

    apps_after = _migrate_to(AFTER)
    RefreshToken = apps_after.get_model("oauth2_provider", "RefreshToken")

    assert list(RefreshToken.objects.using(alias).values_list("pk", flat=True)) == [newer.pk]
    assert not RefreshToken.objects.using(alias).filter(pk=older.pk).exists()


def test_distinct_tokens_are_left_alone_and_the_column_becomes_unique(alias):
    apps_before = _migrate_to(BEFORE)
    user, application = _seed(apps_before)

    keep_a = _make_refresh_token(apps_before, user, application, "one")
    keep_b = _make_refresh_token(apps_before, user, application, "two", revoked=timezone.now())

    apps_after = _migrate_to(AFTER)
    RefreshToken = apps_after.get_model("oauth2_provider", "RefreshToken")

    assert set(RefreshToken.objects.using(alias).values_list("pk", flat=True)) == {keep_a.pk, keep_b.pk}

    # The constraint is now in force, revoked rows included. Re-fetch the related rows
    # through the post-migration state: model classes are per-state and not interchangeable.
    user_after = apps_after.get_model("auth", "User").objects.using(ALIAS).get(pk=user.pk)
    application_after = (
        apps_after.get_model("oauth2_provider", "Application").objects.using(ALIAS).get(pk=application.pk)
    )
    with pytest.raises(IntegrityError):
        _make_refresh_token(apps_after, user_after, application_after, "two")


@pytest.fixture
def postgresql_default(transactional_db):
    # Unlike the sqlite alias above, the default database is shared with the rest of the
    # suite, so it is migrated back to the latest state before transactional_db flushes it.
    yield "default"
    executor = MigrationExecutor(connections["default"])
    executor.loader.build_graph()
    executor.migrate(executor.loader.graph.leaf_nodes())


@pytest.mark.skipif(
    connection.vendor != "postgresql",
    reason="Deferred foreign key checks are specific to PostgreSQL (#1961).",
)
def test_duplicates_are_removed_on_postgresql(postgresql_default):
    """
    PostgreSQL creates Django's foreign keys as DEFERRABLE INITIALLY DEFERRED. Deleting the
    duplicates queues their checks on the refresh token table until commit, and the
    following ALTER TABLE in the same migration transaction then fails with "cannot ALTER
    TABLE ... because it has pending trigger events" (#1961).
    """
    apps_before = _migrate_to(BEFORE, using=postgresql_default)
    user, application = _seed(apps_before, using=postgresql_default)
    keep = _make_refresh_token(apps_before, user, application, "dup", using=postgresql_default)
    drop = _make_refresh_token(
        apps_before, user, application, "dup", revoked=timezone.now(), using=postgresql_default
    )

    apps_after = _migrate_to(AFTER, using=postgresql_default)
    RefreshToken = apps_after.get_model("oauth2_provider", "RefreshToken")

    assert list(RefreshToken.objects.using(postgresql_default).values_list("pk", flat=True)) == [keep.pk]
    assert not RefreshToken.objects.using(postgresql_default).filter(pk=drop.pk).exists()
