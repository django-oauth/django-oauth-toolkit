"""Regression tests for #1591: RunPython data migrations must honor the DB alias.

``0006_alter_application_client_secret`` and ``0012_add_token_checksum`` backfill
data with ``RunPython``. Before the fix their queries ignored
``schema_editor.connection.alias``, so applying them to a non-default database
(``migrate --database=secondary``) read from and wrote to the *default* alias
instead of the database actually being migrated.

Each test provisions its own throwaway sqlite database and registers it as a
temporary ``secondary`` alias for the duration of the test only. Nothing here
touches the shared test databases or their migration state, so these tests are
safe to run (and meaningful) in every environment of the matrix regardless of
backend, topology, or configured routers.
"""

import hashlib
from datetime import timedelta

import pytest
from django.contrib.auth.hashers import check_password
from django.db import connections
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone


SECONDARY_ALIAS = "secondary"


@pytest.fixture
def secondary_alias(db, settings, tmp_path):
    """Register a throwaway sqlite database as a temporary non-default alias.

    Depending on the ``db`` fixture guarantees the pytest-django database setup has
    already run, so the alias is invisible to it: the alias is created after setup
    and removed again before teardown. Routers are cleared because environments
    like ``tests.multi_db_settings`` install routers whose ``allow_migrate`` would
    skip every operation on an unknown alias.

    The settings entry is registered only long enough to instantiate the cached
    connection wrapper and is then removed again: Django's test harness forbids
    connections to configured-but-undeclared aliases but explicitly allows
    dynamically created connections (see ``SimpleTestCase.ensure_connection_patch_method``).
    """
    settings.DATABASE_ROUTERS = []
    db_path = tmp_path / "dot-secondary-migration-tests.sqlite3"
    connections.databases[SECONDARY_ALIAS] = {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": str(db_path),
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
        # Instantiate (and cache) the connection wrapper while the settings entry
        # exists, then drop the entry so the alias counts as dynamically created.
        connection = connections[SECONDARY_ALIAS]
        del connections.databases[SECONDARY_ALIAS]
        yield SECONDARY_ALIAS
    finally:
        connections.databases.pop(SECONDARY_ALIAS, None)
        if connection is not None:
            connection.close()
            del connections[SECONDARY_ALIAS]


def _migrate_to(alias, target):
    connection = connections[alias]
    executor = MigrationExecutor(connection)
    executor.migrate([target])
    state = executor.loader.project_state([target])
    return state.apps


def test_migration_0006_hashes_client_secret_on_non_default_alias(secondary_alias):
    apps_before = _migrate_to(secondary_alias, ("oauth2_provider", "0005_auto_20211222_2352"))
    ApplicationBefore = apps_before.get_model("oauth2_provider", "Application")

    application = ApplicationBefore.objects.using(secondary_alias).create(
        name="migration-test-client",
        client_type="confidential",
        authorization_grant_type="client-credentials",
        client_secret="plain-secret",
    )

    apps_after = _migrate_to(secondary_alias, ("oauth2_provider", "0006_alter_application_client_secret"))
    ApplicationAfter = apps_after.get_model("oauth2_provider", "Application")
    migrated_application = ApplicationAfter.objects.using(secondary_alias).get(pk=application.pk)

    assert migrated_application.client_secret != "plain-secret"
    assert check_password("plain-secret", migrated_application.client_secret)


def test_migration_0012_backfills_token_checksum_on_non_default_alias(secondary_alias):
    apps_before = _migrate_to(secondary_alias, ("oauth2_provider", "0011_refreshtoken_token_family"))

    User = apps_before.get_model("auth", "User")
    Application = apps_before.get_model("oauth2_provider", "Application")
    AccessTokenBefore = apps_before.get_model("oauth2_provider", "AccessToken")

    user = User.objects.using(secondary_alias).create(username="migration-user")
    application = Application.objects.using(secondary_alias).create(
        name="migration-test-client",
        client_type="confidential",
        authorization_grant_type="client-credentials",
        client_secret="plain-secret",
    )

    token_value = "token-to-checksum"
    access_token = AccessTokenBefore.objects.using(secondary_alias).create(
        user=user,
        application=application,
        token=token_value,
        expires=timezone.now() + timedelta(days=1),
        scope="read",
    )

    apps_after = _migrate_to(secondary_alias, ("oauth2_provider", "0012_add_token_checksum"))
    AccessTokenAfter = apps_after.get_model("oauth2_provider", "AccessToken")
    migrated_access_token = AccessTokenAfter.objects.using(secondary_alias).get(pk=access_token.pk)

    expected_checksum = hashlib.sha256(token_value.encode("utf-8")).hexdigest()
    assert migrated_access_token.token_checksum == expected_checksum
