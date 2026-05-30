import hashlib
import os
import tempfile
from copy import deepcopy
from datetime import timedelta

import pytest
from django.contrib.auth.hashers import check_password
from django.db import connections
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone

SECONDARY_ALIAS = "secondary"


@pytest.fixture(scope="session")
def django_db_modify_db_settings(django_db_modify_db_settings_parallel_suffix, request):
    secondary_db = deepcopy(connections.databases["default"])
    secondary_db.setdefault("TEST", {})
    secondary_db["TEST"] = deepcopy(secondary_db["TEST"])
    secondary_db["TEST"]["MIRROR"] = None

    # Keep alias on the active backend so this regression test runs on every DB platform.
    if secondary_db["ENGINE"] == "django.db.backends.sqlite3":
        fd, secondary_db_path = tempfile.mkstemp(prefix="dot-secondary-migration-tests-", suffix=".sqlite3")
        os.close(fd)
        secondary_db["NAME"] = secondary_db_path
        secondary_db["TEST"]["NAME"] = None

        def _cleanup_secondary_db():
            try:
                os.remove(secondary_db_path)
            except FileNotFoundError:
                pass

        request.addfinalizer(_cleanup_secondary_db)

    connections.databases[SECONDARY_ALIAS] = secondary_db


def _migrate_to(alias, target):
    connection = connections[alias]
    executor = MigrationExecutor(connection)
    executor.migrate([target])
    state = executor.loader.project_state([target])
    return state.apps


@pytest.mark.django_db(databases="__all__", transaction=True)
def test_migration_0006_hashes_client_secret_on_non_default_alias():
    apps_before = _migrate_to(SECONDARY_ALIAS, ("oauth2_provider", "0005_auto_20211222_2352"))
    ApplicationBefore = apps_before.get_model("oauth2_provider", "Application")

    application = ApplicationBefore.objects.using(SECONDARY_ALIAS).create(
        name="migration-test-client",
        client_type="confidential",
        authorization_grant_type="client-credentials",
        client_secret="plain-secret",
    )

    apps_after = _migrate_to(SECONDARY_ALIAS, ("oauth2_provider", "0006_alter_application_client_secret"))
    ApplicationAfter = apps_after.get_model("oauth2_provider", "Application")
    migrated_application = ApplicationAfter.objects.using(SECONDARY_ALIAS).get(pk=application.pk)

    assert migrated_application.client_secret != "plain-secret"
    assert check_password("plain-secret", migrated_application.client_secret)


@pytest.mark.django_db(databases="__all__", transaction=True)
def test_migration_0012_backfills_token_checksum_on_non_default_alias():
    apps_before = _migrate_to(SECONDARY_ALIAS, ("oauth2_provider", "0011_refreshtoken_token_family"))

    User = apps_before.get_model("auth", "User")
    Application = apps_before.get_model("oauth2_provider", "Application")
    AccessTokenBefore = apps_before.get_model("oauth2_provider", "AccessToken")

    user = User.objects.using(SECONDARY_ALIAS).create(username="migration-user")
    application = Application.objects.using(SECONDARY_ALIAS).create(
        name="migration-test-client",
        client_type="confidential",
        authorization_grant_type="client-credentials",
        client_secret="plain-secret",
    )

    token_value = "token-to-checksum"
    access_token = AccessTokenBefore.objects.using(SECONDARY_ALIAS).create(
        user=user,
        application=application,
        token=token_value,
        expires=timezone.now() + timedelta(days=1),
        scope="read",
    )

    apps_after = _migrate_to(SECONDARY_ALIAS, ("oauth2_provider", "0012_add_token_checksum"))
    AccessTokenAfter = apps_after.get_model("oauth2_provider", "AccessToken")
    migrated_access_token = AccessTokenAfter.objects.using(SECONDARY_ALIAS).get(pk=access_token.pk)

    expected_checksum = hashlib.sha256(token_value.encode("utf-8")).hexdigest()
    assert migrated_access_token.token_checksum == expected_checksum
