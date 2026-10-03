"""Tests for ``0029_rename_pushedauthorizationrequest``.

The pushed authorization request model is renamed to ``StoredAuthorizationRequest``.
The table is renamed in place, so a request that was stored before the upgrade, and
whose ``request_uri`` a client may still be holding, must come through unchanged, and
``request_uri`` must stay unique under the constraint's new name.

Each test provisions a throwaway sqlite database on its own alias, exactly as
``test_migration_0023_dedupe.py`` does, so nothing here touches the shared test databases.
"""

from datetime import timedelta

import pytest
from django.db import IntegrityError, connections, transaction
from django.db.migrations.executor import MigrationExecutor
from django.db.migrations.loader import MigrationLoader
from django.utils import timezone


ALIAS = "migration_0029"
BEFORE = ("oauth2_provider", "0028_application_client_display_metadata")
AFTER = ("oauth2_provider", "0029_rename_pushedauthorizationrequest")
REQUEST_URI = "urn:ietf:params:oauth:request_uri:before-the-upgrade"
PARAMETERS = {
    "client_id": "migration-client",
    "response_type": "code",
    "scope": "openid",
    "resource": ["https://api.example/a", "https://api.example/b"],
}


@pytest.fixture
def alias(db, settings, tmp_path):
    settings.DATABASE_ROUTERS = []
    connections.databases[ALIAS] = {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": str(tmp_path / "dot-migration-0029.sqlite3"),
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


def _migrate_to(target):
    executor = MigrationExecutor(connections[ALIAS])
    executor.migrate([target])
    return executor.loader.project_state([target]).apps


def _table_name(target, model_name):
    """The table the model has in the migration state at *target*.

    Django truncates table names to the default connection's identifier limit (30
    characters on Oracle), so they are read from the historical model rather than
    spelled out.
    """
    state = MigrationLoader(connections[ALIAS]).project_state([target])
    return state.apps.get_model("oauth2_provider", model_name)._meta.db_table


def _old_table():
    return _table_name(BEFORE, "PushedAuthorizationRequest")


def _new_table():
    return _table_name(AFTER, "StoredAuthorizationRequest")


def _tables():
    with connections[ALIAS].cursor() as cursor:
        return set(connections[ALIAS].introspection.table_names(cursor))


def _unique_constraints(table):
    with connections[ALIAS].cursor() as cursor:
        constraints = connections[ALIAS].introspection.get_constraints(cursor, table)
    return {
        name for name, info in constraints.items() if info["unique"] and info["columns"] == ["request_uri"]
    }


def _store_before_upgrade():
    apps_before = _migrate_to(BEFORE)
    PushedAuthorizationRequest = apps_before.get_model("oauth2_provider", "PushedAuthorizationRequest")
    return PushedAuthorizationRequest.objects.using(ALIAS).create(
        request_uri=REQUEST_URI,
        client_id="migration-client",
        parameters=PARAMETERS,
        expires=timezone.now() + timedelta(seconds=60),
    )


def test_stored_request_survives_the_rename(alias):
    stored = _store_before_upgrade()

    apps_after = _migrate_to(AFTER)
    StoredAuthorizationRequest = apps_after.get_model("oauth2_provider", "StoredAuthorizationRequest")
    renamed = StoredAuthorizationRequest.objects.using(alias).get(request_uri=REQUEST_URI)

    assert renamed.pk == stored.pk
    assert renamed.client_id == "migration-client"
    assert renamed.parameters == PARAMETERS
    assert renamed.expires == stored.expires
    assert renamed.created == stored.created
    assert _old_table() != _new_table()
    tables = _tables()
    assert _new_table() in tables
    assert _old_table() not in tables


def test_request_uri_stays_unique_under_the_new_constraint_name(alias):
    _store_before_upgrade()

    apps_after = _migrate_to(AFTER)
    assert _unique_constraints(_new_table()) == {
        "oauth2_provider_storedauthorizationrequest_unique_request_uri"
    }
    StoredAuthorizationRequest = apps_after.get_model("oauth2_provider", "StoredAuthorizationRequest")
    with pytest.raises(IntegrityError), transaction.atomic(using=alias):
        StoredAuthorizationRequest.objects.using(alias).create(
            request_uri=REQUEST_URI,
            client_id="another-client",
            parameters={},
            expires=timezone.now() + timedelta(seconds=60),
        )


def test_rename_is_reversible(alias):
    stored = _store_before_upgrade()
    _migrate_to(AFTER)

    apps_before = _migrate_to(BEFORE)
    PushedAuthorizationRequest = apps_before.get_model("oauth2_provider", "PushedAuthorizationRequest")
    restored = PushedAuthorizationRequest.objects.using(alias).get(request_uri=REQUEST_URI)

    assert restored.pk == stored.pk
    assert restored.parameters == PARAMETERS
    assert _unique_constraints(_old_table()) == {
        "oauth2_provider_pushedauthorizationrequest_unique_request_uri"
    }
    assert _new_table() not in _tables()


def test_swapped_install_skips_the_rename(alias, settings):
    # Swapped under the old setting name, migration 0025 never created the default table.
    settings.OAUTH2_PROVIDER_PAR_REQUEST_MODEL = "tests.SampleStoredAuthorizationRequest"
    _migrate_to(BEFORE)
    assert _old_table() not in _tables()

    # After renaming the setting, 0029 must decide "swapped?" by the new name and
    # skip the table rename, rather than rename a table that does not exist.
    del settings.OAUTH2_PROVIDER_PAR_REQUEST_MODEL
    settings.OAUTH2_PROVIDER_STORED_AUTHORIZATION_REQUEST_MODEL = "tests.SampleStoredAuthorizationRequest"
    _migrate_to(AFTER)
    assert _new_table() not in _tables()

    _migrate_to(BEFORE)
    assert _old_table() not in _tables()
