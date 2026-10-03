"""Tests for ``0031_grant_consumed_token_family``.

``Grant.token_family`` ties the refresh tokens issued from an authorization code back to
it, so a reuse of the code revokes them (RFC 6749 §4.1.2). Grants stored before the
upgrade must not share a family -- a one-step ``AddField`` with a callable default would
give them all the same UUID, and a reuse of one code would then revoke the tokens issued
from every other. They are left without a family; grants created afterwards each get
their own.

Each test provisions a throwaway sqlite database on its own alias, exactly as
``test_migration_0029_rename_stored_request.py`` does, so nothing here touches the shared
test databases.
"""

from datetime import timedelta

import pytest
from django.db import connections
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone


ALIAS = "migration_0031"
BEFORE = ("oauth2_provider", "0030_application_request_objects")
AFTER = ("oauth2_provider", "0031_grant_consumed_token_family")


@pytest.fixture
def alias(db, settings, tmp_path):
    settings.DATABASE_ROUTERS = []
    connections.databases[ALIAS] = {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": str(tmp_path / "dot-migration-0031.sqlite3"),
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


def _create_grant(apps, code):
    User = apps.get_model("auth", "User")
    Application = apps.get_model("oauth2_provider", "Application")
    user, _ = User.objects.using(ALIAS).get_or_create(username="migration-user")
    application, _ = Application.objects.using(ALIAS).get_or_create(
        name="migration-app",
        defaults={
            "user": user,
            "client_type": "confidential",
            "authorization_grant_type": "authorization-code",
            "redirect_uris": "https://example.org/cb",
        },
    )
    Grant = apps.get_model("oauth2_provider", "Grant")
    return Grant.objects.using(ALIAS).create(
        user=user,
        application=application,
        code=code,
        expires=timezone.now() + timedelta(seconds=60),
        redirect_uri="https://example.org/cb",
    )


def test_existing_grants_do_not_share_a_token_family(alias):
    apps_before = _migrate_to(BEFORE)
    _create_grant(apps_before, "before-1")
    _create_grant(apps_before, "before-2")

    apps_after = _migrate_to(AFTER)
    Grant = apps_after.get_model("oauth2_provider", "Grant")

    stored = Grant.objects.using(alias).filter(code__in=["before-1", "before-2"])
    assert [(grant.token_family, grant.consumed) for grant in stored] == [(None, None), (None, None)]


def test_new_grants_each_get_a_token_family(alias):
    apps_after = _migrate_to(AFTER)

    first = _create_grant(apps_after, "after-1")
    second = _create_grant(apps_after, "after-2")

    assert first.token_family is not None
    assert second.token_family is not None
    assert first.token_family != second.token_family
