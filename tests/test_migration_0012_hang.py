"""Deterministic reproduction for the issue #1591 migration hang.

Issue #1591 reports that applying migration ``0012_add_token_checksum`` hangs on a
primary/replica PostgreSQL topology (e.g. Aurora). The root cause is that the
``RunPython`` data migration originally read ``AccessToken`` through the default
manager. With a primary/replica database router in place, those *reads* are routed
to the ``replica`` alias -- a separate connection -- while the migration's DDL holds
an ``ACCESS EXCLUSIVE`` lock on the table inside the still-open migration transaction
on the ``default`` (primary) connection.

The fix pins the data-migration queries to ``schema_editor.connection.alias`` so the
read happens on the migration's own connection and never crosses to the replica.

This test reproduces the misrouting deterministically by:

1. Installing a primary/replica router so un-aliased reads go to ``replica``.
2. Setting ``statement_timeout`` on the replica connection so that, on a true
   streaming replica where the misrouted read blocks on the migration's lock, it
   fails fast with ``OperationalError`` instead of hanging CI until the global step
   timeout (always set a timeout -- never let a repro test freeze the pipeline).
3. Rolling the schema back to ``0011`` and applying ``0012``.

With the fix in place the migration completes (reads stay on the migration's own
primary connection). Without the fix the read is routed to the separate ``replica``
connection, and the failure mode depends on how that replica path is implemented:

* On the ``TEST: {"MIRROR": "default"}`` topology used here, the replica is a second
  connection to the same database that cannot see the migration transaction's
  uncommitted ``AddField``, so the read fails immediately with ``ProgrammingError:
  column ... does not exist``.
* On a real streaming replica (e.g. Aurora, as reported in #1591), the read can block
    behind lock replay or recovery-conflict handling while replay catches up with the
    DDL stream from primary. In that topology this is observed as an apparent hang until
    ``statement_timeout`` fires.
* With some connection-pooler/router deployments, transaction boundaries are managed
    per backend connection while ORM reads are still routed independently. If the
    migration transaction and the un-aliased read end up on different backend
    connections, this becomes the same cross-connection visibility/locking bug and may
    present as either blocking or schema-visibility errors.

Either way the migration raises rather than completing, so the test fails without the
fix and passes with it. The test is skipped on any backend that lacks a PostgreSQL
primary/replica topology, so it is safe to run in the full matrix and only does real
work in the ``pg16-pr`` environment.
"""

from datetime import timedelta
from unittest import skipUnless

from django.db import connection, connections
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase, override_settings
from django.utils import timezone


APP_LABEL = "oauth2_provider"
BEFORE_TARGET = (APP_LABEL, "0011_refreshtoken_token_family")
TARGET = (APP_LABEL, "0012_add_token_checksum")

REPLICA_ALIAS = "replica"
STATEMENT_TIMEOUT_MS = 5000

ROUTER_PATH = "tests.postgres_pr_router.PrimaryReplicaRouter"

REQUIRES_PRIMARY_REPLICA = connection.vendor == "postgresql" and REPLICA_ALIAS in connections


def _migrate(alias, target):
    executor = MigrationExecutor(connections[alias])
    executor.migrate([target])
    executor.loader.build_graph()
    return executor


def _set_statement_timeout(alias, value):
    with connections[alias].cursor() as cursor:
        cursor.execute(f"SET statement_timeout = {value}")


@skipUnless(
    REQUIRES_PRIMARY_REPLICA,
    "Requires a PostgreSQL primary/replica topology (pg16-pr environment).",
)
class TestMigration0012ReplicaHang(TransactionTestCase):
    databases = {"default", REPLICA_ALIAS}

    def setUp(self):
        super().setUp()
        # Roll the schema back to the state right before the problematic migration.
        _migrate("default", BEFORE_TARGET)

    def tearDown(self):
        # Always restore the database to the latest migration state so a mid-test
        # failure does not leave the schema in an intermediate state for later tests.
        _set_statement_timeout(REPLICA_ALIAS, "DEFAULT")
        executor = MigrationExecutor(connections["default"])
        executor.loader.build_graph()
        executor.migrate(executor.loader.graph.leaf_nodes())
        super().tearDown()

    @override_settings(DATABASE_ROUTERS=[ROUTER_PATH])
    def test_0012_does_not_hang_on_primary_replica_router(self):
        executor = MigrationExecutor(connections["default"])
        state = executor.loader.project_state(BEFORE_TARGET)
        apps = state.apps

        User = apps.get_model("auth", "User")
        Application = apps.get_model(APP_LABEL, "Application")
        AccessToken = apps.get_model(APP_LABEL, "AccessToken")

        user = User.objects.using("default").create(username="hang-repro-user")
        application = Application.objects.using("default").create(
            name="hang-repro-client",
            client_type="confidential",
            authorization_grant_type="client-credentials",
            client_secret="plain-secret",
        )
        AccessToken.objects.using("default").create(
            user=user,
            application=application,
            token="hang-repro-token",
            expires=timezone.now() + timedelta(days=1),
            scope="read",
        )

        # Fail fast instead of hanging: on a true streaming replica the misrouted
        # read blocks on the migration's replicated ACCESS EXCLUSIVE lock, so the
        # timeout aborts it with an OperationalError rather than freezing CI.
        _set_statement_timeout(REPLICA_ALIAS, STATEMENT_TIMEOUT_MS)

        # With the alias fix the data migration reads on its own (primary) connection
        # and this completes. Without the fix it is routed to the replica connection
        # and the migration raises instead of finishing.
        _migrate("default", TARGET)
