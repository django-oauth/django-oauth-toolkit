import os
import sys

import django

from .settings import *  # noqa: F401, F403


# Django's Oracle backend imported cx_Oracle directly until 5.0. python-oracledb
# exposes the same DB-API surface, so alias it the way tests/mysql_settings.py
# aliases PyMySQL to MySQLdb; Django 5.0+ prefers oracledb on its own. oracledb's
# default "thin" mode speaks the wire protocol natively, so no Oracle Instant
# Client has to be installed on the runner.
if django.VERSION < (5, 0):
    import oracledb

    # Django 4.2 rejects cx_Oracle older than 7.0 by inspecting Database.version.
    oracledb.version = "8.3.0"
    sys.modules["cx_Oracle"] = oracledb

# django.db.backends.oracle.utils.dsn() passes NAME to makedsn() as a *SID* whenever
# PORT is set, and an RDS multitenant instance (engine oracle-ee-cdb) is reachable
# only by the pluggable database's service name. HOST/PORT therefore stay unset so
# that NAME is used verbatim as an Easy Connect descriptor: host:port/service_name.
ORACLE_DSN = os.environ.get(
    "ORACLE_DSN",
    "{}:{}/{}".format(
        os.environ.get("ORACLE_HOST", "127.0.0.1"),
        os.environ.get("ORACLE_PORT", "1521"),
        os.environ.get("ORACLE_SERVICE_NAME", "FREEPDB1"),
    ),
)
ORACLE_USER = os.environ.get("ORACLE_USER", "dot")
ORACLE_PASSWORD = os.environ.get("ORACLE_PASSWORD", "dot")

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.oracle",
        "NAME": ORACLE_DSN,
        "USER": ORACLE_USER,
        "PASSWORD": ORACLE_PASSWORD,
        "TEST": {
            # Oracle has no notion of several databases under one user, so Django's
            # test runner normally creates a throwaway user and tablespace, which
            # needs CREATE USER, DROP USER and CREATE TABLESPACE. The CI schema is
            # provisioned up front with only the five privileges the test run needs
            # (see docs/contributing.rst), so both creation steps are switched off
            # and the suite runs in the schema it connects as. Nothing is dropped at
            # the end of a run either, which is why the tox env empties the schema
            # first via tests.oracle_reset_schema.
            "CREATE_DB": False,
            "CREATE_USER": False,
            "USER": ORACLE_USER,
            "PASSWORD": ORACLE_PASSWORD,
        },
    }
}
