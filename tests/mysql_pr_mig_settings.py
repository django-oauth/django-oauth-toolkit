import os

import pymysql

from .mig_settings import *  # noqa: F401, F403


# Django's MySQL backend imports MySQLdb; PyMySQL provides that API for test-only usage.
pymysql.install_as_MySQLdb()

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": os.environ.get("MYSQL_DATABASE", "dot"),
        "USER": os.environ.get("MYSQL_USER", "dot"),
        "PASSWORD": os.environ.get("MYSQL_PASSWORD", "dot"),
        "HOST": os.environ.get("MYSQL_PRIMARY_HOST", os.environ.get("MYSQL_HOST", "host.docker.internal")),
        "PORT": os.environ.get("MYSQL_PRIMARY_PORT", os.environ.get("MYSQL_PORT", "53306")),
    },
    "replica": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": os.environ.get("MYSQL_REPLICA_DATABASE", os.environ.get("MYSQL_DATABASE", "dot")),
        "USER": os.environ.get("MYSQL_REPLICA_USER", os.environ.get("MYSQL_USER", "dot")),
        "PASSWORD": os.environ.get("MYSQL_REPLICA_PASSWORD", os.environ.get("MYSQL_PASSWORD", "dot")),
        "HOST": os.environ.get(
            "MYSQL_REPLICA_HOST",
            os.environ.get("MYSQL_PRIMARY_HOST", os.environ.get("MYSQL_HOST", "host.docker.internal")),
        ),
        "PORT": os.environ.get(
            "MYSQL_REPLICA_PORT",
            "53307",
        ),
        "TEST": {"MIRROR": "default"},
    },
}
