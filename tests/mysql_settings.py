import os

import pymysql

from .settings import *  # noqa: F401, F403


# Django's MySQL backend imports MySQLdb; PyMySQL provides that API for test-only usage.
pymysql.install_as_MySQLdb()

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": os.environ.get("MYSQL_DATABASE", "dot"),
        "USER": os.environ.get("MYSQL_USER", "dot"),
        "PASSWORD": os.environ.get("MYSQL_PASSWORD", "dot"),
        "HOST": os.environ.get("MYSQL_HOST", "127.0.0.1"),
        "PORT": os.environ.get("MYSQL_PORT", "53306"),
    }
}
