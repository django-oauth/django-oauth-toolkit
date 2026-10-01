import os

from .settings import *  # noqa: F401, F403


# django.db.backends.oracle.utils.dsn() passes NAME to makedsn() as a *SID* whenever PORT is
# set, but the container is only reachable by its pluggable database's *service* name.
# HOST and PORT therefore stay unset so that NAME is used verbatim as an Easy Connect
# string: host:port/service_name.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.oracle",
        "NAME": "{}:{}/{}".format(
            os.environ.get("ORACLE_HOST", "127.0.0.1"),
            os.environ.get("ORACLE_PORT", "51521"),
            os.environ.get("ORACLE_SERVICE", "FREEPDB1"),
        ),
        "USER": os.environ.get("ORACLE_USER", "system"),
        "PASSWORD": os.environ.get("ORACLE_PASSWORD", "dot"),
        "TEST": {
            # Django's Oracle test runner creates (and drops) its own test user and
            # tablespaces. Name them explicitly rather than taking the test_system /
            # test_system.dbf defaults derived from USER.
            "USER": "test_dot",
            "PASSWORD": "dot",
            "TBLSPACE": "test_dot",
            "TBLSPACE_TMP": "test_dot_temp",
        },
    }
}
