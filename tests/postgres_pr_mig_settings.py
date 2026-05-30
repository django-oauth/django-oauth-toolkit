import os

from .mig_settings import *  # noqa: F401, F403


DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("POSTGRES_DB", "dot"),
        "USER": os.environ.get("POSTGRES_USER", "dot"),
        "PASSWORD": os.environ.get("POSTGRES_PASSWORD", "dot"),
        "HOST": os.environ.get(
            "POSTGRES_PRIMARY_HOST", os.environ.get("POSTGRES_HOST", "host.docker.internal")
        ),
        "PORT": os.environ.get("POSTGRES_PRIMARY_PORT", os.environ.get("POSTGRES_PORT", "55432")),
    },
    "replica": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("POSTGRES_REPLICA_DB", os.environ.get("POSTGRES_DB", "dot")),
        "USER": os.environ.get("POSTGRES_REPLICA_USER", os.environ.get("POSTGRES_USER", "dot")),
        "PASSWORD": os.environ.get("POSTGRES_REPLICA_PASSWORD", os.environ.get("POSTGRES_PASSWORD", "dot")),
        "HOST": os.environ.get(
            "POSTGRES_REPLICA_HOST", os.environ.get("POSTGRES_HOST", "host.docker.internal")
        ),
        "PORT": os.environ.get("POSTGRES_REPLICA_PORT", "55433"),
        "TEST": {"MIRROR": "default"},
    },
}
