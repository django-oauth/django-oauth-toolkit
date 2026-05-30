import os

from .settings import *  # noqa: F401, F403


DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("POSTGRES_DB", "dot"),
        "USER": os.environ.get("POSTGRES_USER", "dot"),
        "PASSWORD": os.environ.get("POSTGRES_PASSWORD", "dot"),
        "HOST": os.environ.get("POSTGRES_HOST", "127.0.0.1"),
        "PORT": os.environ.get("POSTGRES_PORT", "55432"),
    }
}
