from .settings import *  # noqa: F401, F403


DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "file:memdb?mode=memory&cache=shared",
        "OPTIONS": {"uri": True},
    },
    "secondary": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "file:memdb?mode=memory&cache=shared",
        "OPTIONS": {"uri": True},
    },
}
DATABASE_ROUTERS = []
