# Import the test settings and then override DATABASES.

from .settings import *  # noqa: F401, F403


DATABASES = {
    "alpha": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    },
    "beta": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    },
    # A usable default is required for Django's test infrastructure (TestCase
    # flush/rollback).  The DATABASE_ROUTERS below ensure that no application
    # data is ever written here; ``default`` exists solely so the test runner
    # can create cursors and manage transactions on it without crashing.
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    },
}
DATABASE_ROUTERS = ["tests.db_router.AlphaRouter", "tests.db_router.BetaRouter"]
