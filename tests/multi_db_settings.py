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
    # Keep ``default`` concrete so Django's test harness can use standard multi-db
    # setup while routers still drive real model placement to alpha/beta.
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    },
}
DATABASE_ROUTERS = ["tests.db_router.AlphaRouter", "tests.db_router.BetaRouter"]
