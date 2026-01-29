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
    # As https://docs.djangoproject.com/en/4.2/topics/db/multi-db/#defining-your-databases
    # indicates, it is ok to have no default database.
    "default": {},
}
DATABASE_ROUTERS = ["tests.db_router.AlphaRouter", "tests.db_router.BetaRouter"]
