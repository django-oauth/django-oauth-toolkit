# Import the test settings and then override DATABASES.

from .settings import *  # noqa: F401, F403


DATABASES = {
    "alpha": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
        # Django implicitly adds ``default`` to every database's TEST DEPENDENCIES.
        # Since there is no usable ``default`` database here, that implicit dependency
        # can never be resolved and database setup fails with a circular dependency.
        # Declaring no dependencies avoids it.
        "TEST": {"DEPENDENCIES": []},
    },
    "beta": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
        "TEST": {"DEPENDENCIES": []},
    },
    # As https://docs.djangoproject.com/en/4.2/topics/db/multi-db/#defining-your-databases
    # indicates, it is ok to have no default database.
    "default": {},
}
DATABASE_ROUTERS = ["tests.db_router.AlphaRouter", "tests.db_router.BetaRouter"]
