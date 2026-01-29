from .multi_db_settings import *  # noqa: F401, F403


OAUTH2_PROVIDER = {
    # The other two tokens will be in alpha. This will cause a failure when the
    # app's ready method is called.
    "ID_TOKEN_MODEL": "tests.LocalIDToken",
}
