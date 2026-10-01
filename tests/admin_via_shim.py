"""Fixture for ``tests/test_import_compat.py``: a project admin module that subclasses the
library admin via the deprecated ``oauth2_provider.admin`` path (issue #1860).

Deliberately not named ``admin`` so Django admin autodiscovery never imports it; the test
points ``APPLICATION_ADMIN_CLASS`` at it so it is imported *while*
``oauth2_provider.authorization_server.admin`` is resolving that setting at import time.
"""

from oauth2_provider.admin import ApplicationAdmin as BaseApplicationAdmin  # old path, on purpose


class ShimApplicationAdmin(BaseApplicationAdmin):
    pass
