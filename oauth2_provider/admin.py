"""Backward-compatible import shim.

``oauth2_provider.admin`` moved to ``oauth2_provider.authorization_server.admin``
when the package was reorganized by OAuth2 role. This shim re-exports the moved
module without a DeprecationWarning, because Django's admin autodiscovery imports
``oauth2_provider.admin`` at startup. The old path is deprecated and will be
removed in django-oauth-toolkit 4.0.
"""

import sys

from oauth2_provider.authorization_server import admin as _moved

sys.modules[__name__] = _moved
