"""Backward-compatible import shim.

``oauth2_provider.views.dynamic_client_registration`` has moved to
``oauth2_provider.authorization_server.views.dynamic_client_registration``.

Importing from this old path still works but is deprecated and will be removed
in django-oauth-toolkit 4.0.
"""

import sys
import warnings

from oauth2_provider.authorization_server.views import dynamic_client_registration as _moved


warnings.warn(
    "oauth2_provider.views.dynamic_client_registration has moved to "
    "oauth2_provider.authorization_server.views.dynamic_client_registration. "
    "The old import path is deprecated and will be removed in "
    "django-oauth-toolkit 4.0.",
    DeprecationWarning,
    stacklevel=2,
)

sys.modules[__name__] = _moved
