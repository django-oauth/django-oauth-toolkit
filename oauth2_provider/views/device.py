"""Backward-compatible import shim.

``oauth2_provider.views.device`` has moved to
``oauth2_provider.authorization_server.views.device``.

Importing from this old path still works but is deprecated and will be removed
in django-oauth-toolkit 4.0.
"""

import sys
import warnings

from oauth2_provider.authorization_server.views import device as _moved


warnings.warn(
    "oauth2_provider.views.device has moved to oauth2_provider.authorization_server.views.device. "
    "The old import path is deprecated and will be removed in "
    "django-oauth-toolkit 4.0.",
    DeprecationWarning,
    stacklevel=2,
)

sys.modules[__name__] = _moved
