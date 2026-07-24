"""Backward-compatible import shim.

``oauth2_provider.views.generic`` has moved to
``oauth2_provider.resource_server.views.generic``.

Importing from this old path still works but is deprecated and will be removed
in django-oauth-toolkit 4.0.
"""

import sys
import warnings

from oauth2_provider.resource_server.views import generic as _moved


warnings.warn(
    "oauth2_provider.views.generic has moved to oauth2_provider.resource_server.views.generic. "
    "The old import path is deprecated and will be removed in "
    "django-oauth-toolkit 4.0.",
    DeprecationWarning,
    stacklevel=2,
)

sys.modules[__name__] = _moved
