"""Backward-compatible import shim.

``oauth2_provider.middleware`` moved to ``oauth2_provider.resource_server.middleware`` when
the package was reorganized by OAuth2 role. Importing from this old path still
works but is deprecated and will be removed in django-oauth-toolkit 4.0.
"""

import sys
import warnings

from oauth2_provider.resource_server import middleware as _moved

warnings.warn(
    "oauth2_provider.middleware has moved to oauth2_provider.resource_server.middleware. "
    "The old import path is deprecated and will be removed in "
    "django-oauth-toolkit 4.0.",
    DeprecationWarning,
    stacklevel=2,
)

sys.modules[__name__] = _moved
