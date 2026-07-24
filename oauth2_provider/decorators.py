"""Backward-compatible import shim.

``oauth2_provider.decorators`` moved to ``oauth2_provider.resource_server.decorators`` when
the package was reorganized by OAuth2 role. Importing from this old path still
works but is deprecated and will be removed in django-oauth-toolkit 4.0.
"""

import sys
import warnings

from oauth2_provider.resource_server import decorators as _moved

warnings.warn(
    "oauth2_provider.decorators has moved to oauth2_provider.resource_server.decorators. "
    "The old import path is deprecated and will be removed in "
    "django-oauth-toolkit 4.0.",
    DeprecationWarning,
    stacklevel=2,
)

sys.modules[__name__] = _moved
