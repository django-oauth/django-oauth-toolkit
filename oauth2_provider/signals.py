"""Backward-compatible import shim.

``oauth2_provider.signals`` moved to ``oauth2_provider.core.signals`` when the package was reorganized by
OAuth2 role. Importing from this old path still works but is deprecated and will
be removed in django-oauth-toolkit 4.0.
"""

import warnings

from oauth2_provider.core.signals import *  # noqa: F401,F403

warnings.warn(
    "oauth2_provider.signals has moved to oauth2_provider.core.signals. The old import path is "
    "deprecated and will be removed in django-oauth-toolkit 4.0.",
    DeprecationWarning,
    stacklevel=2,
)
