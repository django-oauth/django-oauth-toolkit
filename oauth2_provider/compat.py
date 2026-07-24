"""Backward-compatible import shim.

``oauth2_provider.compat`` moved to ``oauth2_provider.core.compat`` when the package was reorganized
by OAuth2 role. Importing from this old path still works but is deprecated and
will be removed in django-oauth-toolkit 4.0.
"""

import sys
import warnings

from oauth2_provider.core import compat as _moved

warnings.warn(
    "oauth2_provider.compat has moved to oauth2_provider.core.compat. The old import path is "
    "deprecated and will be removed in django-oauth-toolkit 4.0.",
    DeprecationWarning,
    stacklevel=2,
)

# Alias the old module name to the moved module so every attribute (including
# private, underscore-prefixed names) resolves with identical object identity.
sys.modules[__name__] = _moved
