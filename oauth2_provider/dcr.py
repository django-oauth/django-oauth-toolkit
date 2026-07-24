"""Backward-compatible import shim.

``oauth2_provider.dcr`` moved to ``oauth2_provider.authorization_server.dcr`` when the package was reorganized
by OAuth2 role. Importing from this old path still works but is deprecated and
will be removed in django-oauth-toolkit 4.0.
"""

import sys
import warnings

from oauth2_provider.authorization_server import dcr as _moved

warnings.warn(
    "oauth2_provider.dcr has moved to oauth2_provider.authorization_server.dcr. The old import path is "
    "deprecated and will be removed in django-oauth-toolkit 4.0.",
    DeprecationWarning,
    stacklevel=2,
)

# Alias the old module name to the moved module so every attribute (including
# private, underscore-prefixed names) resolves with identical object identity.
sys.modules[__name__] = _moved
