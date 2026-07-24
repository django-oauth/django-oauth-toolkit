"""Backward-compatible import shim.

``oauth2_provider.www_authenticate`` moved to
``oauth2_provider.resource_server.www_authenticate`` when the package was
reorganized by OAuth2 role. Importing from this old path still works but is
deprecated and will be removed in django-oauth-toolkit 4.0.
"""

import warnings

from oauth2_provider.resource_server.www_authenticate import *  # noqa: F401,F403
from oauth2_provider.resource_server.www_authenticate import (  # noqa: F401
    build_bearer_challenge,
    challenge_status,
)

warnings.warn(
    "oauth2_provider.www_authenticate has moved to "
    "oauth2_provider.resource_server.www_authenticate. The old import path is "
    "deprecated and will be removed in django-oauth-toolkit 4.0.",
    DeprecationWarning,
    stacklevel=2,
)
