"""Backward-compatible shim for the metadata views.

These views were split by OAuth2 role when the package was reorganized:

* RFC 8414 authorization-server metadata + the shared discovery helpers ->
  :mod:`oauth2_provider.authorization_server.views.metadata`
* RFC 9728 protected-resource metadata ->
  :mod:`oauth2_provider.resource_server.views.metadata`

Importing from this module is deprecated and will be removed in
django-oauth-toolkit 4.0.
"""

import warnings

from oauth2_provider.authorization_server.views.metadata import (
    OAuthServerMetadataView,
    ServerMetadataViewMixin,
    _is_implicit_response_type,
    bcp_filter_code_challenge_methods,
    bcp_filter_response_types,
)
from oauth2_provider.resource_server.views.metadata import OAuthProtectedResourceMetadataView


__all__ = [
    "OAuthServerMetadataView",
    "OAuthProtectedResourceMetadataView",
    "ServerMetadataViewMixin",
    "bcp_filter_response_types",
    "bcp_filter_code_challenge_methods",
    "_is_implicit_response_type",
]

warnings.warn(
    "oauth2_provider.views.metadata has moved: the RFC 8414 authorization-server "
    "metadata view is now in oauth2_provider.authorization_server.views.metadata and "
    "the RFC 9728 protected-resource metadata view in "
    "oauth2_provider.resource_server.views.metadata. The old import path is "
    "deprecated and will be removed in django-oauth-toolkit 4.0.",
    DeprecationWarning,
    stacklevel=2,
)
