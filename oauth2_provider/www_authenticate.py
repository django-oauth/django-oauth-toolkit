"""
Helpers for building ``WWW-Authenticate`` Bearer challenges.

RFC 9728 §5.1 lets a protected resource point clients at its metadata document by
adding a ``resource_metadata`` parameter to the ``WWW-Authenticate`` challenge it
returns on a ``401 Unauthorized``. This module centralises construction of that
challenge string so the RFC 9728 opt-in mixin and decorator emit it consistently.
"""

from collections import OrderedDict

from .settings import oauth2_settings


def build_bearer_challenge(request, oauth2_error=None, realm=None):
    """Build a ``WWW-Authenticate: Bearer`` challenge value.

    ``oauth2_error`` is the structured error dict oauthlib stashes on the request
    during ``verify_request`` (``{"error": ..., "error_description": ...}``). When
    the RFC 9728 metadata route is registered, a ``resource_metadata`` parameter
    pointing at the protected-resource metadata document is appended.

    Parameters are rendered as RFC 6750 comma-separated ``key="value"`` auth-params;
    a bare ``Bearer`` is returned when there is nothing to advertise.
    """
    attributes = OrderedDict()
    if realm:
        attributes["realm"] = realm
    if oauth2_error:
        attributes.update(oauth2_error)
    metadata_url = oauth2_settings.oauth2_resource_metadata_url(request)
    if metadata_url:
        attributes["resource_metadata"] = metadata_url
    if not attributes:
        return "Bearer"
    return "Bearer " + ", ".join('{}="{}"'.format(key, value) for key, value in attributes.items())
