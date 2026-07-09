"""
Helpers for building ``WWW-Authenticate`` Bearer challenges.

RFC 9728 §5.1 lets a protected resource point clients at its metadata document by
adding a ``resource_metadata`` parameter to the ``WWW-Authenticate`` challenge it
returns on a ``401 Unauthorized``. This module centralises construction of that
challenge string so the RFC 9728 opt-in mixin and decorator emit it consistently.
"""

from collections import OrderedDict

from .settings import oauth2_settings


# Sentinel distinguishing "caller did not specify a metadata URL" (derive the
# default) from an explicit ``None`` (omit ``resource_metadata`` entirely).
_UNSET = object()


def _quote(value):
    """Escape a value for inclusion in an RFC 7230 ``quoted-string``.

    Backslashes and double quotes are escaped with a backslash, and CR/LF are
    stripped, so an ``error_description`` (or any other value) cannot break out of
    the quoted string or inject additional header content.
    """
    value = str(value).replace("\r", "").replace("\n", "")
    return value.replace("\\", "\\\\").replace('"', '\\"')


def challenge_status(oauth2_error):
    """HTTP status for a Bearer challenge given oauthlib's ``oauth2_error``.

    Per RFC 6750 §3.1 a valid token with insufficient scope is an authorization
    failure (``403 Forbidden``), while a missing/invalid token is an authentication
    failure (``401 Unauthorized``). Both still carry a ``WWW-Authenticate`` header.
    """
    if oauth2_error and oauth2_error.get("error") == "insufficient_scope":
        return 403
    return 401


def build_bearer_challenge(request, oauth2_error=None, realm=None, resource_metadata_url=_UNSET):
    """Build a ``WWW-Authenticate: Bearer`` challenge value.

    ``oauth2_error`` is the structured error dict oauthlib stashes on the request
    during ``verify_request`` (``{"error": ..., "error_description": ...}``). A
    ``resource_metadata`` parameter pointing at the protected-resource metadata
    document is appended when available.

    ``resource_metadata_url`` controls which document is advertised: left unset it
    defaults to this server's root metadata route
    (``oauth2_settings.oauth2_resource_metadata_url``); pass an explicit URL to
    advertise the RFC 9728 path-component form for a path-based/multi-tenant
    resource, or ``None`` to omit the parameter.

    Parameters are rendered as comma-separated ``key="value"`` auth-params (no
    space after the comma, matching the DRF header builder), with values escaped
    for the quoted-string form; a bare ``Bearer`` is returned when there is nothing
    to advertise.
    """
    attributes = OrderedDict()
    if realm:
        attributes["realm"] = realm
    if oauth2_error:
        attributes.update(oauth2_error)
    if resource_metadata_url is _UNSET:
        resource_metadata_url = oauth2_settings.oauth2_resource_metadata_url(request)
    if resource_metadata_url:
        attributes["resource_metadata"] = resource_metadata_url
    if not attributes:
        return "Bearer"
    params = ",".join('{}="{}"'.format(key, _quote(value)) for key, value in attributes.items())
    return "Bearer " + params
