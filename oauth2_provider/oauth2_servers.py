"""
django-oauth-toolkit server classes.

These subclass oauthlib's pre-configured ``Server`` (OAuth 2.0) and
``openid.Server`` (OIDC) to register DOT's own grant-type handlers that oauthlib
does not ship — currently the RFC 7523 §2.1 JWT bearer grant. They are the
default ``OAUTH2_SERVER_CLASS`` / ``OIDC_SERVER_CLASS`` and remain drop-in
replacements for the oauthlib classes (a deployment overriding those settings
keeps full control).

Registration of the JWT bearer grant is gated by ``JWT_BEARER_GRANT_ENABLED`` so
the token endpoint's accepted grant types do not change unless the feature is
turned on.
"""

from oauthlib.oauth2 import Server as OAuthLibServer
from oauthlib.openid import Server as OAuthLibOIDCServer

from .oauth2_grants import JWT_BEARER_GRANT_TYPE, JWTBearerGrant
from .settings import oauth2_settings


def register_jwt_bearer_grant(server, request_validator):
    """Register the RFC 7523 JWT bearer grant on *server* when enabled.

    oauthlib's ``TokenEndpoint.grant_types`` is a mutable dict keyed by the
    grant-type string (the device-code grant is registered the same way), so
    adding an entry after ``__init__`` is the supported extension point.
    """
    if not oauth2_settings.JWT_BEARER_GRANT_ENABLED:
        return
    grant = JWTBearerGrant(
        request_validator,
        refresh_token=oauth2_settings.JWT_BEARER_ISSUE_REFRESH_TOKENS,
    )
    server.jwt_bearer_grant = grant
    server.grant_types[JWT_BEARER_GRANT_TYPE] = grant


class OAuth2Server(OAuthLibServer):
    """oauthlib OAuth 2.0 ``Server`` plus DOT's custom grant handlers."""

    def __init__(self, request_validator, *args, **kwargs):
        super().__init__(request_validator, *args, **kwargs)
        register_jwt_bearer_grant(self, request_validator)


class OIDCServer(OAuthLibOIDCServer):
    """oauthlib OIDC ``Server`` plus DOT's custom grant handlers."""

    def __init__(self, request_validator, *args, **kwargs):
        super().__init__(request_validator, *args, **kwargs)
        register_jwt_bearer_grant(self, request_validator)
