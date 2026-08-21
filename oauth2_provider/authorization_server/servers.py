"""
django-oauth-toolkit server classes.

These subclass the project's pre-configured OAuth 2.0 / OIDC ``Server`` classes to
register DOT's own grant-type handlers that oauthlib does not ship — currently
the RFC 7523 §2.1 JWT bearer grant. They are the default ``OAUTH2_SERVER_CLASS``
/ ``OIDC_SERVER_CLASS`` and remain drop-in replacements (a deployment overriding
those settings keeps full control).

``OIDCServer`` extends :class:`oauth2_provider.authorization_server.oidc.server.Server`
(oauthlib's OIDC server plus DOT's signed-UserInfo finalization) rather than
oauthlib's ``openid.Server`` directly, so enabling the grant does not give up the
signed-UserInfo behavior — and ``userinfo_signing_available`` still recognizes it
as a subclass of that ``Server``.

Registration of the JWT bearer grant is gated by ``JWT_BEARER_GRANT_ENABLED`` so
the token endpoint's accepted grant types do not change unless the feature is
turned on.
"""

from oauthlib.oauth2 import Server as OAuthLibServer

from oauth2_provider.authorization_server.grants import JWTBearerGrant
from oauth2_provider.authorization_server.oidc.server import Server as OIDCProviderServer
from oauth2_provider.core.rfc7523 import JWT_BEARER_GRANT_TYPE
from oauth2_provider.settings import oauth2_settings


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


class OIDCServer(OIDCProviderServer):
    """DOT's OpenID Provider ``Server`` plus DOT's custom grant handlers."""

    def __init__(self, request_validator, *args, **kwargs):
        super().__init__(request_validator, *args, **kwargs)
        register_jwt_bearer_grant(self, request_validator)
