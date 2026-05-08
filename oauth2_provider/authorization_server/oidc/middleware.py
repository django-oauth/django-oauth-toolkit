"""Middleware for OpenID Connect Session Management 1.0.

https://openid.net/specs/openid-connect-session-1_0.html
"""

import hashlib

from oauth2_provider.settings import oauth2_settings


class OIDCSessionManagementMiddleware:
    """
    Publish the OP User Agent state as a cookie the OP iframe can read.

    The iframe served by
    :class:`~oauth2_provider.authorization_server.oidc.views.SessionIFrameView` compares this
    cookie against the ``session_state`` a relying party received when it was authorized, so
    the RP learns that the End-User's login session changed without polling the OP.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if not oauth2_settings.OIDC_SESSION_MANAGEMENT_ENABLED:
            return response

        cookie_name = oauth2_settings.OIDC_SESSION_MANAGEMENT_COOKIE_NAME
        user = getattr(request, "user", None)
        is_authenticated = getattr(user, "is_authenticated", False)
        session = getattr(request, "session", None)
        session_key = getattr(session, "session_key", None)
        if is_authenticated and session_key is not None:
            session_key_bytes = session_key.encode("utf-8")
            hashed_key = hashlib.sha256(session_key_bytes).hexdigest()
            response.set_cookie(cookie_name, hashed_key, samesite="None", secure=True)
        else:
            response.delete_cookie(cookie_name, samesite="None")
        return response
