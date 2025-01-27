"""Session state for OpenID Connect Session Management 1.0.

https://openid.net/specs/openid-connect-session-1_0.html

The OP User Agent state derived here is what both halves of session management
compare: it is hashed into the ``session_state`` returned with an authorization
response, and published to the browser by
:class:`~oauth2_provider.authorization_server.oidc.middleware.OIDCSessionManagementMiddleware`
so the OP iframe can tell a relying party whether the End-User's login session
still is the one that authorized it.
"""

import hashlib

from django.conf import settings

from oauth2_provider.settings import oauth2_settings


def session_management_state_key(request):
    """
    Determine value to use as session state.
    """

    # Prefer the actual session cookie value when available, since some
    # session engines (e.g. signed-cookie sessions) do not provide a
    # usable session_key.
    cookie_name = getattr(settings, "SESSION_COOKIE_NAME", None)
    session_cookie_value = None
    if cookie_name:
        session_cookie_value = request.COOKIES.get(cookie_name)
    if session_cookie_value is not None:
        raw_key = session_cookie_value
    elif getattr(request, "session", None) is not None and getattr(request.session, "session_key", None):
        raw_key = request.session.session_key
    else:
        raw_key = str(oauth2_settings.OIDC_SESSION_MANAGEMENT_DEFAULT_SESSION_KEY)
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
