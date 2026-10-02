from datetime import timedelta

from django.conf import settings
from django.contrib.auth.middleware import AuthenticationMiddleware
from django.contrib.sessions.middleware import SessionMiddleware

from oauth2_provider.oauth2_validators import OAuth2Validator


# get_response is required for middleware, it doesn't need to do anything
# the way we're using it, so we just use a lambda that returns None
def get_response():
    None


class CustomOAuth2Validator(OAuth2Validator):
    def validate_silent_login(self, request) -> bool:
        # request is an OAuthLib.common.Request and doesn't have the session
        # or user of the django request. We will emulate the session and auth
        # middleware here, since that is what the idp is using for auth. You
        # may need to modify this if you are using a different session
        # middleware or auth backend.

        session_cookie_name = settings.SESSION_COOKIE_NAME
        # HTTP_COOKIE is missing from request.headers entirely when the user
        # agent sends no Cookie header at all. That is the normal case for a
        # prompt=none request in a hidden third-party iframe under a browser
        # that partitions or blocks third-party cookies (Firefox's Total Cookie
        # Protection): there is no OP session to authenticate against, so the
        # request must resolve to login_required rather than raising.
        cookie_header = request.headers.get("HTTP_COOKIE") or ""
        session_key = None
        for cookie in cookie_header.split(";"):
            # partition() rather than split("="): a cookie value may itself
            # contain "=" (base64 padding, for one), which unpacking rejects.
            name, _, value = cookie.strip().partition("=")
            if name == session_cookie_name:
                session_key = value
                break
        if not session_key:
            return False

        session_middleware = SessionMiddleware(get_response)
        session = session_middleware.SessionStore(session_key)
        # add session to request for compatibility with django.contrib.auth
        request.session = session

        # call the auth middleware to set request.user
        auth_middleware = AuthenticationMiddleware(get_response)
        auth_middleware.process_request(request)
        return request.user.is_authenticated

    def validate_silent_authorization(self, request) -> bool:
        return True

    def get_additional_claims(self, request):
        # Standard OIDC claims sourced from the Django user and its idp.models.UserProfile.
        # django-oauth-toolkit filters each claim by the granted scope via
        # ``oidc_claim_scope`` (e.g. ``email`` is only emitted when the ``email`` scope was
        # granted, the ``profile`` claims only with the ``profile`` scope), so returning
        # them unconditionally here is safe. With OIDC_COMPLIANT_SCOPE_CLAIMS enabled they
        # are returned from UserInfo, and in the ID Token only for response_type=id_token
        # (OIDC Core §5.4), giving the compliance suite real claims to assert.
        user = request.user
        claims = {
            "name": user.get_full_name() or user.get_username(),
            "given_name": user.first_name,
            "family_name": user.last_name,
            "preferred_username": user.get_username(),
            "email": user.email,
        }
        # email_verified etc. come from the profile only: the stock Django user model
        # does not track whether the address was verified, and emitting bool(email)
        # would misrepresent it.
        profile = getattr(user, "oidc_profile", None)
        if profile is not None:
            claims.update(profile.profile_claims())
            claims["email_verified"] = profile.email_verified
            if profile.phone_number:
                claims["phone_number"] = profile.phone_number
                claims["phone_number_verified"] = profile.phone_number_verified
            address = profile.address_claim()
            if address:
                claims["address"] = address
        return claims


def access_token_expires_in(request):
    """Demo of a per-request access token lifetime (``ACCESS_TOKEN_EXPIRE_SECONDS``).

    ``request`` is an ``oauthlib.common.Request``, so the lifetime can be keyed on the
    grant type, the client (``request.client`` is the Application instance), the granted
    scopes, or the user. Here a client acting on its own behalf gets a short-lived token
    because no human is present to notice a leak, while an end-user token keeps the
    default lifetime. Return either a number of seconds or a ``timedelta``.
    """
    if request.grant_type == "client_credentials":
        return timedelta(minutes=15)
    return 36000
