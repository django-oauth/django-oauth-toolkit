from django.conf import settings
from django.contrib.auth.middleware import AuthenticationMiddleware
from django.contrib.sessions.middleware import SessionMiddleware

from oauth2_provider.oauth2_validators import OAuth2Validator


# get_response is required for middleware, it doesn't need to do anything
# the way we're using it, so we just use a lambda that returns None
def get_response():
    None


class CustomOAuth2Validator(OAuth2Validator):
    def validate_silent_login(self, request) -> None:
        # request is an OAuthLib.common.Request and doesn't have the session
        # or user of the django request. We will emulate the session and auth
        # middleware here, since that is what the idp is using for auth. You
        # may need to modify this if you are using a different session
        # middleware or auth backend.

        session_cookie_name = settings.SESSION_COOKIE_NAME
        HTTP_COOKIE = request.headers.get("HTTP_COOKIE")
        COOKIES = HTTP_COOKIE.split("; ")
        for cookie in COOKIES:
            cookie_name, cookie_value = cookie.split("=")
            if cookie.startswith(session_cookie_name):
                break
        session_middleware = SessionMiddleware(get_response)
        session = session_middleware.SessionStore(cookie_value)
        # add session to request for compatibility with django.contrib.auth
        request.session = session

        # call the auth middleware to set request.user
        auth_middleware = AuthenticationMiddleware(get_response)
        auth_middleware.process_request(request)
        return request.user.is_authenticated

    def validate_silent_authorization(self, request) -> None:
        return True

    def get_additional_claims(self, request):
        # Standard OIDC claims sourced from the Django user. django-oauth-toolkit
        # filters each claim by the granted scope via ``oidc_claim_scope`` (e.g.
        # ``email`` is only emitted when the ``email`` scope was granted, the
        # ``profile`` claims only with the ``profile`` scope), so returning them
        # unconditionally here is safe. These feed both the ID Token and the
        # UserInfo response, giving the compliance suite real claims to assert.
        return {
            "name": request.user.get_full_name() or request.user.get_username(),
            "given_name": request.user.first_name,
            "family_name": request.user.last_name,
            "preferred_username": request.user.get_username(),
            "email": request.user.email,
            "email_verified": bool(request.user.email),
        }
