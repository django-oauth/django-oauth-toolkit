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
