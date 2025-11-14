import hashlib
import logging

from django.contrib.auth import authenticate
from django.utils.cache import patch_vary_headers

from oauth2_provider.models import get_access_token_model


log = logging.getLogger(__name__)


class OAuth2TokenMiddleware:
    """
    Middleware for OAuth2 user authentication

    This middleware is able to work along with AuthenticationMiddleware and its behaviour depends
    on the order it's processed with.

    If it comes *after* AuthenticationMiddleware and request.user is valid, leave it as is and does
    not proceed with token validation. If request.user is the Anonymous user proceeds and try to
    authenticate the user using the OAuth2 access token.

    If it comes *before* AuthenticationMiddleware, or AuthenticationMiddleware is not used at all,
    tries to authenticate user with the OAuth2 access token and set request.user field. Setting
    also request._cached_user field makes AuthenticationMiddleware use that instead of the one from
    the session.

    It also adds "Authorization" to the "Vary" header, so that django's cache middleware or a
    reverse proxy can create proper cache keys.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # do something only if request contains a Bearer token
        if request.META.get("HTTP_AUTHORIZATION", "").startswith("Bearer"):
            if not hasattr(request, "user") or request.user.is_anonymous:
                user = authenticate(request=request)
                if user:
                    request.user = request._cached_user = user

        response = self.get_response(request)
        patch_vary_headers(response, ("Authorization",))
        return response


class OAuth2ExtraTokenMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        authheader = request.META.get("HTTP_AUTHORIZATION", "")
        splits = authheader.split(maxsplit=1)
        if authheader.startswith("Bearer") and len(splits) == 2:
            tokenstring = splits[1]
            AccessToken = get_access_token_model()
            try:
                token_checksum = hashlib.sha256(tokenstring.encode("utf-8")).hexdigest()
                token = AccessToken.objects.get(token_checksum=token_checksum)
                request.access_token = token
            except AccessToken.DoesNotExist as e:
                log.exception(e)
        response = self.get_response(request)
        return response
