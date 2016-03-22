from django import http
from django.contrib.auth import authenticate
from django.utils.cache import patch_vary_headers

from .models import Application


class OAuth2TokenMiddleware(object):
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

    It also adds 'Authorization' to the 'Vary' header. So that django's cache middleware or a
    reverse proxy can create proper cache keys
    """
    def process_request(self, request):
        # do something only if request contains a Bearer token
        if request.META.get('HTTP_AUTHORIZATION', '').startswith('Bearer'):
            if not hasattr(request, 'user') or request.user.is_anonymous():
                user = authenticate(request=request)
                if user:
                    request.user = request._cached_user = user

    def process_response(self, request, response):
        patch_vary_headers(response, ('Authorization',))
        return response

HEADERS = ('x-requested-with', 'content-type', 'accept', 'origin',
           'authorization', 'x-csrftoken')
METHODS = ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS')


class CorsMiddleware(object):
    def process_request(self, request):
        '''If this is a preflight-request, we must always return 200'''
        if (request.method == 'OPTIONS' and
                'HTTP_ACCESS_CONTROL_REQUEST_METHOD' in request.META):
            return http.HttpResponse()
        return None

    def process_response(self, request, response):
        '''Add cors-headers to request if they can be derived correctly'''
        try:
            cors_allow_origin = _get_cors_allow_origin_header(request)
        except Application.NoSuitableOriginFoundError:
            pass
        else:
            response['Access-Control-Allow-Origin'] = cors_allow_origin
            response['Access-Control-Allow-Credentials'] = 'true'
            if request.method == 'OPTIONS':
                response['Access-Control-Allow-Headers'] = ', '.join(HEADERS)
                response['Access-Control-Allow-Methods'] = ', '.join(METHODS)
        return response


def _get_cors_allow_origin_header(request):
    '''Fetch the oauth-application that is responsible for making the
    request and return a sutible cors-header, or None
    '''
    origin = request.META.get('HTTP_ORIGIN')
    if origin:
        try:
            app = Application.objects.filter(redirect_uris__contains=origin)[0]
        except IndexError:
            # No application for this origin found
            pass
        else:
            return app.get_cors_header(origin)
    raise Application.NoSuitableOriginFoundError
