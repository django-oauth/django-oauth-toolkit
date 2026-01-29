from functools import wraps

from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponseForbidden
from oauthlib.oauth2 import Server

from .oauth2_backends import OAuthLibCore
from .oauth2_validators import OAuth2Validator
from .scopes import get_scopes_backend
from .settings import oauth2_settings


def protected_resource(scopes=None, validator_cls=OAuth2Validator, server_cls=Server):
    """
    Decorator to protect views by providing OAuth2 authentication out of the box,
    optionally with scope handling.

        @protected_resource()
        def my_view(request):
            # An access token is required to get here...
            # ...
            pass
    """
    _scopes = scopes or []

    def decorator(view_func):
        @wraps(view_func)
        def _validate(request, *args, **kwargs):
            validator = validator_cls()
            core = OAuthLibCore(server_cls(validator))
            valid, oauthlib_req = core.verify_request(request, scopes=_scopes)
            if valid:
                request.resource_owner = oauthlib_req.user
                return view_func(request, *args, **kwargs)
            return HttpResponseForbidden()

        return _validate

    return decorator


def rw_protected_resource(scopes=None, validator_cls=OAuth2Validator, server_cls=Server):
    """
    Decorator to protect views by providing OAuth2 authentication and read/write scopes
    out of the box.
    GET, HEAD, OPTIONS http methods require "read" scope. Otherwise "write" scope is required.

        @rw_protected_resource()
        def my_view(request):
            # If this is a POST, you have to provide 'write' scope to get here...
            # ...
            pass

    """
    _scopes = scopes or []

    def decorator(view_func):
        @wraps(view_func)
        def _validate(request, *args, **kwargs):
            # Check if provided scopes are acceptable
            provided_scopes = get_scopes_backend().get_all_scopes()
            read_write_scopes = [oauth2_settings.READ_SCOPE, oauth2_settings.WRITE_SCOPE]

            if not set(read_write_scopes).issubset(set(provided_scopes)):
                raise ImproperlyConfigured(
                    "rw_protected_resource decorator requires following scopes {0}"
                    " to be in OAUTH2_PROVIDER['SCOPES'] list in settings".format(read_write_scopes)
                )

            # Check if method is safe
            if request.method.upper() in ["GET", "HEAD", "OPTIONS"]:
                _scopes.append(oauth2_settings.READ_SCOPE)
            else:
                _scopes.append(oauth2_settings.WRITE_SCOPE)

            # proceed with validation
            validator = validator_cls()
            core = OAuthLibCore(server_cls(validator))
            valid, oauthlib_req = core.verify_request(request, scopes=_scopes)
            if valid:
                request.resource_owner = oauthlib_req.user
                return view_func(request, *args, **kwargs)
            return HttpResponseForbidden()

        return _validate

    return decorator
