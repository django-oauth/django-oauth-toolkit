from functools import wraps

from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse, HttpResponseForbidden
from oauthlib.oauth2 import Server

from .oauth2_backends import OAuthLibCore
from .oauth2_validators import OAuth2Validator
from .core.scopes import get_scopes_backend
from .settings import oauth2_settings
from .resource_server.www_authenticate import build_bearer_challenge, challenge_status


def _denied_response(request, oauthlib_request, advertise_metadata, resource_metadata_url=None):
    """Failure response for the protected-resource decorators.

    Returns a bare ``403`` by default; when ``advertise_metadata`` is set, returns a
    ``WWW-Authenticate: Bearer`` challenge carrying the RFC 9728 ``resource_metadata``
    parameter, with an RFC 6750 status of ``401`` for a missing/invalid token or
    ``403`` for ``insufficient_scope``. ``resource_metadata_url`` overrides the
    advertised document (default: this server's root metadata route).
    """
    if not advertise_metadata:
        return HttpResponseForbidden()
    oauth2_error = getattr(oauthlib_request, "oauth2_error", None)
    extra = {} if resource_metadata_url is None else {"resource_metadata_url": resource_metadata_url}
    challenge = build_bearer_challenge(request, oauth2_error=oauth2_error, **extra)
    # RFC 6750: insufficient_scope is a 403, other Bearer errors a 401.
    response = HttpResponse(status=challenge_status(oauth2_error))
    response["WWW-Authenticate"] = challenge
    return response


def protected_resource(
    scopes=None,
    validator_cls=OAuth2Validator,
    server_cls=Server,
    advertise_metadata=False,
    resource_metadata_url=None,
):
    """
    Decorator to protect views by providing OAuth2 authentication out of the box,
    optionally with scope handling.

        @protected_resource()
        def my_view(request):
            # An access token is required to get here...
            # ...
            pass

    Pass ``advertise_metadata=True`` (or use :func:`protected_resource_metadata`) to
    return an RFC 9728 ``resource_metadata`` ``WWW-Authenticate`` challenge on failure
    instead of a bare ``403`` — as an RFC 6750 ``401`` (missing/invalid token) or
    ``403`` (``insufficient_scope``). ``resource_metadata_url`` advertises a specific
    metadata document (e.g. the RFC 9728 path-component form) instead of the server's
    root route.
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
            return _denied_response(request, oauthlib_req, advertise_metadata, resource_metadata_url)

        return _validate

    return decorator


def protected_resource_metadata(
    scopes=None, validator_cls=OAuth2Validator, server_cls=Server, resource_metadata_url=None
):
    """
    RFC 9728 variant of :func:`protected_resource`: on failed authentication the
    view returns a ``401`` with a ``WWW-Authenticate: Bearer`` challenge advertising
    the protected-resource metadata document.
    """
    return protected_resource(
        scopes=scopes,
        validator_cls=validator_cls,
        server_cls=server_cls,
        advertise_metadata=True,
        resource_metadata_url=resource_metadata_url,
    )


def rw_protected_resource(
    scopes=None,
    validator_cls=OAuth2Validator,
    server_cls=Server,
    advertise_metadata=False,
    resource_metadata_url=None,
):
    """
    Decorator to protect views by providing OAuth2 authentication and read/write scopes
    out of the box.
    GET, HEAD, OPTIONS http methods require "read" scope. Otherwise "write" scope is required.

        @rw_protected_resource()
        def my_view(request):
            # If this is a POST, you have to provide 'write' scope to get here...
            # ...
            pass

    Pass ``advertise_metadata=True`` (or use :func:`rw_protected_resource_metadata`) to
    return an RFC 9728 ``resource_metadata`` ``WWW-Authenticate`` challenge on failure
    instead of a bare ``403`` — as an RFC 6750 ``401`` (missing/invalid token) or
    ``403`` (``insufficient_scope``).
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

            # Check if method is safe. Build a fresh list per request so the read/write
            # scope is not appended to the shared, decoration-time `_scopes` list (which
            # would accumulate across requests and eventually reject valid tokens, and
            # would also mutate a caller-supplied `scopes` argument).
            if request.method.upper() in ["GET", "HEAD", "OPTIONS"]:
                required_scopes = _scopes + [oauth2_settings.READ_SCOPE]
            else:
                required_scopes = _scopes + [oauth2_settings.WRITE_SCOPE]

            # proceed with validation
            validator = validator_cls()
            core = OAuthLibCore(server_cls(validator))
            valid, oauthlib_req = core.verify_request(request, scopes=required_scopes)
            if valid:
                request.resource_owner = oauthlib_req.user
                return view_func(request, *args, **kwargs)
            return _denied_response(request, oauthlib_req, advertise_metadata, resource_metadata_url)

        return _validate

    return decorator


def rw_protected_resource_metadata(
    scopes=None, validator_cls=OAuth2Validator, server_cls=Server, resource_metadata_url=None
):
    """
    RFC 9728 variant of :func:`rw_protected_resource`: on failed authentication the
    view returns a ``401`` with a ``WWW-Authenticate: Bearer`` challenge advertising
    the protected-resource metadata document.
    """
    return rw_protected_resource(
        scopes=scopes,
        validator_cls=validator_cls,
        server_cls=server_cls,
        advertise_metadata=True,
        resource_metadata_url=resource_metadata_url,
    )
