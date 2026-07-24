"""Resource-server view mixins.

``ResourceServerViewMixin`` verifies protected-resource requests (bearer token or
client authentication) and produces the unauthenticated response; the concrete
mixins below layer scope handling and RFC 9728 metadata advertisement on top. All
build on the shared :class:`oauth2_provider.core.views.OAuthLibCoreMixin`.
"""

import logging

from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from django.http import HttpResponse, HttpResponseForbidden

from oauth2_provider.core.scopes import get_scopes_backend
from oauth2_provider.core.views import OAuthLibCoreMixin
from oauth2_provider.resource_server.www_authenticate import build_bearer_challenge, challenge_status
from oauth2_provider.settings import oauth2_settings


log = logging.getLogger("oauth2_provider")

SAFE_HTTP_METHODS = ["GET", "HEAD", "OPTIONS"]


class ResourceServerViewMixin(OAuthLibCoreMixin):
    """Resource-server request verification.

    Wraps the oauthlib ``Server`` to verify a bearer-token (or client-authenticated)
    protected-resource request, and defines the hook that produces the response
    returned when that verification fails.
    """

    def verify_request(self, request):
        """
        A wrapper method that calls verify_request on `server_class` instance.

        :param request: The current django.http.HttpRequest object
        """
        core = self.get_oauthlib_core()

        try:
            return core.verify_request(request, scopes=self.get_scopes())
        except ValueError as error:
            if str(error) == "Invalid hex encoding in query string.":
                raise SuspiciousOperation(error)
            else:
                raise

    def authenticate_client(self, request):
        """Returns a boolean representing if client is authenticated with client credentials
        method. Returns `True` if authenticated.

        :param request: The current django.http.HttpRequest object
        """
        core = self.get_oauthlib_core()
        return core.authenticate_client(request)

    def unauthenticated_response(self, request, oauthlib_request=None):
        """Response returned when a protected resource request fails authentication.

        Defaults to a bare ``403 Forbidden`` (the historical behaviour).
        :class:`ProtectedResourceMetadataMixin` overrides this to return an RFC 6750
        ``401`` carrying an RFC 9728 ``WWW-Authenticate`` challenge.

        :param oauthlib_request: the oauthlib request produced by ``verify_request``,
            carrying any ``oauth2_error`` detail (``None`` for client-auth failures).
        """
        return HttpResponseForbidden()


class ScopedResourceMixin:
    """
    Helper mixin that implements "scopes handling" behaviour
    """

    required_scopes = None

    def get_scopes(self, *args, **kwargs):
        """
        Return the scopes needed to access the resource

        :param args: Support scopes injections from the outside (not yet implemented)
        """
        if self.required_scopes is None:
            raise ImproperlyConfigured(
                "ProtectedResourceMixin requires either a definition of 'required_scopes'"
                " or an implementation of 'get_scopes()'"
            )
        else:
            return self.required_scopes


class ProtectedResourceMixin(ResourceServerViewMixin):
    """
    Helper mixin that implements OAuth2 protection on request dispatch,
    specially useful for Django Generic Views
    """

    def dispatch(self, request, *args, **kwargs):
        # let preflight OPTIONS requests pass
        if request.method.upper() == "OPTIONS":
            return super().dispatch(request, *args, **kwargs)

        # check if the request is valid and the protected resource may be accessed
        valid, r = self.verify_request(request)
        if valid:
            request.resource_owner = r.user
            return super().dispatch(request, *args, **kwargs)
        else:
            return self.unauthenticated_response(request, r)


class ReadWriteScopedResourceMixin(ScopedResourceMixin, ResourceServerViewMixin):
    """
    Helper mixin that implements "read and write scopes" behavior
    """

    required_scopes = []
    read_write_scope = None

    def __new__(cls, *args, **kwargs):
        provided_scopes = get_scopes_backend().get_all_scopes()
        read_write_scopes = [oauth2_settings.READ_SCOPE, oauth2_settings.WRITE_SCOPE]

        if not set(read_write_scopes).issubset(set(provided_scopes)):
            raise ImproperlyConfigured(
                "ReadWriteScopedResourceMixin requires following scopes {}"
                ' to be in OAUTH2_PROVIDER["SCOPES"] list in settings'.format(read_write_scopes)
            )

        # This __new__ exists only to run the validation above; it
        # constructs no state of its own, so it must forward nothing to
        # the next __new__ in the MRO. Because we override __new__,
        # object.__new__() rejects any extra positional/keyword argument
        # outright ("takes exactly one argument"), so forwarding them
        # breaks instantiation for any view mixing this in that is
        # constructed with arguments -- e.g. DRF's cls(**initkwargs).
        # See GH #694.
        return super().__new__(cls)

    def dispatch(self, request, *args, **kwargs):
        if request.method.upper() in SAFE_HTTP_METHODS:
            self.read_write_scope = oauth2_settings.READ_SCOPE
        else:
            self.read_write_scope = oauth2_settings.WRITE_SCOPE

        return super().dispatch(request, *args, **kwargs)

    def get_scopes(self, *args, **kwargs):
        scopes = super().get_scopes(*args, **kwargs)

        # this returns a copy so that self.required_scopes is not modified
        return scopes + [self.read_write_scope]


class ClientProtectedResourceMixin(ResourceServerViewMixin):
    """Mixin for protecting resources with client authentication as mentioned in rfc:`3.2.1`
    This involves authenticating with any of: HTTP Basic Auth, Client Credentials and
    Access token in that order. Breaks off after first validation.
    """

    def dispatch(self, request, *args, **kwargs):
        # let preflight OPTIONS requests pass
        if request.method.upper() == "OPTIONS":
            return super().dispatch(request, *args, **kwargs)
        # Validate either with HTTP basic or client creds in request body.
        # TODO: Restrict to POST.
        valid = self.authenticate_client(request)
        if not valid:
            # Alternatively allow access tokens
            # check if the request is valid and the protected resource may be accessed
            valid, r = self.verify_request(request)
            if valid:
                request.resource_owner = r.user
                return super().dispatch(request, *args, **kwargs)
            return self.unauthenticated_response(request, r)
        else:
            return super().dispatch(request, *args, **kwargs)


class ProtectedResourceMetadataMixin(ResourceServerViewMixin):
    """RFC 9728 opt-in: advertise protected-resource metadata on auth failure.

    Mix this in *before* a protected-resource view/mixin
    (:class:`ProtectedResourceMixin`, :class:`ClientProtectedResourceMixin`, …) to
    replace the default bare ``403 Forbidden`` denial with a response carrying a
    ``WWW-Authenticate: Bearer`` challenge and the RFC 9728 ``resource_metadata``
    parameter pointing at ``/.well-known/oauth-protected-resource``. Per RFC 6750
    the status is ``401 Unauthorized`` for a missing/invalid token and ``403
    Forbidden`` for ``insufficient_scope``. Opting in explicitly (rather than via a
    global flag) keeps the default views' behaviour unchanged.

    It subclasses :class:`ResourceServerViewMixin` so that its ``unauthenticated_response``
    is an unambiguous override of the base hook (rather than a value from an
    unrelated base class) when combined with a protected-resource view/mixin.

    Set ``www_authenticate_realm`` to advertise a realm in the challenge. Set
    ``resource_metadata_url`` (or override :meth:`get_resource_metadata_url`) to
    advertise a specific metadata document — e.g. the RFC 9728 path-component form
    for a path-based/multi-tenant resource — instead of this server's root
    ``/.well-known/oauth-protected-resource``.
    """

    www_authenticate_realm = None
    resource_metadata_url = None

    def get_resource_metadata_url(self, request):
        """URL advertised in ``resource_metadata``.

        Returns ``resource_metadata_url`` when set, otherwise ``None`` so the
        challenge builder falls back to the server's root metadata route. Override
        to derive the URL from the protected resource's identifier/path.
        """
        return self.resource_metadata_url

    def unauthenticated_response(self, request, oauthlib_request=None):
        oauth2_error = getattr(oauthlib_request, "oauth2_error", None)
        url = self.get_resource_metadata_url(request)
        extra = {} if url is None else {"resource_metadata_url": url}
        challenge = build_bearer_challenge(
            request, oauth2_error=oauth2_error, realm=self.www_authenticate_realm, **extra
        )
        # RFC 6750: insufficient_scope is a 403, other Bearer errors a 401.
        response = HttpResponse(status=challenge_status(oauth2_error))
        response["WWW-Authenticate"] = challenge
        return response
