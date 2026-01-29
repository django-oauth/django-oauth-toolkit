from django.views.generic import View

from .mixins import (
    ClientProtectedResourceMixin,
    ProtectedResourceMixin,
    ReadWriteScopedResourceMixin,
    ScopedResourceMixin,
)


class ProtectedResourceView(ProtectedResourceMixin, View):
    """
    Generic view protecting resources by providing OAuth2 authentication out of the box
    """

    pass


class ScopedProtectedResourceView(ScopedResourceMixin, ProtectedResourceView):
    """
    Generic view protecting resources by providing OAuth2 authentication and Scopes handling
    out of the box
    """

    pass


class ReadWriteScopedResourceView(ReadWriteScopedResourceMixin, ProtectedResourceView):
    """
    Generic view protecting resources with OAuth2 authentication and read/write scopes.
    GET, HEAD, OPTIONS http methods require "read" scope. Otherwise "write" scope is required.
    """

    pass


class ClientProtectedResourceView(ClientProtectedResourceMixin, View):
    """View for protecting a resource with client-credentials method.
    This involves allowing access tokens, Basic Auth and plain credentials in request body.
    """

    pass


class ClientProtectedScopedResourceView(ScopedResourceMixin, ClientProtectedResourceView):
    """Impose scope restrictions if client protection fallsback to access token."""

    pass
