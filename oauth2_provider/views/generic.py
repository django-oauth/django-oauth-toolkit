from django.views.generic import View

from oauth2_provider.resource_server.mixins import (
    ClientProtectedResourceMixin,
    ProtectedResourceMetadataMixin,
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


# RFC 9728 opt-in variants: on failed authentication these return a 401 with a
# WWW-Authenticate: Bearer challenge advertising the protected-resource metadata
# document, instead of the bare 403 the views above return.


class ProtectedResourceMetadataView(ProtectedResourceMetadataMixin, ProtectedResourceView):
    """:class:`ProtectedResourceView` that advertises RFC 9728 resource metadata."""

    pass


class ScopedProtectedResourceMetadataView(ProtectedResourceMetadataMixin, ScopedProtectedResourceView):
    """:class:`ScopedProtectedResourceView` that advertises RFC 9728 resource metadata."""

    pass


class ReadWriteScopedProtectedResourceMetadataView(
    ProtectedResourceMetadataMixin, ReadWriteScopedResourceView
):
    """:class:`ReadWriteScopedResourceView` that advertises RFC 9728 resource metadata."""

    pass


class ClientProtectedResourceMetadataView(ProtectedResourceMetadataMixin, ClientProtectedResourceView):
    """:class:`ClientProtectedResourceView` that advertises RFC 9728 resource metadata."""

    pass
