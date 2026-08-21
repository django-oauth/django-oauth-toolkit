"""Resource Server URL patterns (RFC 9728 protected-resource metadata).

These are aggregated into the root ``oauth2_provider.urls`` under the
``oauth2_provider`` URL namespace; import them from there (or mount this list at
the server root — see ``docs/protected_resource_metadata.rst``).
"""

from django.urls import path

from oauth2_provider.resource_server.views.metadata import OAuthProtectedResourceMetadataView


resource_metadata_urlpatterns = [
    # RFC 9728 locates the protected-resource metadata document at the origin's
    # /.well-known/oauth-protected-resource. Mount this at the server root, not
    # under a prefix — see docs/protected_resource_metadata.rst.
    path(
        ".well-known/oauth-protected-resource",
        OAuthProtectedResourceMetadataView.as_view(),
        name="oauth-resource-metadata",
    ),
    # RFC 9728 path-component form: when the resource identifier has a path (e.g.
    # https://host/resource1), the document lives at
    # /.well-known/oauth-protected-resource/<resource_path>. The captured suffix
    # is reflected back into the resource identifier; the view reads it from the
    # request path.
    path(
        ".well-known/oauth-protected-resource/<path:resource_path>",
        OAuthProtectedResourceMetadataView.as_view(),
        name="oauth-resource-metadata-path",
    ),
]
