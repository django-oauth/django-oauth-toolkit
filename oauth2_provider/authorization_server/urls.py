"""Authorization Server URL patterns.

Grouped by concern: RFC 8414 authorization-server metadata, the core protocol
endpoints (authorize/token/revoke/introspect/device), the application/token
management UI, and Dynamic Client Registration. These lists are aggregated into
the root ``oauth2_provider.urls`` under the ``oauth2_provider`` URL namespace;
the OpenID Connect Provider routes live in
:mod:`oauth2_provider.authorization_server.oidc.urls`.
"""

from django.urls import path

from oauth2_provider import views


server_metadata_urlpatterns = [
    # RFC 8414 locates the metadata document at the origin's
    # /.well-known/oauth-authorization-server. Mount this at the server root, not
    # under a prefix — see docs/oauth2_server_metadata.rst.
    path(
        ".well-known/oauth-authorization-server",
        views.OAuthServerMetadataView.as_view(),
        name="oauth-server-metadata",
    ),
    # RFC 8414 path-component form: when the issuer has a path (e.g.
    # https://host/tenant1), the document lives at
    # /.well-known/oauth-authorization-server/<issuer_path>. The captured suffix
    # is reflected back into the issuer; the view reads it from the request path.
    path(
        ".well-known/oauth-authorization-server/<path:issuer_path>",
        views.OAuthServerMetadataView.as_view(),
        name="oauth-server-metadata-issuer",
    ),
]

base_urlpatterns = [
    path("authorize/", views.AuthorizationView.as_view(), name="authorize"),
    path("token/", views.TokenView.as_view(), name="token"),
    path("revoke_token/", views.RevokeTokenView.as_view(), name="revoke-token"),
    path("introspect/", views.IntrospectTokenView.as_view(), name="introspect"),
    path("device-authorization/", views.DeviceAuthorizationView.as_view(), name="device-authorization"),
    path("device/", views.DeviceUserCodeView.as_view(), name="device"),
    path(
        "device-confirm/<slug:client_id>/<slug:user_code>",
        views.DeviceConfirmView.as_view(),
        name="device-confirm",
    ),
    path(
        "device-grant-status/<slug:client_id>/<slug:user_code>",
        views.DeviceGrantStatusView.as_view(),
        name="device-grant-status",
    ),
]


management_urlpatterns = [
    # Application management views
    path("applications/", views.ApplicationList.as_view(), name="list"),
    path("applications/register/", views.ApplicationRegistration.as_view(), name="register"),
    path("applications/<slug:pk>/", views.ApplicationDetail.as_view(), name="detail"),
    path("applications/<slug:pk>/delete/", views.ApplicationDelete.as_view(), name="delete"),
    path("applications/<slug:pk>/update/", views.ApplicationUpdate.as_view(), name="update"),
    # Token management views
    path("authorized_tokens/", views.AuthorizedTokensListView.as_view(), name="authorized-token-list"),
    path(
        "authorized_tokens/<slug:pk>/delete/",
        views.AuthorizedTokenDeleteView.as_view(),
        name="authorized-token-delete",
    ),
]

dcr_urlpatterns = [
    path("register/", views.DynamicClientRegistrationView.as_view(), name="dcr-register"),
    path(
        "register/<str:client_id>/",
        views.DynamicClientRegistrationManagementView.as_view(),
        name="dcr-register-management",
    ),
]
