from django.urls import path, re_path

from . import views


app_name = "oauth2_provider"


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

oidc_urlpatterns = [
    # .well-known/openid-configuration/ is deprecated
    # https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
    # does not specify a trailing slash
    # Support for trailing slash shall be removed in a future release.
    re_path(
        r"^\.well-known/openid-configuration/?$",
        views.ConnectDiscoveryInfoView.as_view(),
        name="oidc-connect-discovery-info",
    ),
    path(".well-known/jwks.json", views.JwksInfoView.as_view(), name="jwks-info"),
    path("userinfo/", views.UserInfoView.as_view(), name="user-info"),
    path("logout/", views.RPInitiatedLogoutView.as_view(), name="rp-initiated-logout"),
]


urlpatterns = base_urlpatterns + management_urlpatterns + oidc_urlpatterns
