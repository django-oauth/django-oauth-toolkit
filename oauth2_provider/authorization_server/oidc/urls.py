"""OpenID Connect Provider URL patterns (discovery, JWKS, userinfo, logout).

Aggregated into the root ``oauth2_provider.urls`` under the ``oauth2_provider``
URL namespace.
"""

from django.urls import path, re_path

from oauth2_provider.authorization_server.oidc.views import (
    ConnectDiscoveryInfoView,
    JwksInfoView,
    RPInitiatedLogoutView,
    UserInfoView,
)


oidc_urlpatterns = [
    # .well-known/openid-configuration/ is deprecated
    # https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
    # does not specify a trailing slash
    # Support for trailing slash shall be removed in a future release.
    re_path(
        r"^\.well-known/openid-configuration/?$",
        ConnectDiscoveryInfoView.as_view(),
        name="oidc-connect-discovery-info",
    ),
    path(".well-known/jwks.json", JwksInfoView.as_view(), name="jwks-info"),
    path("userinfo/", UserInfoView.as_view(), name="user-info"),
    path("logout/", RPInitiatedLogoutView.as_view(), name="rp-initiated-logout"),
]
