from django.urls import path

from oauth2_provider.authorization_server.oidc.views import ConnectDiscoveryInfoView


# Only the OIDC discovery route is registered — the authorize/token/userinfo/
# jwks routes are absent, so reversing them raises NoReverseMatch. Used to
# verify the discovery view fails fast rather than emitting null endpoints.
urlpatterns = [
    path(".well-known/openid-configuration", ConnectDiscoveryInfoView.as_view()),
]
