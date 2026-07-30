# flake8: noqa
#
# Backward-compatible aggregator. The view classes moved into role packages when
# the package was reorganized (authorization_server.views / resource_server.views
# / authorization_server.oidc.views); they are re-exported here so
# ``from oauth2_provider.views import AuthorizationView`` keeps working. Imports
# below point at the canonical homes, so importing this package emits no
# deprecation warnings; only the per-module shims (oauth2_provider.views.base,
# etc.) warn.
from ..authorization_server.oidc.views import (
    ConnectDiscoveryInfoView,
    JwksInfoView,
    RPInitiatedLogoutView,
    UserInfoView,
)
from ..authorization_server.views.application import (
    ApplicationDelete,
    ApplicationDetail,
    ApplicationList,
    ApplicationRegistration,
    ApplicationUpdate,
)
from ..authorization_server.views.base import AuthorizationView, RevokeTokenView, TokenView
from ..authorization_server.views.device import (
    DeviceAuthorizationView,
    DeviceConfirmView,
    DeviceGrantStatusView,
    DeviceUserCodeView,
)
from ..authorization_server.views.dynamic_client_registration import (
    DynamicClientRegistrationManagementView,
    DynamicClientRegistrationView,
)
from ..authorization_server.views.introspect import IntrospectTokenView
from ..authorization_server.views.metadata import OAuthServerMetadataView
from ..authorization_server.views.token import AuthorizedTokenDeleteView, AuthorizedTokensListView
from ..resource_server.views.generic import (
    ClientProtectedResourceMetadataView,
    ClientProtectedResourceView,
    ClientProtectedScopedResourceView,
    ProtectedResourceMetadataView,
    ProtectedResourceView,
    ReadWriteScopedProtectedResourceMetadataView,
    ReadWriteScopedResourceView,
    ScopedProtectedResourceMetadataView,
    ScopedProtectedResourceView,
)
from ..resource_server.views.metadata import OAuthProtectedResourceMetadataView
