"""Backward-compatible shim for the view mixins.

These mixins were split by OAuth2 role when the package was reorganized:

* the shared oauthlib config/getters -> :class:`oauth2_provider.core.views.OAuthLibCoreMixin`
* authorization-server response builders ->
  :class:`oauth2_provider.authorization_server.views.mixins.AuthorizationServerViewMixin`
* resource-server verification + protected-resource mixins ->
  :mod:`oauth2_provider.resource_server.mixins`
* OIDC view gating -> :mod:`oauth2_provider.authorization_server.oidc.mixins`

Importing from this module is deprecated and will be removed in
django-oauth-toolkit 4.0. The combined :class:`OAuthLibMixin` below is retained
only for backwards compatibility; it warns whenever it is subclassed.
"""

import warnings

from oauth2_provider.authorization_server.oidc.mixins import (  # noqa: F401
    OIDCLogoutOnlyMixin,
    OIDCOnlyMixin,
)
from oauth2_provider.authorization_server.views.mixins import AuthorizationServerViewMixin
from oauth2_provider.core.views import OAuthLibCoreMixin  # noqa: F401
from oauth2_provider.resource_server.mixins import (  # noqa: F401
    ClientProtectedResourceMixin,
    ProtectedResourceMetadataMixin,
    ProtectedResourceMixin,
    ReadWriteScopedResourceMixin,
    ResourceServerViewMixin,
    ScopedResourceMixin,
)


__all__ = [
    "OAuthLibMixin",
    "OAuthLibCoreMixin",
    "AuthorizationServerViewMixin",
    "ResourceServerViewMixin",
    "ScopedResourceMixin",
    "ProtectedResourceMixin",
    "ReadWriteScopedResourceMixin",
    "ClientProtectedResourceMixin",
    "ProtectedResourceMetadataMixin",
    "OIDCOnlyMixin",
    "OIDCLogoutOnlyMixin",
]


class OAuthLibMixin(AuthorizationServerViewMixin, ResourceServerViewMixin):
    """Deprecated combined authorization-server + resource-server view mixin.

    Historically a single mixin carried both the authorization-server response
    builders and the resource-server verification helpers, so every view inherited
    the other role's methods. Use
    :class:`oauth2_provider.authorization_server.views.mixins.AuthorizationServerViewMixin`
    for authorization-server views, or the mixins in
    :mod:`oauth2_provider.resource_server.mixins` for resource-server views.

    Subclassing this combined mixin emits a ``DeprecationWarning``; it will be
    removed in django-oauth-toolkit 4.0.
    """

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        warnings.warn(
            "oauth2_provider.views.mixins.OAuthLibMixin is deprecated: it combines "
            "authorization-server and resource-server behavior. Subclass "
            "oauth2_provider.authorization_server.views.mixins.AuthorizationServerViewMixin "
            "and/or the oauth2_provider.resource_server mixins instead. The combined "
            "mixin will be removed in django-oauth-toolkit 4.0.",
            DeprecationWarning,
            stacklevel=2,
        )


warnings.warn(
    "oauth2_provider.views.mixins has moved: its mixins were split by role into "
    "oauth2_provider.core.views, oauth2_provider.authorization_server.views.mixins, "
    "oauth2_provider.resource_server.mixins and "
    "oauth2_provider.authorization_server.oidc.mixins. The old import path is "
    "deprecated and will be removed in django-oauth-toolkit 4.0.",
    DeprecationWarning,
    stacklevel=2,
)
