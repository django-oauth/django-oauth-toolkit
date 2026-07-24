"""Resource Server role: validating bearer tokens (RFC 7662 introspection,
RFC 8707 audience) and advertising RFC 9728 protected-resource metadata.

Public API is re-exported here so callers can import it by role, e.g.::

    from oauth2_provider.resource_server import ProtectedResourceView, OAuth2Backend

Names backed by Django views/backends are loaded lazily (PEP 562) so importing
this package never touches the app registry before ``django.setup()``.
"""

import importlib

from .www_authenticate import build_bearer_challenge, challenge_status


# name -> canonical module that defines it (loaded on first access)
_LAZY = {
    "OAuth2Backend": "oauth2_provider.resource_server.backends",
    "protected_resource": "oauth2_provider.resource_server.decorators",
    "protected_resource_metadata": "oauth2_provider.resource_server.decorators",
    "rw_protected_resource": "oauth2_provider.resource_server.decorators",
    "rw_protected_resource_metadata": "oauth2_provider.resource_server.decorators",
    "OAuth2TokenMiddleware": "oauth2_provider.resource_server.middleware",
    "OAuth2ExtraTokenMiddleware": "oauth2_provider.resource_server.middleware",
    # RFC 8707 resource-indicator validation + bearer-token validator mixin.
    "ResourceServerValidatorMixin": "oauth2_provider.resource_server.validators",
    "validate_resource_as_url_prefix": "oauth2_provider.resource_server.validators",
    "is_valid_resource_uri": "oauth2_provider.resource_server.validators",
    # Concrete protected-resource views (bodies remain in oauth2_provider.views).
    "ProtectedResourceView": "oauth2_provider.views.generic",
    "ScopedProtectedResourceView": "oauth2_provider.views.generic",
    "ReadWriteScopedResourceView": "oauth2_provider.views.generic",
    "ClientProtectedResourceView": "oauth2_provider.views.generic",
    "ClientProtectedScopedResourceView": "oauth2_provider.views.generic",
    "ProtectedResourceMetadataView": "oauth2_provider.views.generic",
    "ScopedProtectedResourceMetadataView": "oauth2_provider.views.generic",
    "ReadWriteScopedProtectedResourceMetadataView": "oauth2_provider.views.generic",
    "ClientProtectedResourceMetadataView": "oauth2_provider.views.generic",
    "OAuthProtectedResourceMetadataView": "oauth2_provider.views.metadata",
    # Mixins (bodies remain in oauth2_provider.views.mixins).
    "ProtectedResourceMixin": "oauth2_provider.views.mixins",
    "ScopedResourceMixin": "oauth2_provider.views.mixins",
    "ReadWriteScopedResourceMixin": "oauth2_provider.views.mixins",
    "ClientProtectedResourceMixin": "oauth2_provider.views.mixins",
    "ProtectedResourceMetadataMixin": "oauth2_provider.views.mixins",
}

__all__ = ["build_bearer_challenge", "challenge_status", *sorted(_LAZY)]


def __getattr__(name):
    try:
        module = _LAZY[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    return getattr(importlib.import_module(module), name)


def __dir__():
    return sorted(__all__)
