"""Authorization Server role (the OAuth2/OIDC provider side): issuing
authorization and tokens, client registration, and the OpenID Connect Provider
identity layer.

Provider-side modules live in this package (``dcr``, ``cimd``, ``bcp``,
``forms``, ``admin``) and can be imported directly. The primary public classes
are also re-exported here so callers can import them by role, e.g.::

    from oauth2_provider.authorization_server import AuthorizationView, TokenView

View and validator names are loaded lazily (PEP 562) so importing this package
never touches the app registry before ``django.setup()``. The OpenID Connect
Provider surface lives in the :mod:`oauth2_provider.authorization_server.oidc`
subpackage.
"""

import importlib


# name -> canonical module that defines it (loaded on first access)
_LAZY = {
    "OAuth2Validator": "oauth2_provider.oauth2_validators",
    "AuthorizationView": "oauth2_provider.views.base",
    "TokenView": "oauth2_provider.views.base",
    "RevokeTokenView": "oauth2_provider.views.base",
    "IntrospectTokenView": "oauth2_provider.views.introspect",
    "OAuthServerMetadataView": "oauth2_provider.views.metadata",
    "DeviceAuthorizationView": "oauth2_provider.views.device",
    "DeviceUserCodeView": "oauth2_provider.views.device",
    "DeviceConfirmView": "oauth2_provider.views.device",
    "DeviceGrantStatusView": "oauth2_provider.views.device",
    "DynamicClientRegistrationView": "oauth2_provider.views.dynamic_client_registration",
    "DynamicClientRegistrationManagementView": "oauth2_provider.views.dynamic_client_registration",
}

__all__ = sorted(_LAZY)


def __getattr__(name):
    try:
        module = _LAZY[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    return getattr(importlib.import_module(module), name)


def __dir__():
    return sorted(__all__)
