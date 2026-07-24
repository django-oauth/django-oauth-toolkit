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
_VIEWS = "oauth2_provider.authorization_server.views"
_DCR = f"{_VIEWS}.dynamic_client_registration"

_LAZY = {
    "OAuth2Validator": "oauth2_provider.oauth2_validators",
    "AuthorizationView": f"{_VIEWS}.base",
    "TokenView": f"{_VIEWS}.base",
    "RevokeTokenView": f"{_VIEWS}.base",
    "IntrospectTokenView": f"{_VIEWS}.introspect",
    "OAuthServerMetadataView": f"{_VIEWS}.metadata",
    "DeviceAuthorizationView": f"{_VIEWS}.device",
    "DeviceUserCodeView": f"{_VIEWS}.device",
    "DeviceConfirmView": f"{_VIEWS}.device",
    "DeviceGrantStatusView": f"{_VIEWS}.device",
    "DynamicClientRegistrationView": _DCR,
    "DynamicClientRegistrationManagementView": _DCR,
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
