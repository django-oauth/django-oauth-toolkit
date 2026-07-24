"""OpenID Connect Provider (OP) facet of the Authorization Server.

Re-exports the OP-facing views (discovery, JWKS, userinfo, RP-Initiated Logout)
by role, e.g.::

    from oauth2_provider.authorization_server.oidc import UserInfoView

The view bodies live in :mod:`oauth2_provider.authorization_server.oidc.views`; names are loaded
lazily (PEP 562) to avoid touching the app registry at import time.
"""

import importlib


_LAZY = {
    "ConnectDiscoveryInfoView": "oauth2_provider.authorization_server.oidc.views",
    "JwksInfoView": "oauth2_provider.authorization_server.oidc.views",
    "UserInfoView": "oauth2_provider.authorization_server.oidc.views",
    "RPInitiatedLogoutView": "oauth2_provider.authorization_server.oidc.views",
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
