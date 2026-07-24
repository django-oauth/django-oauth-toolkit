"""Backward-compatibility guarantees for the role-based package reorganization.

Modules were regrouped under ``oauth2_provider.core`` /
``oauth2_provider.authorization_server`` / ``oauth2_provider.resource_server``.
The old top-level import paths must keep working (via shims) for one release
cycle, and importing them by their old path must resolve to the exact same
module/objects as the new canonical path.
"""

import importlib
import sys
import warnings

import pytest


# old dotted path -> new canonical dotted path
MOVED_MODULES = {
    "oauth2_provider.exceptions": "oauth2_provider.core.exceptions",
    "oauth2_provider.http": "oauth2_provider.core.http",
    "oauth2_provider.compat": "oauth2_provider.core.compat",
    "oauth2_provider.signals": "oauth2_provider.core.signals",
    "oauth2_provider.utils": "oauth2_provider.core.utils",
    "oauth2_provider.scopes": "oauth2_provider.core.scopes",
    "oauth2_provider.checks": "oauth2_provider.core.checks",
    "oauth2_provider.oauth2_backends": "oauth2_provider.core.backends_oauthlib",
    "oauth2_provider.bcp": "oauth2_provider.authorization_server.bcp",
    "oauth2_provider.dcr": "oauth2_provider.authorization_server.dcr",
    "oauth2_provider.cimd": "oauth2_provider.authorization_server.cimd",
    "oauth2_provider.forms": "oauth2_provider.authorization_server.forms",
    "oauth2_provider.admin": "oauth2_provider.authorization_server.admin",
    "oauth2_provider.www_authenticate": "oauth2_provider.resource_server.www_authenticate",
    "oauth2_provider.backends": "oauth2_provider.resource_server.backends",
    "oauth2_provider.decorators": "oauth2_provider.resource_server.decorators",
    "oauth2_provider.middleware": "oauth2_provider.resource_server.middleware",
}

# The admin shim is intentionally silent (Django imports oauth2_provider.admin
# during admin autodiscovery at startup, so it must not warn).
SILENT_SHIMS = {"oauth2_provider.admin"}


@pytest.mark.parametrize("old, new", sorted(MOVED_MODULES.items()))
def test_old_path_resolves_to_moved_module(old, new):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        old_mod = importlib.import_module(old)
        new_mod = importlib.import_module(new)
    # The shim aliases sys.modules[old] to the moved module, so identity is exact
    # and every attribute (public and private) is shared.
    assert old_mod is new_mod


@pytest.mark.parametrize("old", sorted(m for m in MOVED_MODULES if m not in SILENT_SHIMS))
def test_old_path_emits_deprecation_warning(old):
    # Force the shim file to execute again by dropping the cached alias.
    sys.modules.pop(old, None)
    with pytest.warns(DeprecationWarning, match="has moved to"):
        importlib.import_module(old)


def test_admin_shim_is_silent():
    sys.modules.pop("oauth2_provider.admin", None)
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        importlib.import_module("oauth2_provider.admin")  # must not raise


def test_private_names_resolve_via_old_path():
    # Regression: the shims must re-export private, underscore-prefixed names
    # that external code imports from the old paths.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        from oauth2_provider.forms import _is_hashed  # noqa: F401
        from oauth2_provider.oauth2_backends import _add_iss_to_redirect  # noqa: F401


def test_oauth2_validator_composition_and_reexports():
    from oauth2_provider.oauth2_validators import (
        OAuth2Validator,
        is_valid_resource_uri,
        validate_resource_as_url_prefix,
    )
    from oauth2_provider.resource_server.validators import (
        ResourceServerValidatorMixin,
    )
    from oauth2_provider.resource_server.validators import (
        is_valid_resource_uri as rs_is_valid,
    )
    from oauth2_provider.resource_server.validators import (
        validate_resource_as_url_prefix as rs_validate,
    )

    # The resource-server slice is composed into the public validator...
    assert issubclass(OAuth2Validator, ResourceServerValidatorMixin)
    assert hasattr(OAuth2Validator, "validate_bearer_token")
    # ...and the RFC 8707 helpers are the same objects via either path.
    assert validate_resource_as_url_prefix is rs_validate
    assert is_valid_resource_uri is rs_is_valid


def test_role_facades_reexport_public_api():
    from oauth2_provider.authorization_server import (
        AuthorizationView,
        OAuth2Validator,
        TokenView,
    )
    from oauth2_provider.authorization_server.oidc import UserInfoView
    from oauth2_provider.resource_server import (
        OAuth2Backend,
        ProtectedResourceView,
        protected_resource,
    )

    # Facade re-exports resolve to the same objects as their canonical modules.
    from oauth2_provider.views.base import AuthorizationView as _AuthorizationView
    from oauth2_provider.views.generic import ProtectedResourceView as _ProtectedResourceView

    assert AuthorizationView is _AuthorizationView
    assert ProtectedResourceView is _ProtectedResourceView
    assert callable(protected_resource)
    assert OAuth2Backend is not None
    assert TokenView is not None
    assert OAuth2Validator is not None
    assert UserInfoView is not None
