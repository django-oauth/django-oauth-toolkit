"""Backward-compatibility guarantees for the role-based package reorganization.

Modules were regrouped under ``oauth2_provider.core`` /
``oauth2_provider.authorization_server`` / ``oauth2_provider.resource_server``.
The old top-level import paths must keep working (via shims) for one release
cycle, and importing them by their old path must resolve to the exact same
module/objects as the new canonical path.
"""

import ast
import contextlib
import importlib
import pathlib
import sys
import warnings

import pytest


@contextlib.contextmanager
def _reimport_without_leaking(modname):
    """Re-trigger a shim's import-time warning without leaking a reloaded module.

    Several tests below pop a shim from ``sys.modules`` and import it again so its
    import-time ``DeprecationWarning`` fires a second time. For a *re-export* shim
    (e.g. ``oauth2_provider.views.mixins``, which defines the combined
    ``OAuthLibMixin`` in its own body) re-executing the module creates a brand-new
    class object for every name it defines. Any code that already subclassed the
    original class -- test view classes elsewhere in the suite, ``mock.patch``
    targets -- would then diverge from the freshly imported module, so patching
    ``<shim>.OAuthLibMixin.<attr>`` no longer affects those subclasses. Under
    ``pytest -n auto --dist loadfile`` that surfaces as a flaky failure in whatever
    file happens to share the worker. Restore the original module object afterwards
    so its identity is preserved for the rest of the session.
    """
    saved = sys.modules.get(modname)
    sys.modules.pop(modname, None)
    try:
        yield
    finally:
        if saved is not None:
            sys.modules[modname] = saved
        else:
            sys.modules.pop(modname, None)


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
    "oauth2_provider.bcp": "oauth2_provider.core.bcp",
    "oauth2_provider.dcr": "oauth2_provider.authorization_server.dcr",
    "oauth2_provider.cimd": "oauth2_provider.authorization_server.cimd",
    "oauth2_provider.forms": "oauth2_provider.authorization_server.forms",
    "oauth2_provider.admin": "oauth2_provider.authorization_server.admin",
    "oauth2_provider.www_authenticate": "oauth2_provider.resource_server.www_authenticate",
    "oauth2_provider.backends": "oauth2_provider.resource_server.backends",
    "oauth2_provider.decorators": "oauth2_provider.resource_server.decorators",
    "oauth2_provider.middleware": "oauth2_provider.resource_server.middleware",
    # View modules moved into role packages (sys.modules-alias shims).
    "oauth2_provider.views.base": "oauth2_provider.authorization_server.views.base",
    "oauth2_provider.views.introspect": "oauth2_provider.authorization_server.views.introspect",
    "oauth2_provider.views.device": "oauth2_provider.authorization_server.views.device",
    "oauth2_provider.views.dynamic_client_registration": (
        "oauth2_provider.authorization_server.views.dynamic_client_registration"
    ),
    "oauth2_provider.views.application": "oauth2_provider.authorization_server.views.application",
    "oauth2_provider.views.token": "oauth2_provider.authorization_server.views.token",
    "oauth2_provider.views.oidc": "oauth2_provider.authorization_server.oidc.views",
    "oauth2_provider.views.generic": "oauth2_provider.resource_server.views.generic",
}


# These old paths are re-export shims (not whole-module aliases), because their
# contents were split across more than one new module. Importing a symbol from the
# old path must still resolve to the same object as the canonical module, and the
# old path must warn.
SPLIT_SHIM_SYMBOLS = {
    # old module, symbol, canonical module
    (
        "oauth2_provider.views.mixins",
        "AuthorizationServerViewMixin",
        "oauth2_provider.authorization_server.views.mixins",
    ),
    ("oauth2_provider.views.mixins", "ProtectedResourceMixin", "oauth2_provider.resource_server.mixins"),
    ("oauth2_provider.views.mixins", "OIDCOnlyMixin", "oauth2_provider.authorization_server.oidc.mixins"),
    ("oauth2_provider.views.mixins", "OAuthLibCoreMixin", "oauth2_provider.core.views"),
    (
        "oauth2_provider.views.metadata",
        "OAuthServerMetadataView",
        "oauth2_provider.authorization_server.views.metadata",
    ),
    (
        "oauth2_provider.views.metadata",
        "OAuthProtectedResourceMetadataView",
        "oauth2_provider.resource_server.views.metadata",
    ),
    # Not classes: module-level names that were part of the 3.4.1 public surface and
    # had to be re-exported explicitly after their defining code moved elsewhere.
    ("oauth2_provider.views.mixins", "SAFE_HTTP_METHODS", "oauth2_provider.resource_server.mixins"),
    ("oauth2_provider.cimd", "NAT64_PREFIX", "oauth2_provider.core.safe_fetch"),
}

# Modules that are NOT deprecated -- they keep their import path on purpose -- but
# that re-export a name whose defining code moved. Identity must hold; these must
# NOT warn, so they are kept out of SPLIT_SHIM_SYMBOLS.
NON_DEPRECATED_REEXPORTS = {
    (
        "oauth2_provider.oauth2_validators",
        "_SCHEME_DEFAULT_PORTS",
        "oauth2_provider.resource_server.validators",
    ),
}

# The complete public surface ``oauth2_provider.views.mixins`` exposed before the
# split. A re-export shim only re-exports what it is told to, so a name dropped from
# its import list fails with ImportError at the old path and nothing else notices.
# Freeze the list here: it is the compatibility contract until 4.0.
VIEWS_MIXINS_PUBLIC_NAMES = [
    "OAuthLibMixin",
    "SAFE_HTTP_METHODS",
    "ScopedResourceMixin",
    "ProtectedResourceMixin",
    "ReadWriteScopedResourceMixin",
    "ClientProtectedResourceMixin",
    "ProtectedResourceMetadataMixin",
    "OIDCOnlyMixin",
    "OIDCLogoutOnlyMixin",
]

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
    # Force the shim file to execute again by dropping the cached alias, then
    # restore the original module so a reloaded re-export shim can't leak.
    with _reimport_without_leaking(old), pytest.warns(DeprecationWarning, match="has moved to"):
        importlib.import_module(old)


def test_admin_shim_is_silent():
    with _reimport_without_leaking("oauth2_provider.admin"), warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        importlib.import_module("oauth2_provider.admin")  # must not raise


@pytest.mark.parametrize("old, symbol, new", sorted(SPLIT_SHIM_SYMBOLS))
def test_split_shim_symbol_matches_canonical(old, symbol, new):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        old_obj = getattr(importlib.import_module(old), symbol)
        new_obj = getattr(importlib.import_module(new), symbol)
    assert old_obj is new_obj


@pytest.mark.parametrize("mod, symbol, canonical", sorted(NON_DEPRECATED_REEXPORTS))
def test_non_deprecated_reexport_matches_canonical(mod, symbol, canonical):
    """A retained module re-exporting a moved name: same object, and no warning."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        held = getattr(importlib.import_module(mod), symbol)
    canonical_obj = getattr(importlib.import_module(canonical), symbol)
    assert held is canonical_obj


@pytest.mark.parametrize("old", sorted({o for o, _, _ in SPLIT_SHIM_SYMBOLS}))
def test_split_shim_warns(old):
    with _reimport_without_leaking(old), pytest.warns(DeprecationWarning, match="has moved"):
        importlib.import_module(old)


def test_combined_oauthlib_mixin_warns_on_subclass():
    from django.views.generic import View

    # Importing the shim module itself emits a DeprecationWarning; silence it so this
    # test asserts only on the subclass-time warning below (and stays robust if the
    # suite ever treats deprecations as errors).
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        from oauth2_provider.views.mixins import OAuthLibMixin

    with pytest.warns(DeprecationWarning, match="OAuthLibMixin is deprecated"):

        class _LegacyView(OAuthLibMixin, View):
            pass

    # The combined mixin still yields the full API to legacy subclasses.
    assert issubclass(_LegacyView, OAuthLibMixin)
    assert hasattr(_LegacyView, "create_token_response")
    assert hasattr(_LegacyView, "verify_request")


def test_views_mixins_shim_reexports_full_public_surface():
    """Every public name the pre-split module exported must survive at the old path.

    Regression: ``SAFE_HTTP_METHODS`` was dropped from the shim's import list, so
    ``from oauth2_provider.views.mixins import SAFE_HTTP_METHODS`` raised ImportError
    even though the constant still existed at its new home.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        shim = importlib.import_module("oauth2_provider.views.mixins")

    missing = [n for n in VIEWS_MIXINS_PUBLIC_NAMES if not hasattr(shim, n)]
    assert not missing, f"dropped from the views.mixins shim: {missing}"
    # __all__ must advertise them too -- Sphinx autodoc honors __all__ for imported
    # members, and docs/views/details.rst still automodules this path.
    assert not [n for n in VIEWS_MIXINS_PUBLIC_NAMES if n not in shim.__all__]


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


def test_client_package_is_standalone():
    """``oauth2_provider.client`` is the client side and must stay independent.

    It is meant to be usable from a plain client application, so it must not
    reach into the provider packages (which would drag in the app registry and
    models). Guard both the public surface and that independence.
    """
    import oauth2_provider.client.client_assertions as client_module
    from oauth2_provider.client import make_client_assertion

    assert make_client_assertion is client_module.make_client_assertion

    # The RFC 7523 protocol constant is shared plumbing, not owned by a role.
    from oauth2_provider.core.rfc7523 import JWT_BEARER_CLIENT_ASSERTION_TYPE

    assert JWT_BEARER_CLIENT_ASSERTION_TYPE.endswith("client-assertion-type:jwt-bearer")

    # No provider-side imports anywhere in the rp package. Parse the imports
    # rather than grepping the source, so prose about the rule (docstrings that
    # mention the provider packages) does not trip the check.
    package_dir = pathlib.Path(client_module.__file__).parent
    forbidden = ("oauth2_provider.authorization_server", "oauth2_provider.resource_server")
    for path in sorted(package_dir.glob("*.py")):
        tree = ast.parse(path.read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        offenders = [m for m in imported if m.startswith(forbidden)]
        assert not offenders, f"{path.name} imports provider code: {offenders}"


def test_client_assertion_halves_are_split_by_role():
    """Verification is authorization-server code; building is client code."""
    from oauth2_provider.authorization_server import client_assertions as as_half
    from oauth2_provider.client import client_assertions as client_half

    assert hasattr(as_half, "authenticate_client_assertion")
    assert hasattr(client_half, "make_client_assertion")
    # Each half owns only its side.
    assert not hasattr(as_half, "make_client_assertion")
    assert not hasattr(client_half, "authenticate_client_assertion")


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
