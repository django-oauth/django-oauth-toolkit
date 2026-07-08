"""
Fixtures and pytest wiring for the specification-organized end-to-end /
compliance suite.

The suite is black-box: it boots the real ``tests/app/idp`` Django project as a
live server (see ``helpers/idp_process.py``) and drives it purely over HTTP with
the Python relying-party client in ``helpers/oauth_client.py`` (and, for the
browser layer, the real SvelteKit RP via Playwright).
"""

import pytest

from . import constants
from .compliance import CompliancePlugin
from .helpers.idp_process import IdpServer
from .helpers.oauth_client import OAuthClient


# Directory-name -> (spec label, marker name). The module a test lives in
# declares which specification it exercises; the marker lets you run one spec's
# suite (e.g. ``pytest -m spec_rfc7636``) and feeds the compliance report.
SPEC_BY_PACKAGE = {
    "rfc6749_authorization_code": ("RFC 6749", "spec_rfc6749"),
    "rfc6749_client_credentials": ("RFC 6749", "spec_rfc6749"),
    "rfc6749_resource_owner_password": ("RFC 6749", "spec_rfc6749"),
    "rfc6749_implicit": ("RFC 6749", "spec_rfc6749"),
    "rfc6749_refresh_token": ("RFC 6749", "spec_rfc6749"),
    "rfc7636_pkce": ("RFC 7636", "spec_rfc7636"),
    "rfc7009_revocation": ("RFC 7009", "spec_rfc7009"),
    "rfc7662_introspection": ("RFC 7662", "spec_rfc7662"),
    "rfc8414_as_metadata": ("RFC 8414", "spec_rfc8414"),
    "rfc8628_device_grant": ("RFC 8628", "spec_rfc8628"),
    "rfc7591_dynamic_client_registration": ("RFC 7591", "spec_rfc7591"),
    "oidc_core": ("OpenID Connect Core 1.0", "spec_oidc_core"),
    "oidc_discovery": ("OpenID Connect Discovery 1.0", "spec_oidc_discovery"),
    "oidc_rp_initiated_logout": ("OpenID Connect RP-Initiated Logout 1.0", "spec_oidc_rp_logout"),
    "browser_rp": ("Browser RP (SvelteKit)", "spec_browser_rp"),
}

ALL_SPEC_MARKERS = sorted({marker for _, marker in SPEC_BY_PACKAGE.values()})


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "compliance(spec, section, requirement): bind a test to a specification requirement "
        "for the generated compliance matrix.",
    )
    config.addinivalue_line("markers", "deprecated: flow discouraged by OAuth 2.1 (implicit, ROPC).")
    config.addinivalue_line("markers", "browser: requires a real browser (Playwright) + the SvelteKit RP.")
    for marker in ALL_SPEC_MARKERS:
        config.addinivalue_line("markers", f"{marker}: tests for this specification family.")
    config._compliance_plugin = CompliancePlugin(config)
    config.pluginmanager.register(config._compliance_plugin, "dot-compliance")


def pytest_collection_modifyitems(config, items):
    """Auto-apply the per-spec family marker based on the test's package."""
    for item in items:
        parts = item.nodeid.replace("\\", "/").split("/")
        for part in parts:
            if part in SPEC_BY_PACKAGE:
                item.add_marker(SPEC_BY_PACKAGE[part][1])
                break
    plugin = getattr(config, "_compliance_plugin", None)
    if plugin is not None:
        plugin.register(items, SPEC_BY_PACKAGE)


def pytest_sessionfinish(session, exitstatus):
    plugin = getattr(session.config, "_compliance_plugin", None)
    if plugin is not None:
        result = plugin.write_reports()
        if result:
            md_path, _ = result
            reporter = session.config.pluginmanager.get_plugin("terminalreporter")
            if reporter is not None:
                reporter.write_line(f"Compliance matrix written to {md_path}", green=True)


# --------------------------------------------------------------------------
# Live IdP + client fixtures
# --------------------------------------------------------------------------
@pytest.fixture(scope="session")
def idp_server():
    """A live IdP instance shared across the whole session.

    Launched with the extra e2e scopes and with PKCE required only for the
    dedicated PKCE client, so every supported flow can be exercised against a
    single running server.
    """
    server = IdpServer(
        scopes=constants.E2E_SCOPES,
        default_scopes=constants.E2E_DEFAULT_SCOPES,
        pkce_required=False,
        pkce_required_client_ids=constants.PKCE_REQUIRED_CLIENT_IDS,
    )
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture(scope="session")
def oauth(idp_server):
    return OAuthClient(idp_server.base_url)


@pytest.fixture(scope="session")
def issuer(idp_server):
    return idp_server.issuer


@pytest.fixture
def login(oauth):
    """Factory: log a resource owner in and return the authenticated session."""

    def _login(username=constants.E2E_USERNAME, password=constants.E2E_PASSWORD):
        return oauth.login(username, password)

    return _login


@pytest.fixture
def user_session(login):
    """A session already authenticated as the claims-rich e2e user."""
    return login()
