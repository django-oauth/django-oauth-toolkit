"""
Fixtures for the cross-site browser layer.

Everything the ``browser_rp`` package does happens on one registrable domain
(``localhost:8000`` / ``localhost:5173``): ports do not count toward "site", so
a browser treats an OP iframe embedded by the RP as *first-party* and
third-party-cookie policy never engages. This package therefore runs a second
IdP + RP pair on two genuinely distinct registrable domains, ``idp.test`` and
``rp.test``. ``.test`` is an IANA special-use TLD that is absent from the Public
Suffix List, so the whole two-label host is the registrable domain and the two
are different sites.

The pair is served over TLS with a throwaway self-signed certificate. That is
not incidental: the OP session cookie has to be ``SameSite=None``, browsers only
honour ``SameSite=None`` alongside ``Secure``, and ``Secure`` requires a secure
context. Over plain HTTP the cookie would be withheld from the iframe in *every*
engine and the two-engine comparison would prove nothing.

Both hosts must resolve to loopback (CI adds them to ``/etc/hosts``); when they
do not, the layer skips, or fails under ``E2E_REQUIRE_BROWSER``.
"""

import os
import socket

import pytest

from tests.e2e import constants as c


pytest.importorskip("playwright")
pytest.importorskip("pytest_playwright")

from tests.e2e.helpers.browser import skip_or_fail  # noqa: E402
from tests.e2e.helpers.idp_process import IdpServer  # noqa: E402
from tests.e2e.helpers.rp_process import (  # noqa: E402
    RpServer,
    chromium_executable,
    firefox_executable,
)
from tests.e2e.helpers.tls import generate_self_signed_cert  # noqa: E402


IDP_HOST = "idp.test"
RP_HOST = "rp.test"
# Fixed ports: they appear verbatim in the client's registered redirect_uris,
# and they are deliberately distinct from browser_rp's 8000/5173 so both
# session-scoped server pairs can be alive at once in a single pytest session.
IDP_PORT = 8443
RP_PORT = 5443

IDP_ORIGIN = f"https://{IDP_HOST}:{IDP_PORT}"
RP_ORIGIN = f"https://{RP_HOST}:{RP_PORT}"


@pytest.fixture(scope="session", autouse=True)
def _require_cross_site_hosts():
    """Require idp.test and rp.test to resolve to the loopback interface.

    CI adds them to /etc/hosts. Locally they usually are not present, so the
    layer skips — unless E2E_REQUIRE_BROWSER is set, where a missing entry is a
    hard failure: silently dropping this coverage is the exact failure mode that
    flag exists to prevent.
    """
    for host in (IDP_HOST, RP_HOST):
        try:
            resolved = socket.gethostbyname(host)
        except OSError as exc:
            skip_or_fail(
                f'{host} does not resolve ({exc}); add "127.0.0.1 {IDP_HOST} {RP_HOST}" to /etc/hosts'
            )
        else:
            if not resolved.startswith("127."):
                skip_or_fail(f"{host} resolves to {resolved}, not the loopback interface")


@pytest.fixture(scope="session")
def cross_site_tls(tmp_path_factory):
    return generate_self_signed_cert(
        tmp_path_factory.mktemp("e2e-tls"),
        hostnames=[IDP_HOST, RP_HOST, "localhost"],
    )


@pytest.fixture(scope="session")
def cross_site_idp(cross_site_tls):
    certfile, keyfile = cross_site_tls
    server = IdpServer(
        host=IDP_HOST,
        bind_host="127.0.0.1",
        port=IDP_PORT,
        scopes=c.E2E_SCOPES,
        default_scopes=c.E2E_DEFAULT_SCOPES,
        pkce_required=False,
        pkce_required_client_ids=c.PKCE_REQUIRED_CLIENT_IDS,
        allowed_hosts=[IDP_HOST, "127.0.0.1", "localhost"],
        ssl_certfile=certfile,
        ssl_keyfile=keyfile,
        # The whole point of this layer: without SameSite=None the OP session
        # cookie never reaches a third-party iframe in any engine.
        session_cookie_samesite="None",
        secure_cookies=True,
        csrf_trusted_origins=[IDP_ORIGIN],
    )
    try:
        server.start()
    except Exception as exc:  # pragma: no cover - environment guard
        skip_or_fail(f"Could not start the cross-site IdP: {exc}")
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture(scope="session")
def cross_site_rp(cross_site_idp, cross_site_tls):
    certfile, keyfile = cross_site_tls
    server = RpServer(
        host=RP_HOST,
        bind_host="127.0.0.1",
        port=RP_PORT,
        tls_cert=certfile,
        tls_key=keyfile,
        # browser_rp's dev server is alive at the same time, out of the same
        # project directory; without this they clobber each other's build state.
        isolate_build=True,
        env={
            "PUBLIC_RP_ISSUER": cross_site_idp.issuer,
            "PUBLIC_RP_CLIENT_ID": c.RP_OIDC_CLIENT_ID,
            "PUBLIC_RP_ORIGIN": RP_ORIGIN,
        },
    )
    try:
        server.start()
    except Exception as exc:  # pragma: no cover - environment guard
        skip_or_fail(f"Could not start the cross-site SvelteKit RP: {exc}")
    try:
        yield server
    finally:
        server.stop()


# idp.test and rp.test are /etc/hosts aliases for loopback, but they do not
# *look* local, so an ambient HTTP(S)_PROXY in the environment would have the
# browser try to reach them through it. Hand the browser process an environment
# with those variables removed.
_PROXY_ENV_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy")


def _browser_env():
    return {key: value for key, value in os.environ.items() if key.lower() not in _PROXY_ENV_VARS}


def _launch(browser_type, executable, **kwargs):
    if executable:
        kwargs["executable_path"] = executable
    try:
        return browser_type.launch(env=_browser_env(), **kwargs)
    except Exception as exc:  # pragma: no cover - environment guard
        skip_or_fail(f"No usable {browser_type.name} for Playwright ({exc})")


# The engines are launched explicitly rather than through pytest-playwright's
# ``browser``/``page`` fixtures: this layer is a *comparison* between engines
# within one session, and ``firefox_user_prefs`` is Firefox-only (passing it to
# ``chromium.launch()`` is an error).
@pytest.fixture(scope="session")
def chromium(playwright):
    browser = _launch(playwright.chromium, chromium_executable())
    yield browser
    browser.close()


@pytest.fixture(scope="session")
def firefox_partitioning(playwright):
    """Firefox with Total Cookie Protection pinned on (its shipped default)."""
    browser = _launch(
        playwright.firefox,
        firefox_executable(),
        # 5 == BEHAVIOR_REJECT_TRACKER_AND_PARTITION_FOREIGN. Pinned rather than
        # inherited so the assertion cannot quietly change meaning when the
        # bundled Firefox changes its default.
        firefox_user_prefs={"network.cookie.cookieBehavior": 5},
    )
    yield browser
    browser.close()


@pytest.fixture(scope="session")
def firefox_permissive(playwright):
    """Control engine: the same Firefox with third-party cookies accepted.

    A broken setup — bad certificate, unregistered redirect_uri, a 500 in the OP
    — also yields "not a code", which is exactly what the partitioning test
    expects to see. This control fails in that case and passes only when the
    difference really is the cookie policy.
    """
    browser = _launch(
        playwright.firefox,
        firefox_executable(),
        firefox_user_prefs={"network.cookie.cookieBehavior": 0},
    )
    yield browser
    browser.close()
