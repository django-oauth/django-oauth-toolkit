"""
Fixtures for the browser layer: a live IdP on port 8000 plus the real SvelteKit
RP on 5173, driven through Chromium with Playwright.

These tests are skipped automatically when Playwright / pytest-playwright or a
working Node toolchain is not available, so the rest of the compliance suite
still runs in minimal environments.
"""

import os

import pytest

from tests.e2e import constants as c


pytest.importorskip("playwright")
pytest.importorskip("pytest_playwright")

from tests.e2e.helpers.idp_process import IdpServer  # noqa: E402
from tests.e2e.helpers.rp_process import RpServer, chromium_executable  # noqa: E402


def _skip_or_fail(message):
    """Skip the browser layer, or fail it when E2E_REQUIRE_BROWSER is set.

    CI sets E2E_REQUIRE_BROWSER so that a missing browser or an IdP/RP that
    won't start is a hard failure rather than silently dropped coverage; local
    and protocol-only runs keep skipping.
    """
    if os.environ.get("E2E_REQUIRE_BROWSER"):
        pytest.fail(f"{message}; E2E_REQUIRE_BROWSER is set so the browser layer must run")
    pytest.skip(f"{message}; skipping browser layer")


@pytest.fixture(scope="session")
def browser_type_launch_args(browser_type_launch_args):
    """Point Playwright at the pre-installed Chromium when present."""
    exe = chromium_executable()
    if exe:
        return {**browser_type_launch_args, "executable_path": exe}
    return browser_type_launch_args


@pytest.fixture(scope="session", autouse=True)
def _require_browser(browser_type, browser_type_launch_args):
    """Skip the browser layer when no Chromium can launch — unless it is required.

    pytest-playwright's ``page`` fixture errors during setup if the browser
    binary is missing; this guard turns that into a clean skip so protocol-only
    environments (where ``playwright install`` was best-effort) stay green.

    Set ``E2E_REQUIRE_BROWSER`` (as CI does) to make a missing browser a hard
    failure instead, so the browser coverage cannot be silently skipped.
    """
    try:
        browser = browser_type.launch(**browser_type_launch_args)
    except Exception as exc:  # pragma: no cover - environment guard
        _skip_or_fail(f"No usable Chromium for Playwright ({exc})")
    else:
        browser.close()


@pytest.fixture(scope="session")
def browser_idp():
    # The RP is hard-configured for http://localhost:8000, so pin host+port.
    server = IdpServer(
        host="localhost",
        port=8000,
        scopes=c.E2E_SCOPES,
        default_scopes=c.E2E_DEFAULT_SCOPES,
        pkce_required=False,
        pkce_required_client_ids=c.PKCE_REQUIRED_CLIENT_IDS,
        # The device page in the RP talks to 127.0.0.1:8000 while OIDC uses
        # localhost:8000; allow both so neither hits DisallowedHost.
        allowed_hosts=["localhost", "127.0.0.1"],
    )
    try:
        server.start()
    except Exception as exc:  # pragma: no cover - environment guard
        _skip_or_fail(f"Could not start IdP for browser tests: {exc}")
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture(scope="session")
def rp_server(browser_idp):
    server = RpServer()
    try:
        server.start()
    except Exception as exc:  # pragma: no cover - environment guard
        _skip_or_fail(f"Could not start SvelteKit RP (Node/npm required): {exc}")
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def rp_login(rp_server):
    """Return a helper that logs the given page in through the IdP."""

    def _login(page, username=c.SUPERUSER_USERNAME, password=c.SUPERUSER_PASSWORD):
        page.goto(rp_server.base_url)
        button = page.get_by_role("button", name="Login")
        button.wait_for(state="visible")
        page.wait_for_timeout(1200)  # allow SvelteKit to hydrate before clicking
        button.click()
        page.wait_for_selector("#id_username", timeout=20000)
        page.fill("#id_username", username)
        page.fill("#id_password", password)
        page.click("button[type=submit]")
        page.wait_for_function("document.body.innerText.includes('eyJ')", timeout=20000)

    return _login
