"""
Browser-driven end-to-end tests against the real SvelteKit relying party
(``tests/app/rp``) — the flows the shipped RP implements, exercised through
Chromium: OIDC Authorization Code login (with real redirects, fragments and
CORS), token refresh, and Device Authorization initiation.
"""

import pytest

from tests.e2e.helpers.browser import click_until


pytestmark = pytest.mark.browser


@pytest.mark.compliance("OpenID Connect Core 1.0", "3.1", "Authorization Code Flow (browser RP)")
def test_browser_oidc_login_populates_tokens(page, rp_login):
    rp_login(page)
    # The RP renders isAuthenticated + tokens once the code flow completes.
    assert "true" in page.locator("table").first.inner_text().lower()
    body = page.locator("body").inner_text()
    assert "eyJ" in body, "the ID token (a JWT) should be displayed after login"


@pytest.mark.compliance("RFC 6749", "6", "Refresh Token (browser RP)")
def test_browser_refresh_token(page, rp_login):
    rp_login(page)
    # Wait for the actual refresh request to the token endpoint rather than a
    # fixed sleep, so the assertion is tied to a concrete signal.
    with page.expect_response(lambda r: "/o/token/" in r.url and r.request.method == "POST", timeout=20000):
        page.get_by_role("button", name="refreshToken").click()
    # After refreshing, the RP stays authenticated with a token still displayed.
    assert "true" in page.locator("table").first.inner_text().lower()
    assert "eyJ" in page.locator("body").inner_text()


@pytest.mark.compliance("RFC 8628", "3.2", "Device Authorization Request (browser RP)")
def test_browser_device_authorization_initiation(page, rp_server):
    page.goto(rp_server.base_url + "/device")
    button = page.get_by_role("button", name="Start Device Authorization")
    # Re-click until the device-authorization response (over CORS) advances the
    # RP to the polling state — tolerates hydration without a fixed sleep.
    click_until(
        button,
        lambda: page.wait_for_selector("text=Step 2: Authorize the Device", timeout=1500),
    )
    body = page.locator("body").inner_text()
    assert "Verification URL" in body
    assert "Polling for authorization" in body
