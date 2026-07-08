"""
Browser-driven end-to-end tests against the real SvelteKit relying party
(``tests/app/rp``) — the flows the shipped RP implements, exercised through
Chromium: OIDC Authorization Code login (with real redirects, fragments and
CORS), token refresh, and Device Authorization initiation.
"""

import pytest


pytestmark = pytest.mark.browser


@pytest.mark.compliance("OpenID Connect Core 1.0", "3.1", "Authorization Code Flow (browser RP)")
def test_browser_oidc_login_populates_tokens(page, rp_login):
    rp_login(page)
    # The RP renders isAuthenticated + tokens once the code flow completes.
    assert "true" in page.locator("table").first.inner_text().lower()
    body = page.locator("body").inner_text()
    assert "eyJ" in body, "an access/ID token (JWT) should be displayed after login"


@pytest.mark.compliance("RFC 6749", "6", "Refresh Token (browser RP)")
def test_browser_refresh_token(page, rp_login):
    rp_login(page)
    page.get_by_role("button", name="refreshToken").click()
    # After refreshing, the RP stays authenticated with no error surfaced.
    page.wait_for_timeout(1500)
    first_table = page.locator("table").first.inner_text().lower()
    assert "true" in first_table
    assert "eyJ" in page.locator("body").inner_text()


@pytest.mark.compliance("RFC 8628", "3.2", "Device Authorization Request (browser RP)")
def test_browser_device_authorization_initiation(page, rp_server):
    page.goto(rp_server.base_url + "/device")
    button = page.get_by_role("button", name="Start Device Authorization")
    button.wait_for(state="visible")
    page.wait_for_timeout(1200)  # allow SvelteKit to hydrate before clicking
    button.click()
    # A successful device-authorization response (over CORS) advances the RP to
    # the polling state, which shows the verification URL + user code.
    page.wait_for_selector("text=Step 2: Authorize the Device", timeout=20000)
    body = page.locator("body").inner_text()
    assert "Verification URL" in body
    assert "Polling for authorization" in body
