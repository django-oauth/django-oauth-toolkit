"""
Browser-driven test of the SvelteKit RP's Pushed Authorization Requests demo
(``tests/app/rp`` ``/par`` route).

PAR is a back-channel flow, so the RP's SvelteKit *server* performs the push to
the IdP (holding the client secret); only ``client_id`` + ``request_uri`` travel
through the browser. This drives that real flow through Chromium: push →
request_uri → login → consent → the server-side code exchange that renders the
tokens.
"""

import pytest

from tests.e2e.helpers.browser import click_until


pytestmark = pytest.mark.browser


@pytest.mark.compliance("RFC 9126", "2.1", "Pushed Authorization Request (browser RP)")
@pytest.mark.compliance("RFC 9126", "4", "Authorization Request (browser RP)")
def test_browser_par_flow(page, rp_server):
    page.goto(rp_server.base_url + "/par")

    # Step 1: the RP server pushes the request (back channel) and returns a request_uri.
    push = page.get_by_role("button", name="Push authorization request")
    click_until(push, lambda: page.wait_for_selector("text=received a request_uri", timeout=1500))
    assert "urn:ietf:params:oauth:request_uri:" in page.locator("body").inner_text()

    # Step 2: only client_id + request_uri travel through the browser to /authorize.
    page.get_by_role("link", name="Continue to the authorization endpoint").click()

    # Resource-owner login.
    page.wait_for_selector("#id_username", timeout=20000)
    page.fill("#id_username", "superuser")
    page.fill("#id_password", "password")
    page.click("button[type=submit]")

    # Approve consent (the demo client does not skip authorization).
    page.wait_for_selector("input[name=allow]", timeout=20000)
    page.click("input[name=allow]")

    # Step 3: the RP server exchanged the code; the token response is displayed.
    page.wait_for_function("document.body.innerText.includes('access_token')", timeout=20000)
    body = page.locator("body").inner_text()
    assert "access_token" in body
    assert "eyJ" in body, "the id_token (openid scope) is a JWT and should be shown"
