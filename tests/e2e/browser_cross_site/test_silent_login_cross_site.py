"""
Third-party-cookie behaviour of OIDC silent login (``prompt=none``), driven
through two real engines against genuinely cross-site hosts.

The authorization server behaves identically in every run here; what differs is
the user agent. Whether a relying party can refresh a session behind the scenes
depends entirely on whether the browser lets the OP's cookie into a third-party
iframe: Chromium (today, with third-party cookies allowed) does, and the RP gets
an authorization ``code``; Firefox with Total Cookie Protection does not, and
the RP gets ``login_required``.

This is the coverage that OIDC Session Management and Front-Channel Logout will
need when they land — both depend on the same cookie reaching the same kind of
frame — so the harness is in place ahead of them.
"""

import pytest

from tests.e2e import constants as c


pytestmark = pytest.mark.browser


def _probe(browser, idp, rp, login=True):
    """Read the cross-site iframe's outcome, optionally after an OP login."""
    context = browser.new_context(ignore_https_errors=True)
    try:
        page = context.new_page()

        if login:
            # First-party, top-level login at the OP. This leg is identical in
            # both engines: the session cookie is set during a top-level
            # navigation to idp.test, so it lands in the unpartitioned jar
            # either way.
            page.goto(f"{idp.base_url}/accounts/login/?next=/")
            page.wait_for_selector("#id_username", timeout=20000)
            page.fill("#id_username", c.SUPERUSER_USERNAME)
            page.fill("#id_password", c.SUPERUSER_PASSWORD)
            page.click("button[type=submit]")
            page.wait_for_url(f"{idp.base_url}/", timeout=20000)

            # Fail loudly when it is the *setup* that broke rather than the
            # cookie policy. Without a Secure, SameSite=None session cookie
            # every engine would answer login_required, and the Firefox
            # assertion below would pass for entirely the wrong reason.
            session = [cookie for cookie in context.cookies() if cookie["name"] == "sessionid"]
            assert session, f"the OP set no session cookie on login:\n{idp.read_log()[-2000:]}"
            assert session[0]["secure"], "the OP session cookie is not Secure"
            assert session[0]["sameSite"] == "None", (
                f"the OP session cookie is SameSite={session[0]['sameSite']}; it can never "
                "reach a third-party iframe"
            )

        # Cross-site leg: rp.test frames idp.test's authorization endpoint.
        page.goto(f"{rp.base_url}/silent")
        # Guard against the RP silently falling back to its localhost defaults,
        # which would make the iframe same-site and the whole comparison moot.
        # The URL is built on mount, so wait for hydration rather than reading
        # the server-rendered placeholder.
        page.wait_for_function(
            "document.querySelector('[data-testid=silent-src]')?.textContent.trim() !== ''",
            timeout=20000,
        )
        assert idp.base_url in page.locator("[data-testid=silent-src]").inner_text(), (
            "the RP is not framing the cross-site IdP; PUBLIC_RP_ISSUER did not reach the app"
        )
        try:
            page.wait_for_function(
                "document.querySelector('[data-testid=silent-outcome]')?.textContent.trim() !== 'pending'",
                timeout=20000,
            )
        except Exception as exc:
            raise AssertionError(
                "the silent-login iframe never reported a result — the OP probably "
                "rendered an error page (which X-Frame-Options: DENY keeps blank) "
                f"instead of redirecting:\n{idp.read_log()[-4000:]}"
            ) from exc
        return page.locator("[data-testid=silent-outcome]").inner_text().strip()
    finally:
        context.close()


@pytest.mark.compliance(
    "OpenID Connect Core 1.0",
    "3.1.2.1",
    "prompt=none silent login returns a code in a cross-site iframe (third-party cookies allowed)",
)
def test_chromium_silent_login_returns_code(chromium, cross_site_idp, cross_site_rp):
    assert _probe(chromium, cross_site_idp, cross_site_rp) == "code"


@pytest.mark.compliance(
    "OpenID Connect Core 1.0",
    "3.1.2.6",
    "prompt=none returns login_required when the iframe carries no OP cookie",
)
def test_silent_login_without_an_op_session_yields_login_required(chromium, cross_site_idp, cross_site_rp):
    """The no-cookie-at-all case, reachable without Firefox.

    A partitioned iframe and an iframe belonging to a user who never logged in
    look identical to the OP: the authorization request simply arrives with no
    Cookie header. That is the shape the OP has to answer with login_required
    rather than an error page — which, carrying X-Frame-Options: DENY, would
    leave the frame blank and give the RP nothing at all.
    """
    assert _probe(chromium, cross_site_idp, cross_site_rp, login=False) == "login_required"


@pytest.mark.compliance(
    "OpenID Connect Core 1.0",
    "3.1.2.6",
    "prompt=none returns login_required when the OP cookie is partitioned away",
)
def test_firefox_total_cookie_protection_yields_login_required(
    firefox_partitioning, cross_site_idp, cross_site_rp
):
    # Exactly login_required, not merely "an error": a misconfigured client or
    # an unregistered redirect_uri would surface as invalid_request or
    # no-parameters, and a dead iframe as timeout.
    assert _probe(firefox_partitioning, cross_site_idp, cross_site_rp) == "login_required"


@pytest.mark.compliance(
    "OpenID Connect Core 1.0",
    "3.1.2.1",
    "prompt=none silent login returns a code in Firefox when third-party cookies are allowed",
)
def test_firefox_without_partitioning_returns_code(firefox_permissive, cross_site_idp, cross_site_rp):
    # Control for the test above: same engine, same URLs, same certificate,
    # same OP — only the cookie policy differs. If this fails, the
    # login_required result above is a broken setup, not a partitioning result.
    assert _probe(firefox_permissive, cross_site_idp, cross_site_rp) == "code"
