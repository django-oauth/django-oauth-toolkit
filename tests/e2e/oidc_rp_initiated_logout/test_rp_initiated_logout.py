"""OpenID Connect RP-Initiated Logout 1.0 (end_session endpoint)."""

from urllib.parse import urlparse

import pytest

from tests.e2e import constants as c


def _login_and_get_id_token(oauth, login):
    session = oauth.login(c.E2E_USERNAME, c.E2E_PASSWORD)
    result = oauth.authorize(
        session,
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
        state="s",
    )
    code = result.query_params["code"]
    id_token = oauth.exchange_code(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        code=code,
        redirect_uri=c.REDIRECT_URI,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
    ).json()["id_token"]
    return session, id_token


@pytest.mark.compliance("OpenID Connect RP-Initiated Logout 1.0", "2", "Logout Request")
@pytest.mark.compliance("OpenID Connect RP-Initiated Logout 1.0", "3", "Redirect to RP")
def test_logout_redirects_to_post_logout_redirect_uri_with_state(oauth, login):
    session, id_token = _login_and_get_id_token(oauth, login)
    resp = oauth.rp_logout(
        session,
        id_token_hint=id_token,
        post_logout_redirect_uri=c.POST_LOGOUT_REDIRECT_URI,
        state="logout-state",
    )
    assert resp.status_code == 302
    assert resp.headers["Location"].startswith(c.POST_LOGOUT_REDIRECT_URI)
    assert "state=logout-state" in resp.headers["Location"]


@pytest.mark.compliance("OpenID Connect RP-Initiated Logout 1.0", "2", "Unregistered redirect rejected")
def test_logout_rejects_unregistered_post_logout_redirect_uri(oauth, login):
    session, id_token = _login_and_get_id_token(oauth, login)
    resp = oauth.rp_logout(
        session,
        id_token_hint=id_token,
        post_logout_redirect_uri="http://evil.example/after-logout",
        state="s",
    )
    # An unregistered post_logout_redirect_uri MUST NOT be redirected to.
    assert resp.status_code == 400
    # Check the parsed redirect target host rather than a substring so the
    # assertion cannot be fooled by the URL appearing elsewhere in Location.
    assert urlparse(resp.headers.get("Location", "")).netloc != "evil.example"
