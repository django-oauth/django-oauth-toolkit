"""RFC 7009 — OAuth 2.0 Token Revocation."""

import pytest

from tests.e2e import constants as c


def _tokens(oauth, user_session):
    result = oauth.authorize(
        user_session,
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid read",
        state="s",
    )
    code = result.query_params["code"]
    return oauth.exchange_code(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        code=code,
        redirect_uri=c.REDIRECT_URI,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
    ).json()


@pytest.mark.compliance("RFC 7009", "2.1", "Revocation Request (access token)")
@pytest.mark.compliance("RFC 7009", "2.2", "Revocation Response")
def test_revoked_access_token_is_no_longer_accepted(oauth, user_session):
    tokens = _tokens(oauth, user_session)
    access_token = tokens["access_token"]
    assert oauth.userinfo(access_token).status_code == 200

    resp = oauth.revoke(
        token=access_token,
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
        token_type_hint="access_token",
    )
    assert resp.status_code == 200
    assert oauth.userinfo(access_token).status_code == 401


@pytest.mark.compliance("RFC 7009", "2.1", "Revocation Request (refresh token)")
def test_revoked_refresh_token_cannot_be_used(oauth, user_session):
    tokens = _tokens(oauth, user_session)
    resp = oauth.revoke(
        token=tokens["refresh_token"],
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
        token_type_hint="refresh_token",
    )
    assert resp.status_code == 200
    used = oauth.refresh(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        refresh_token=tokens["refresh_token"],
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
    )
    assert used.status_code == 400
    assert used.json()["error"] == "invalid_grant"


@pytest.mark.compliance("RFC 7009", "2.2", "Unknown token returns 200")
def test_revoking_unknown_token_returns_200(oauth):
    resp = oauth.revoke(
        token="this-token-does-not-exist",
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
    )
    # RFC 7009 2.2: the endpoint responds with 200 even for an invalid token.
    assert resp.status_code == 200
