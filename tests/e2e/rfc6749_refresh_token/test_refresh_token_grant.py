"""RFC 6749 section 6 — Refreshing an Access Token (+ rotation / reuse protection)."""

import pytest

from tests.e2e import constants as c


def _fresh_tokens(oauth, user_session):
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


@pytest.mark.compliance("RFC 6749", "6", "Refreshing an Access Token")
def test_refresh_token_returns_new_access_token(oauth, user_session):
    tokens = _fresh_tokens(oauth, user_session)
    resp = oauth.refresh(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        refresh_token=tokens["refresh_token"],
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"] and body["access_token"] != tokens["access_token"]


@pytest.mark.compliance("RFC 6749", "6", "Refresh token rotation")
def test_refresh_token_is_rotated_and_old_token_is_revoked(oauth, user_session):
    tokens = _fresh_tokens(oauth, user_session)
    old_rt = tokens["refresh_token"]

    first = oauth.refresh(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        refresh_token=old_rt,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
    ).json()
    new_rt = first["refresh_token"]
    assert new_rt != old_rt, "refresh token MUST be rotated"

    # Reusing the rotated-out refresh token MUST fail.
    reuse = oauth.refresh(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        refresh_token=old_rt,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
    )
    assert reuse.status_code == 400
    assert reuse.json()["error"] == "invalid_grant"

    # The new refresh token still works.
    again = oauth.refresh(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        refresh_token=new_rt,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
    )
    assert again.status_code == 200


@pytest.mark.compliance("RFC 6749", "5.2", "Invalid Grant")
def test_unknown_refresh_token_is_invalid_grant(oauth):
    resp = oauth.refresh(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        refresh_token="not-a-real-refresh-token",
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"
