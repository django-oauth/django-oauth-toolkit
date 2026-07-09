"""RFC 7662 — OAuth 2.0 Token Introspection."""

import pytest

from tests.e2e import constants as c
from tests.e2e.helpers.oauth_client import token_data


@pytest.fixture
def introspection_bearer(oauth):
    """A client-credentials access token carrying the ``introspection`` scope,
    used to authenticate calls to the introspection endpoint."""
    resp = oauth.client_credentials(
        client_id=c.CLIENT_CREDENTIALS_CLIENT_ID,
        client_secret=c.CLIENT_CREDENTIALS_SECRET,
        scope="introspection",
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


def _subject_token(oauth, user_session):
    result = oauth.authorize(
        user_session,
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid read",
        state="s",
    )
    code = result.query_params["code"]
    return token_data(
        oauth.exchange_code(
            client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
            code=code,
            redirect_uri=c.REDIRECT_URI,
            client_secret=c.CONFIDENTIAL_CODE_SECRET,
        )
    )["access_token"]


@pytest.mark.compliance("RFC 7662", "2.2", "Introspection Response (active token)")
def test_active_token_introspection(oauth, user_session, introspection_bearer):
    token = _subject_token(oauth, user_session)
    resp = oauth.introspect(token=token, bearer=introspection_bearer)
    assert resp.status_code == 200
    body = resp.json()
    assert body["active"] is True
    assert body["client_id"] == c.CONFIDENTIAL_CODE_CLIENT_ID
    assert "read" in body["scope"].split()
    assert "exp" in body


@pytest.mark.compliance("RFC 7662", "2.2", "Introspection Response (inactive token)")
def test_revoked_token_is_inactive(oauth, user_session, introspection_bearer):
    token = _subject_token(oauth, user_session)
    oauth.revoke(
        token=token,
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
    )
    resp = oauth.introspect(token=token, bearer=introspection_bearer)
    assert resp.status_code == 200
    assert resp.json()["active"] is False


@pytest.mark.compliance("RFC 7662", "2.1", "Introspection requires authorization")
def test_introspection_without_scope_is_rejected(oauth, user_session):
    token = _subject_token(oauth, user_session)
    # A bearer token *without* the introspection scope must not be accepted.
    non_introspection = token_data(
        oauth.client_credentials(
            client_id=c.CLIENT_CREDENTIALS_CLIENT_ID,
            client_secret=c.CLIENT_CREDENTIALS_SECRET,
            scope="read",
        )
    )["access_token"]
    resp = oauth.introspect(token=token, bearer=non_introspection)
    assert resp.status_code in (401, 403)
