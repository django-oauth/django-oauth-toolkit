"""RFC 6749 section 4.4 — Client Credentials Grant."""

import pytest

from tests.e2e import constants as c


@pytest.mark.compliance("RFC 6749", "4.4.2", "Access Token Response")
def test_client_credentials_issues_access_token(oauth):
    resp = oauth.client_credentials(
        client_id=c.CLIENT_CREDENTIALS_CLIENT_ID,
        client_secret=c.CLIENT_CREDENTIALS_SECRET,
        scope="read write",
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"].lower() == "bearer"
    assert body["access_token"]
    assert set(body["scope"].split()) <= {"read", "write"}


@pytest.mark.compliance("RFC 6749", "5.2", "Invalid Client Authentication")
def test_client_credentials_wrong_secret_is_invalid_client(oauth):
    resp = oauth.client_credentials(
        client_id=c.CLIENT_CREDENTIALS_CLIENT_ID,
        client_secret="wrong-secret",
        scope="read",
    )
    assert resp.status_code in (400, 401)
    assert resp.json()["error"] == "invalid_client"
