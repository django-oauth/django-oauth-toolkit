"""
RFC 6749 section 4.3 — Resource Owner Password Credentials Grant.

Marked ``deprecated``: this grant is discouraged by OAuth 2.1 and included only
for completeness of the compliance matrix. Run ``pytest -m 'not deprecated'`` to
skip it.
"""

import pytest

from tests.e2e import constants as c


pytestmark = pytest.mark.deprecated


@pytest.mark.compliance("RFC 6749", "4.3.2", "Access Token Request")
@pytest.mark.compliance("RFC 6749", "4.3.3", "Access Token Response")
def test_password_grant_issues_access_token(oauth):
    resp = oauth.password_grant(
        client_id=c.PASSWORD_CLIENT_ID,
        client_secret=c.PASSWORD_SECRET,
        username=c.E2E_USERNAME,
        password=c.E2E_PASSWORD,
        scope="read",
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"].lower() == "bearer"
    assert body["access_token"]


@pytest.mark.compliance("RFC 6749", "5.2", "Invalid Grant")
def test_password_grant_wrong_password_is_invalid_grant(oauth):
    resp = oauth.password_grant(
        client_id=c.PASSWORD_CLIENT_ID,
        client_secret=c.PASSWORD_SECRET,
        username=c.E2E_USERNAME,
        password="not-the-password",
        scope="read",
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"
