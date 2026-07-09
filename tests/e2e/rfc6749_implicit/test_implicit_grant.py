"""
RFC 6749 section 4.2 — Implicit Grant (and OIDC implicit response types).

Marked ``deprecated``: discouraged by OAuth 2.1, retained for completeness.
The access token / id_token are returned in the redirect URI *fragment*.
"""

import pytest

from tests.e2e import constants as c
from tests.e2e.helpers.jwt_tools import validate_id_token


pytestmark = pytest.mark.deprecated


@pytest.mark.compliance("RFC 6749", "4.2.2", "Access Token Response")
def test_implicit_returns_access_token_in_fragment(oauth, user_session):
    result = oauth.authorize(
        user_session,
        client_id=c.IMPLICIT_CLIENT_ID,
        response_type="token",
        redirect_uri=c.REDIRECT_URI,
        scope="read",
        state="implicit-state",
    )
    assert result.status_code == 302
    frag = result.fragment_params
    assert frag["access_token"]
    assert frag["token_type"].lower() == "bearer"
    assert frag["state"] == "implicit-state"
    assert "code" not in frag


@pytest.mark.compliance("OpenID Connect Core 1.0", "3.2.2.5", "Implicit id_token token")
def test_oidc_implicit_returns_id_token_and_access_token(oauth, user_session, issuer):
    result = oauth.authorize(
        user_session,
        client_id=c.IMPLICIT_CLIENT_ID,
        response_type="id_token token",
        redirect_uri=c.REDIRECT_URI,
        scope="openid email",
        state="s",
        nonce="nonce-implicit",
    )
    assert result.status_code == 302
    frag = result.fragment_params
    assert frag["access_token"]
    claims = validate_id_token(frag["id_token"], issuer=issuer, audience=c.IMPLICIT_CLIENT_ID)
    assert claims["nonce"] == "nonce-implicit"
