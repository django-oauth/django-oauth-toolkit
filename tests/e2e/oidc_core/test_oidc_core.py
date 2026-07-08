"""
OpenID Connect Core 1.0 — Hybrid Flow, UserInfo, and scope-gated claims.

(The Authorization Code Flow's ID Token issuance/validation is covered in
``rfc6749_authorization_code``; this module focuses on the OIDC-specific
behaviours.)
"""

import pytest

from tests.e2e import constants as c
from tests.e2e.helpers.jwt_tools import validate_id_token


@pytest.mark.compliance("OpenID Connect Core 1.0", "3.3.2.5", "Hybrid Authorization Response")
def test_hybrid_flow_returns_code_and_id_token(oauth, user_session, issuer):
    result = oauth.authorize(
        user_session,
        client_id=c.HYBRID_CLIENT_ID,
        response_type="code id_token",
        redirect_uri=c.REDIRECT_URI,
        scope="openid email",
        state="hybrid-state",
        nonce="hybrid-nonce",
    )
    assert result.status_code == 302
    frag = result.fragment_params
    assert frag["code"], "hybrid response MUST include the authorization code"
    assert frag["state"] == "hybrid-state"
    claims = validate_id_token(frag["id_token"], issuer=issuer, audience=c.HYBRID_CLIENT_ID)
    assert claims["nonce"] == "hybrid-nonce"

    # The code from the hybrid response is still exchangeable at the token endpoint.
    token_resp = oauth.exchange_code(
        client_id=c.HYBRID_CLIENT_ID,
        code=frag["code"],
        redirect_uri=c.REDIRECT_URI,
        client_secret=c.HYBRID_SECRET,
    )
    assert token_resp.status_code == 200


@pytest.mark.compliance("OpenID Connect Core 1.0", "5.3.2", "UserInfo Response")
def test_userinfo_returns_claims_for_granted_scopes(oauth, user_session):
    result = oauth.authorize(
        user_session,
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid email profile",
        state="s",
    )
    code = result.query_params["code"]
    access_token = oauth.exchange_code(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        code=code,
        redirect_uri=c.REDIRECT_URI,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
    ).json()["access_token"]

    resp = oauth.userinfo(access_token)
    assert resp.status_code == 200
    body = resp.json()
    assert body["sub"]
    assert body["email"] == c.E2E_EMAIL
    assert body["given_name"] == c.E2E_GIVEN_NAME


@pytest.mark.compliance("OpenID Connect Core 1.0", "5.4", "Requesting Claims using Scope Values")
def test_userinfo_omits_email_when_scope_not_granted(oauth, user_session):
    result = oauth.authorize(
        user_session,
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",  # no email/profile scope
        state="s",
    )
    code = result.query_params["code"]
    access_token = oauth.exchange_code(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        code=code,
        redirect_uri=c.REDIRECT_URI,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
    ).json()["access_token"]

    body = oauth.userinfo(access_token).json()
    assert body["sub"]
    assert "email" not in body
    assert "given_name" not in body
