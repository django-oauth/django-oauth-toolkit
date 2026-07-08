"""
RFC 6749 section 4.1 — Authorization Code Grant.

Exercised end-to-end against the live IdP with a confidential client that
requires user consent: browser-style login, the consent screen, the
authorization response, the token exchange, and access to the UserInfo
resource.
"""

import pytest

from tests.e2e import constants as c
from tests.e2e.helpers.jwt_tools import validate_id_token
from tests.e2e.helpers.oauth_client import generate_pkce_pair


@pytest.mark.compliance("RFC 6749", "4.1.1", "Authorization Request")
@pytest.mark.compliance("RFC 6749", "4.1.2", "Authorization Response")
def test_authorization_response_returns_code_and_preserves_state(oauth, user_session):
    state = "opaque-state-123"
    result = oauth.authorize(
        user_session,
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
        state=state,
    )
    assert result.status_code == 302
    assert result.location.startswith(c.REDIRECT_URI)
    assert result.query_params["state"] == state, "RFC 6749 4.1.2: state MUST be returned"
    assert result.query_params.get("code"), "authorization code MUST be present"


@pytest.mark.compliance("RFC 6749", "4.1.3", "Access Token Request")
@pytest.mark.compliance("RFC 6749", "4.1.4", "Access Token Response")
def test_authorization_code_exchanged_for_tokens(oauth, user_session, issuer):
    result = oauth.authorize(
        user_session,
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid read",
        state="s",
    )
    code = result.query_params["code"]

    token_resp = oauth.exchange_code(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        code=code,
        redirect_uri=c.REDIRECT_URI,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
    )
    assert token_resp.status_code == 200
    body = token_resp.json()
    assert body["token_type"].lower() == "bearer"
    assert body["access_token"]
    assert body["refresh_token"]
    assert "read" in body["scope"].split()

    # The access token is accepted at the UserInfo resource (OIDC Core 5.3).
    userinfo = oauth.userinfo(body["access_token"])
    assert userinfo.status_code == 200
    assert userinfo.json()["sub"]


@pytest.mark.compliance("RFC 6749", "4.1.2", "Authorization Response")
@pytest.mark.compliance("OpenID Connect Core 1.0", "3.1.2.7", "ID Token Validation")
def test_authorization_code_issues_valid_id_token(oauth, user_session, issuer):
    result = oauth.authorize(
        user_session,
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid email profile",
        state="s",
        nonce="n-123",
    )
    code = result.query_params["code"]
    body = oauth.exchange_code(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        code=code,
        redirect_uri=c.REDIRECT_URI,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
    ).json()

    claims = validate_id_token(body["id_token"], issuer=issuer, audience=c.CONFIDENTIAL_CODE_CLIENT_ID)
    assert claims["nonce"] == "n-123"
    assert claims["email"] == c.E2E_EMAIL
    assert claims["given_name"] == c.E2E_GIVEN_NAME


@pytest.mark.compliance("RFC 6749", "4.1.3", "Access Token Request")
def test_authorization_code_is_single_use(oauth, user_session):
    result = oauth.authorize(
        user_session,
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
        state="s",
    )
    code = result.query_params["code"]
    first = oauth.exchange_code(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        code=code,
        redirect_uri=c.REDIRECT_URI,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
    )
    assert first.status_code == 200

    # RFC 6749 4.1.2: the authorization code MUST NOT be used more than once.
    replay = oauth.exchange_code(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        code=code,
        redirect_uri=c.REDIRECT_URI,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
    )
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"


@pytest.mark.compliance("RFC 6749", "4.1.2.1", "Authorization Error Response")
def test_consent_denied_returns_access_denied(oauth, user_session):
    result = oauth.authorize(
        user_session,
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
        state="deny-state",
        approve=False,
    )
    assert result.status_code == 302
    assert result.query_params["error"] == "access_denied"
    assert result.query_params["state"] == "deny-state"


@pytest.mark.compliance("RFC 6749", "3.1.2.4", "Invalid Redirection URI")
def test_unregistered_redirect_uri_is_rejected(oauth, user_session):
    result = oauth.authorize(
        user_session,
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        response_type="code",
        redirect_uri="http://evil.example/callback",
        scope="openid",
        state="s",
    )
    # A mismatched redirect_uri MUST NOT redirect; the error is shown locally.
    assert result.status_code in (400, 401)
    assert "error" in result.response.text.lower()


@pytest.mark.compliance("RFC 7636", "4.6", "PKCE downgrade")
def test_pkce_required_client_rejects_missing_challenge(oauth, user_session):
    # e2e-public-pkce is in PKCE_REQUIRED_CLIENT_IDS: an authorization request
    # without a code_challenge MUST be rejected.
    result = oauth.authorize(
        user_session,
        client_id=c.PUBLIC_PKCE_CLIENT_ID,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
        state="s",
    )
    assert result.status_code in (400, 302)
    params = result.params
    if result.status_code == 302:
        assert params.get("error") == "invalid_request"
    else:
        assert "error" in result.response.text.lower()


@pytest.mark.compliance("RFC 7636", "4.5", "code_verifier")
def test_public_client_pkce_s256_round_trip(oauth, user_session):
    verifier, challenge = generate_pkce_pair()
    result = oauth.authorize(
        user_session,
        client_id=c.PUBLIC_PKCE_CLIENT_ID,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
        state="s",
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    code = result.query_params["code"]
    token_resp = oauth.exchange_code(
        client_id=c.PUBLIC_PKCE_CLIENT_ID,
        code=code,
        redirect_uri=c.REDIRECT_URI,
        code_verifier=verifier,
    )
    assert token_resp.status_code == 200
    assert token_resp.json()["access_token"]
