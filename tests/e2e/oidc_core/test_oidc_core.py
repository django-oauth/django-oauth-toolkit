"""
OpenID Connect Core 1.0 — Hybrid Flow, UserInfo, and scope-gated claims.

(The Authorization Code Flow's ID Token issuance/validation is covered in
``rfc6749_authorization_code``; this module focuses on the OIDC-specific
behaviours.)
"""

import pytest

from tests.e2e import constants as c
from tests.e2e.helpers.jwt_tools import validate_id_token
from tests.e2e.helpers.oauth_client import token_data


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


@pytest.mark.compliance("OpenID Connect Core 1.0", "3.1.2.1", "prompt=none with an authenticated End-User")
def test_prompt_none_returns_code_for_an_authenticated_end_user(oauth, user_session):
    """An authenticated ``prompt=none`` request is answered without any UI.

    The unauthenticated half of this contract (``error=login_required``) is
    covered by the unit suite; this pins the *successful* half, which is what
    the browser layer's cross-site probe measures. Keeping it here, over plain
    HTTP with no browser involved, means a failure there can be attributed to
    cookie policy rather than to the authorization server.
    """
    result = oauth.authorize(
        user_session,
        client_id=c.PUBLIC_PKCE_CLIENT_ID,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
        state="silent-state",
        code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        code_challenge_method="S256",
        extra={"prompt": "none"},
    )
    assert result.status_code == 302
    assert result.query_params["code"], "an authenticated prompt=none request MUST return a code"
    assert result.query_params["state"] == "silent-state"
    assert "error" not in result.query_params


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
    access_token = token_data(
        oauth.exchange_code(
            client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
            code=code,
            redirect_uri=c.REDIRECT_URI,
            client_secret=c.CONFIDENTIAL_CODE_SECRET,
        )
    )["access_token"]

    resp = oauth.userinfo(access_token)
    assert resp.status_code == 200
    body = resp.json()
    assert body["sub"]
    assert body["email"] == c.E2E_EMAIL
    assert body["given_name"] == c.E2E_GIVEN_NAME


@pytest.mark.compliance("OpenID Connect Core 1.0", "5.3", "UserInfo CORS support")
def test_userinfo_supports_cors_for_javascript_clients(oauth, user_session):
    origin = "http://localhost:5173"

    # A UserInfo request carries an Authorization header, which is not CORS-safelisted,
    # so the browser preflights it before sending the real request. The demo IdP also
    # installs django-cors-headers (for the device flow), whose middleware answers every
    # preflight before any view runs, so all this can assert end-to-end is that the
    # preflight is allowed; the toolkit's own OPTIONS handler is covered by the unit
    # tests in tests/test_oidc_views.py.
    preflight = oauth.userinfo_preflight(origin=origin)
    assert preflight.status_code == 200
    assert preflight.headers["Access-Control-Allow-Origin"] in ("*", origin)

    result = oauth.authorize(
        user_session,
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
        state="s",
    )
    access_token = token_data(
        oauth.exchange_code(
            client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
            code=result.query_params["code"],
            redirect_uri=c.REDIRECT_URI,
            client_secret=c.CONFIDENTIAL_CODE_SECRET,
        )
    )["access_token"]

    # The wildcard on the actual response comes from the toolkit, not the middleware:
    # nothing enables django-cors-headers for a UserInfo GET in the demo IdP.
    resp = oauth.userinfo(access_token, origin=origin)
    assert resp.status_code == 200
    assert resp.headers["Access-Control-Allow-Origin"] == "*"
    # A wildcard origin must never be paired with credentialed requests.
    assert "Access-Control-Allow-Credentials" not in resp.headers


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
    access_token = token_data(
        oauth.exchange_code(
            client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
            code=code,
            redirect_uri=c.REDIRECT_URI,
            client_secret=c.CONFIDENTIAL_CODE_SECRET,
        )
    )["access_token"]

    body = oauth.userinfo(access_token).json()
    assert body["sub"]
    assert "email" not in body
    assert "given_name" not in body
