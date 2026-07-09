"""
RFC 7636 — Proof Key for Code Exchange (PKCE).

The ``e2e-public-pkce`` client is registered in ``PKCE_REQUIRED_CLIENT_IDS`` so
the IdP enforces PKCE for it, letting us prove both the S256/plain round trips
and the required-challenge / verifier-mismatch protections.
"""

import base64
import hashlib

import pytest

from tests.e2e import constants as c
from tests.e2e.helpers.oauth_client import generate_pkce_pair


def _plain_pair():
    verifier = "plain-verifier-0123456789-0123456789-0123456789"
    return verifier, verifier


@pytest.mark.compliance("RFC 7636", "4.2", "code_challenge (S256)")
@pytest.mark.compliance("RFC 7636", "4.5", "code_verifier")
def test_pkce_s256_round_trip(oauth, user_session):
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


@pytest.mark.compliance("RFC 7636", "4.2", "code_challenge (plain)")
def test_pkce_plain_round_trip(oauth, user_session):
    verifier, challenge = _plain_pair()
    result = oauth.authorize(
        user_session,
        client_id=c.PUBLIC_PKCE_CLIENT_ID,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
        state="s",
        code_challenge=challenge,
        code_challenge_method="plain",
    )
    code = result.query_params["code"]
    token_resp = oauth.exchange_code(
        client_id=c.PUBLIC_PKCE_CLIENT_ID,
        code=code,
        redirect_uri=c.REDIRECT_URI,
        code_verifier=verifier,
    )
    assert token_resp.status_code == 200


@pytest.mark.compliance("RFC 7636", "4.6", "Server verifies code_verifier")
def test_pkce_verifier_mismatch_is_rejected(oauth, user_session):
    _, challenge = generate_pkce_pair()
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
    # A verifier that does not hash to the challenge MUST be rejected.
    wrong_verifier = base64.urlsafe_b64encode(hashlib.sha256(b"wrong").digest()).rstrip(b"=").decode()
    token_resp = oauth.exchange_code(
        client_id=c.PUBLIC_PKCE_CLIENT_ID,
        code=code,
        redirect_uri=c.REDIRECT_URI,
        code_verifier=wrong_verifier,
    )
    assert token_resp.status_code == 400
    assert token_resp.json()["error"] == "invalid_grant"


@pytest.mark.compliance("RFC 7636", "4.4.1", "Missing code_verifier rejected")
def test_pkce_missing_verifier_is_rejected(oauth, user_session):
    _, challenge = generate_pkce_pair()
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
        # no code_verifier
    )
    assert token_resp.status_code == 400
    # A missing verifier is rejected as either invalid_request (missing
    # parameter) or invalid_grant depending on the server's check order.
    assert token_resp.json()["error"] in ("invalid_grant", "invalid_request")


@pytest.mark.compliance("RFC 7636", "4.4.1", "PKCE required client rejects missing challenge")
def test_pkce_required_client_rejects_missing_challenge(oauth, user_session):
    # No code_challenge supplied to a client PKCE is enforced for.
    result = oauth.authorize(
        user_session,
        client_id=c.PUBLIC_PKCE_CLIENT_ID,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
        state="s",
    )
    assert result.status_code in (400, 302)
    if result.status_code == 302:
        assert result.params.get("error") == "invalid_request"
    else:
        assert "error" in result.response.text.lower()
