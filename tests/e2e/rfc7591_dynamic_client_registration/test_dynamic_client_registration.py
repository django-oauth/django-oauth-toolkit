"""
RFC 7591 — OAuth 2.0 Dynamic Client Registration, and
RFC 7592 — Dynamic Client Registration Management.

The demo IdP enables DCR with ``AllowAllDCRPermission`` so the endpoints can be
exercised without prior credentials.
"""

import pytest
import requests

from tests.e2e import constants as c
from tests.e2e.helpers.jwt_tools import decode_header, validate_id_token


def _register(oauth, metadata):
    return requests.post(oauth.url("/o/register/"), json=metadata, timeout=10)


def _register_ok(oauth, metadata):
    """Register a client and return its JSON, asserting a 201 first."""
    resp = _register(oauth, metadata)
    assert resp.status_code == 201, f"DCR failed ({resp.status_code}): {resp.text}"
    return resp.json()


@pytest.mark.compliance("RFC 7591", "3.2.1", "Client Information Response")
def test_register_confidential_client(oauth):
    resp = _register(
        oauth,
        {
            "client_name": "Dynamically Registered Client",
            "redirect_uris": [c.REDIRECT_URI],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "client_secret_basic",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["client_id"]
    assert body["client_secret"]
    assert body["registration_access_token"]
    assert body["registration_client_uri"]
    assert c.REDIRECT_URI in body["redirect_uris"]


@pytest.mark.compliance("RFC 7591", "3.2.2", "Client Registration Error Response")
def test_register_authorization_code_without_redirect_uri_is_rejected(oauth):
    resp = _register(
        oauth,
        {
            "client_name": "Missing Redirect",
            "redirect_uris": [],
            "grant_types": ["authorization_code"],
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client_metadata"


@pytest.mark.compliance("RFC 7592", "2.1", "Client Read Request")
def test_registered_client_can_be_read_back(oauth):
    created = _register_ok(
        oauth,
        {
            "client_name": "Readable Client",
            "redirect_uris": [c.REDIRECT_URI],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "client_secret_basic",
        },
    )

    read = requests.get(
        created["registration_client_uri"],
        headers={"Authorization": f"Bearer {created['registration_access_token']}"},
        timeout=10,
    )
    assert read.status_code == 200
    assert read.json()["client_id"] == created["client_id"]


@pytest.mark.compliance("RFC 7591", "3.1", "Registered client is usable")
def test_registered_client_can_complete_authorization_code_flow(oauth, user_session):
    created = _register_ok(
        oauth,
        {
            "client_name": "Usable Client",
            "redirect_uris": [c.REDIRECT_URI],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "client_secret_basic",
        },
    )

    # A plain OAuth 2.0 scope; the OpenID Connect path is covered below.
    result = oauth.authorize(
        user_session,
        client_id=created["client_id"],
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="read",
        state="s",
    )
    code = result.query_params["code"]
    token_resp = oauth.exchange_code(
        client_id=created["client_id"],
        code=code,
        redirect_uri=c.REDIRECT_URI,
        client_secret=created["client_secret"],
    )
    assert token_resp.status_code == 200
    assert token_resp.json()["access_token"]


@pytest.mark.compliance("RFC 7591", "3.1", "Registered client is provisioned to receive ID Tokens")
def test_registered_public_client_receives_id_token(oauth, user_session, issuer):
    """OpenID Connect for a dynamically registered client (#1853).

    Nothing is said about ``id_token_signed_response_alg``, so the OpenID
    Connect Dynamic Client Registration 1.0 default of RS256 applies: the
    response reports it and an ``openid`` code flow mints an ID Token
    verifiable against the IdP's JWKS.
    """
    created = _register_ok(
        oauth,
        {
            "client_name": "OpenID Client",
            "redirect_uris": [c.REDIRECT_URI],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "none",
        },
    )
    assert created["id_token_signed_response_alg"] == "RS256"

    result = oauth.authorize(
        user_session,
        client_id=created["client_id"],
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
        nonce="n-dcr",
    )
    token_resp = oauth.exchange_code(
        client_id=created["client_id"], code=result.query_params["code"], redirect_uri=c.REDIRECT_URI
    )
    assert token_resp.status_code == 200, token_resp.text
    id_token = token_resp.json()["id_token"]
    assert decode_header(id_token)["alg"] == "RS256"
    claims = validate_id_token(id_token, issuer=issuer, audience=created["client_id"])
    assert claims["nonce"] == "n-dcr"
