"""RFC 7523 §2.1 — JWT Bearer Authorization Grant.

Drives the live IdP's token endpoint with a JWT assertion signed by an external
client, verifying the assertion grant end to end against the ``e2e-jwt-bearer``
seeded application. The assertion is built with jwcrypto directly (rather than
importing DOT) so the test acts as a genuine third-party client with no access
to the server's Django configuration.
"""

import time
import uuid

import pytest
from jwcrypto import jwk, jwt

from tests.e2e import constants as c


GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"


@pytest.fixture(scope="module")
def signing_key():
    return jwk.JWK(**c.JWT_BEARER_PRIVATE_JWK)


@pytest.fixture
def make_assertion(oauth, signing_key):
    def _make(**overrides):
        now = int(time.time())
        claims = {
            "iss": c.JWT_BEARER_CLIENT_ID,
            "sub": c.JWT_BEARER_SUBJECT,
            "aud": oauth.url("/o/token/"),
            "iat": now,
            "exp": now + 300,
            "jti": uuid.uuid4().hex,
        }
        claims.update(overrides)
        token = jwt.JWT(
            header={"alg": "RS256", "kid": c.JWT_BEARER_PRIVATE_JWK["kid"]},
            claims=claims,
        )
        token.make_signed_token(signing_key)
        return token.serialize()

    return _make


@pytest.mark.compliance("RFC 7523", "2.1", "JWT Bearer Access Token Response")
def test_jwt_bearer_assertion_issues_access_token(oauth, make_assertion):
    resp = oauth.token(
        {
            "grant_type": GRANT_TYPE,
            "assertion": make_assertion(),
            "client_id": c.JWT_BEARER_CLIENT_ID,
            "scope": "read",
        }
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"].lower() == "bearer"
    assert body["access_token"]
    assert body["scope"] == "read"
    # RFC 7523 §3: no refresh token by default for the assertion grant.
    assert "refresh_token" not in body


@pytest.mark.compliance("RFC 7523", "3", "Audience validation")
def test_jwt_bearer_wrong_audience_rejected(oauth, make_assertion):
    resp = oauth.token(
        {
            "grant_type": GRANT_TYPE,
            "assertion": make_assertion(aud="https://not-this-server.example.com/"),
            "client_id": c.JWT_BEARER_CLIENT_ID,
        }
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_grant"


@pytest.mark.compliance("RFC 7523", "3", "Untrusted issuer rejected")
def test_jwt_bearer_untrusted_issuer_rejected(oauth, make_assertion):
    resp = oauth.token(
        {
            "grant_type": GRANT_TYPE,
            "assertion": make_assertion(iss="https://stranger.example.com"),
            "client_id": c.JWT_BEARER_CLIENT_ID,
        }
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_grant"


@pytest.mark.compliance("RFC 8414", "2", "grant_types_supported advertises jwt-bearer")
def test_metadata_advertises_jwt_bearer_grant(oauth):
    metadata = oauth.oauth_metadata().json()
    assert GRANT_TYPE in metadata["grant_types_supported"]
