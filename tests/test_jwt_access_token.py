"""
Tests for RFC 9068 - JWT Profile for OAuth 2.0 Access Tokens ("at+jwt").

These exercise the per-application ``jwt_access_token`` opt-in: when enabled, the
authorization server issues a signed JWT access token (instead of an opaque random
token) carrying the RFC 9068 claim set, signed with the application's algorithm.
"""

import json

import pytest
from django.core.exceptions import ValidationError
from django.urls import reverse
from jwcrypto import jws, jwt

from oauth2_provider.models import get_access_token_model, get_application_model

from . import presets
from .conftest import CLEARTEXT_SECRET


Application = get_application_model()
AccessToken = get_access_token_model()

pytestmark = pytest.mark.django_db


def decode_header(token):
    """Return the (unverified) JOSE header of a compact JWS/JWT."""
    unverified = jws.JWS()
    unverified.deserialize(token)
    return unverified.jose_header


def verify_and_get_claims(token, key):
    """Verify the token signature with ``key`` and return its claims dict."""
    verified = jwt.JWT(key=key, jwt=token)
    return json.loads(verified.claims)


def authorization_code_token(client, application, user, scope, redirect_uri="http://example.org"):
    client.force_login(user)
    auth_rsp = client.post(
        reverse("oauth2_provider:authorize"),
        data={
            "client_id": application.client_id,
            "state": "random_state_string",
            "scope": scope,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "allow": True,
        },
    )
    assert auth_rsp.status_code == 302
    from urllib.parse import parse_qs, urlparse

    code = parse_qs(urlparse(auth_rsp["Location"]).query)["code"]
    client.logout()
    token_rsp = client.post(
        reverse("oauth2_provider:token"),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": application.client_id,
            "client_secret": CLEARTEXT_SECRET,
            "scope": scope,
        },
    )
    assert token_rsp.status_code == 200, token_rsp.content
    return token_rsp.json()


def client_credentials_token(client, application, scope=None, resource=None):
    data = {
        "grant_type": "client_credentials",
        "client_id": application.client_id,
        "client_secret": CLEARTEXT_SECRET,
    }
    if scope is not None:
        data["scope"] = scope
    if resource is not None:
        data["resource"] = resource
    token_rsp = client.post(reverse("oauth2_provider:token"), data=data)
    assert token_rsp.status_code == 200, token_rsp.content
    return token_rsp.json()


@pytest.fixture
def cc_application():
    """A confidential client-credentials application, RS256 signed."""
    return Application.objects.create(
        name="JWT CC Application",
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
        algorithm=Application.RS256_ALGORITHM,
        client_secret=CLEARTEXT_SECRET,
        jwt_access_token=True,
    )


@pytest.fixture
def hs256_cc_application():
    """A confidential client-credentials application, HS256 signed (unhashed secret)."""
    return Application.objects.create(
        name="JWT CC HS256 Application",
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
        algorithm=Application.HS256_ALGORITHM,
        client_secret=CLEARTEXT_SECRET,
        hash_client_secret=False,
        jwt_access_token=True,
    )


def test_authorization_code_issues_at_jwt(oauth2_settings, application, test_user, oidc_key, client):
    """An opted-in RS256 app issues an at+jwt with the full RFC 9068 claim set."""
    oauth2_settings.update(presets.OIDC_SETTINGS_RW)
    application.jwt_access_token = True
    application.save()

    token_data = authorization_code_token(client, application, test_user, scope="read write")
    access_token = token_data["access_token"]

    # RFC 9068 §2.1 header.
    header = decode_header(access_token)
    assert header["typ"] == "at+jwt"
    assert header["alg"] == "RS256"
    assert "kid" in header

    # RFC 9068 §2.2 required claims.
    claims = verify_and_get_claims(access_token, oidc_key)
    assert claims["iss"] == "http://localhost/o"
    assert claims["sub"] == str(test_user.pk)
    assert claims["client_id"] == application.client_id
    assert claims["aud"] == application.client_id  # no resource -> default (§3)
    assert isinstance(claims["exp"], int)
    assert isinstance(claims["iat"], int)
    assert claims["jti"]
    assert claims["scope"] == "read write"


def test_client_credentials_sub_is_client_id(oauth2_settings, cc_application, oidc_key, client):
    """RFC 9068 §2.2/§5: with no resource owner, sub identifies the client."""
    oauth2_settings.update(presets.OIDC_SETTINGS_RW)
    token_data = client_credentials_token(client, cc_application, scope="read")
    claims = verify_and_get_claims(token_data["access_token"], oidc_key)
    assert claims["sub"] == cc_application.client_id
    assert claims["client_id"] == cc_application.client_id


def test_aud_uses_rfc8707_resource(oauth2_settings, cc_application, oidc_key, client):
    """RFC 9068 §3: aud echoes the RFC 8707 resource parameter when present."""
    oauth2_settings.update(presets.OIDC_SETTINGS_RW)
    resource = "https://api.example.org"
    token_data = client_credentials_token(client, cc_application, scope="read", resource=resource)
    claims = verify_and_get_claims(token_data["access_token"], oidc_key)
    assert resource in claims["aud"]


def test_hs256_at_jwt(oauth2_settings, hs256_cc_application, client):
    """HS256 apps sign the at+jwt with the client secret and omit kid."""
    oauth2_settings.update(presets.OIDC_SETTINGS_RW)
    token_data = client_credentials_token(client, hs256_cc_application, scope="read")
    access_token = token_data["access_token"]

    header = decode_header(access_token)
    assert header["typ"] == "at+jwt"
    assert header["alg"] == "HS256"
    assert "kid" not in header

    claims = verify_and_get_claims(access_token, hs256_cc_application.jwk_key)
    assert claims["sub"] == hs256_cc_application.client_id


def test_issued_jwt_is_persisted_for_introspection_and_revocation(oauth2_settings, cc_application, client):
    """The JWT is stored as a normal AccessToken so checksum lookup keeps working."""
    oauth2_settings.update(presets.OIDC_SETTINGS_RW)
    token_data = client_credentials_token(client, cc_application, scope="read")
    access_token = token_data["access_token"]
    # validate_bearer_token / introspection locate the token by its checksum.
    import hashlib

    checksum = hashlib.sha256(access_token.encode("utf-8")).hexdigest()
    stored = AccessToken.objects.get(token_checksum=checksum)
    assert stored.is_valid()


def test_opt_out_application_still_gets_opaque_token(oauth2_settings, application, test_user, client):
    """Applications without the flag keep receiving opaque (non-JWT) tokens."""
    oauth2_settings.update(presets.OIDC_SETTINGS_RW)
    assert application.jwt_access_token is False

    token_data = authorization_code_token(client, application, test_user, scope="read write")
    access_token = token_data["access_token"]
    # An opaque token is not a three-segment signed JWT.
    assert access_token.count(".") != 2
    with pytest.raises(Exception):
        decode_header(access_token)


def test_clean_rejects_jwt_without_signing_algorithm():
    """clean() forbids enabling JWT access tokens without a signing algorithm."""
    app = Application(
        name="No algorithm",
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
        algorithm=Application.NO_ALGORITHM,
        client_secret=CLEARTEXT_SECRET,
        jwt_access_token=True,
    )
    with pytest.raises(ValidationError):
        app.clean()
