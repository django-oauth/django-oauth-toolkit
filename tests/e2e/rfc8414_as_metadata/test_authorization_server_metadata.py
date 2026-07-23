"""RFC 8414 — OAuth 2.0 Authorization Server Metadata."""

import pytest
import requests

from tests.e2e import constants as c


@pytest.fixture(scope="module")
def metadata(oauth):
    resp = oauth.oauth_metadata()
    assert resp.status_code == 200
    return resp.json()


@pytest.mark.compliance("RFC 8414", "3", "Well-Known URI (strict, issuer with path)")
def test_metadata_served_at_strict_well_known_location(oauth, issuer):
    # For an issuer with a path component (".../o"), RFC 8414 places the document
    # at /.well-known/oauth-authorization-server/o, with the issuer reflected back.
    resp = requests.get(oauth.url("/.well-known/oauth-authorization-server/o"), timeout=5)
    assert resp.status_code == 200
    assert resp.json()["issuer"] == issuer


@pytest.mark.compliance("RFC 8414", "2", "Required metadata fields")
def test_metadata_advertises_core_endpoints(metadata, issuer):
    assert metadata["issuer"] == issuer
    assert metadata["authorization_endpoint"].endswith("/o/authorize/")
    assert metadata["token_endpoint"].endswith("/o/token/")
    assert metadata["revocation_endpoint"].endswith("/o/revoke_token/")
    assert metadata["introspection_endpoint"].endswith("/o/introspect/")


@pytest.mark.compliance("RFC 8414", "2", "grant_types_supported")
def test_metadata_advertises_supported_grant_types(metadata):
    grant_types = set(metadata["grant_types_supported"])
    assert {
        "authorization_code",
        "client_credentials",
        "password",
        "refresh_token",
    } <= grant_types


@pytest.mark.compliance("RFC 8414", "2", "response_types / PKCE / auth methods")
def test_metadata_advertises_response_types_and_pkce(metadata):
    assert "code" in metadata["response_types_supported"]
    assert "S256" in metadata["code_challenge_methods_supported"]
    assert {"client_secret_basic", "client_secret_post"} <= set(
        metadata["token_endpoint_auth_methods_supported"]
    )


@pytest.mark.compliance("RFC 8414", "2", "scopes_supported")
def test_metadata_advertises_configured_scopes(metadata):
    assert set(c.E2E_SCOPES) <= set(metadata["scopes_supported"])


@pytest.mark.compliance("RFC 8414", "2", "registration_endpoint")
def test_metadata_advertises_registration_endpoint(metadata):
    # The demo IdP runs with DCR enabled, so the RFC 7591 registration
    # endpoint must be discoverable from the metadata document.
    assert metadata["registration_endpoint"].endswith("/o/register/")
