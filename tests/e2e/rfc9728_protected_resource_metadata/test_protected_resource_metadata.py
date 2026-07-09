"""RFC 9728 — OAuth 2.0 Protected Resource Metadata."""

import pytest

from tests.e2e import constants as c
from tests.e2e.helpers.oauth_client import token_data


@pytest.fixture(scope="module")
def metadata(oauth):
    """The protected-resource metadata document served at the domain root."""
    resp = oauth.resource_metadata()
    assert resp.status_code == 200
    return resp.json()


@pytest.mark.compliance("RFC 9728", "3", "Well-Known URI + JSON media type")
def test_metadata_served_as_json_at_well_known_location(oauth):
    resp = oauth.resource_metadata()
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("application/json")


@pytest.mark.compliance("RFC 9728", "3.1", "Access-Control-Allow-Origin")
def test_metadata_sets_cors_header(oauth):
    resp = oauth.resource_metadata()
    assert resp.headers.get("Access-Control-Allow-Origin") == "*"


@pytest.mark.compliance("RFC 9728", "2", "resource (required)")
def test_metadata_advertises_resource_identifier(metadata, oauth):
    # Served at the domain root, so the resource identifier is the origin.
    assert metadata["resource"] == oauth.base_url


@pytest.mark.compliance("RFC 9728", "2", "authorization_servers")
def test_metadata_advertises_authorization_server(metadata, issuer):
    assert issuer in metadata["authorization_servers"]


@pytest.mark.compliance("RFC 9728", "2", "scopes_supported")
def test_metadata_advertises_configured_scopes(metadata):
    assert set(c.E2E_SCOPES) <= set(metadata["scopes_supported"])


@pytest.mark.compliance("RFC 9728", "2", "bearer_methods_supported")
def test_metadata_advertises_bearer_methods(metadata):
    assert metadata["bearer_methods_supported"] == ["header"]


@pytest.mark.compliance("RFC 9728", "3.1", "Path-component form (resource with a path)")
def test_metadata_path_component_form(oauth, issuer):
    # /.well-known/oauth-protected-resource/o reflects the path back into the
    # resource identifier, yielding "<origin>/o" (== the issuer here).
    resp = oauth.resource_metadata("o")
    assert resp.status_code == 200
    assert resp.json()["resource"] == issuer


@pytest.mark.compliance("RFC 9728", "5.1", "WWW-Authenticate resource_metadata on 401")
def test_protected_resource_advertises_metadata_on_401(oauth):
    resp = oauth.protected_resource()
    assert resp.status_code == 401
    challenge = resp.headers["WWW-Authenticate"]
    assert challenge.startswith("Bearer")
    assert "resource_metadata=" in challenge
    assert "/.well-known/oauth-protected-resource" in challenge


@pytest.mark.compliance("RFC 9728", "5.1", "Protected resource accepts a valid access token")
def test_protected_resource_allows_valid_token(oauth):
    tokens = token_data(
        oauth.client_credentials(
            client_id=c.CLIENT_CREDENTIALS_CLIENT_ID,
            client_secret=c.CLIENT_CREDENTIALS_SECRET,
        )
    )
    resp = oauth.protected_resource(access_token=tokens["access_token"])
    assert resp.status_code == 200
    assert resp.json() == {"protected": True}
