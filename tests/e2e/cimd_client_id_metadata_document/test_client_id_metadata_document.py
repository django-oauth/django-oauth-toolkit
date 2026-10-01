"""
OAuth Client ID Metadata Documents
(draft-ietf-oauth-client-id-metadata-document-01).

A client presents an ``https`` URL as its ``client_id``; the authorization
server fetches the metadata document from that URL, validates it, and treats
the result as a public client registration. The package conftest launches a
CIMD-enabled IdP whose (test-only) loopback fetcher retrieves documents from
a local server, so every check here exercises the real authorize/token
endpoints over HTTP.
"""

import pytest

from tests.e2e import constants as c
from tests.e2e.helpers.jwt_tools import decode_header, validate_id_token
from tests.e2e.helpers.oauth_client import token_data


SPEC = "OAuth Client ID Metadata Document"


@pytest.mark.compliance(SPEC, "5", "client_id_metadata_document_supported is advertised when enabled")
def test_as_metadata_advertises_cimd_support(cimd_oauth):
    for response in (cimd_oauth.oauth_metadata(), cimd_oauth.discovery()):
        assert response.status_code == 200
        assert response.json()["client_id_metadata_document_supported"] is True


@pytest.mark.compliance(SPEC, "5", "client_id_metadata_document_supported is false when disabled")
def test_disabled_idp_does_not_advertise_or_resolve(oauth, doc_server):
    """The shared IdP runs without CIMD_ENABLED: no advertisement, no fetch."""
    assert oauth.oauth_metadata().json()["client_id_metadata_document_supported"] is False

    client_id = doc_server.add_client("/clients/disabled-idp.json")
    session = oauth.login(c.E2E_USERNAME, c.E2E_PASSWORD)
    result = oauth.authorize(
        session, client_id=client_id, response_type="code", redirect_uri=c.REDIRECT_URI, scope="read"
    )
    assert result.status_code == 400
    assert doc_server.hits("/clients/disabled-idp.json") == 0


@pytest.mark.compliance(SPEC, "4", "A URL client_id is resolved via its metadata document")
def test_url_client_id_completes_authorization_code_flow(cimd_oauth, cimd_user_session, doc_server):
    client_id = doc_server.add_client("/clients/happy-path.json")

    result = cimd_oauth.authorize(
        cimd_user_session,
        client_id=client_id,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="read",
        state="s",
    )
    assert result.query_params["state"] == "s"
    token = token_data(
        cimd_oauth.exchange_code(
            client_id=client_id, code=result.query_params["code"], redirect_uri=c.REDIRECT_URI
        )
    )
    assert token["access_token"]
    assert token["token_type"].lower() == "bearer"


@pytest.mark.compliance(SPEC, "4.1", "A URL client_id is provisioned to receive RS256-signed ID Tokens")
def test_url_client_id_receives_signed_id_token(cimd_oauth, cimd_idp, cimd_user_session, doc_server):
    """OpenID Connect for a CIMD client (#1853).

    The document says nothing about ``id_token_signed_response_alg``, so the
    OpenID Connect Dynamic Client Registration 1.0 default of RS256 applies and
    an ``openid`` code flow mints an ID Token verifiable against the IdP's JWKS.
    """
    client_id = doc_server.add_client("/clients/openid.json")

    result = cimd_oauth.authorize(
        cimd_user_session,
        client_id=client_id,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
        nonce="n-cimd",
    )
    token = token_data(
        cimd_oauth.exchange_code(
            client_id=client_id, code=result.query_params["code"], redirect_uri=c.REDIRECT_URI
        )
    )
    assert decode_header(token["id_token"])["alg"] == "RS256"
    claims = validate_id_token(token["id_token"], issuer=cimd_idp.issuer, audience=client_id)
    assert claims["nonce"] == "n-cimd"


@pytest.mark.compliance(
    SPEC, "4.1", "A document requesting an unsupported id_token_signed_response_alg is rejected"
)
def test_document_with_unsupported_id_token_alg_is_rejected(cimd_oauth, cimd_user_session, doc_server):
    """HS256 signs with a client secret, which a CIMD client must not have."""
    client_id = doc_server.add_client("/clients/hs256.json", id_token_signed_response_alg="HS256")
    result = cimd_oauth.authorize(
        cimd_user_session,
        client_id=client_id,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="read",
    )
    assert result.status_code == 400


@pytest.mark.compliance(SPEC, "4.4", "The stored registration serves subsequent requests until it expires")
def test_stored_application_serves_refresh_without_refetch(cimd_oauth, cimd_user_session, doc_server):
    path = "/clients/caching.json"
    client_id = doc_server.add_client(path)

    result = cimd_oauth.authorize(
        cimd_user_session,
        client_id=client_id,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="read",
    )
    token = token_data(
        cimd_oauth.exchange_code(
            client_id=client_id, code=result.query_params["code"], redirect_uri=c.REDIRECT_URI
        )
    )
    refreshed = token_data(cimd_oauth.refresh(client_id=client_id, refresh_token=token["refresh_token"]))
    assert refreshed["access_token"] != token["access_token"]
    # One fetch resolved the client; the token and refresh exchanges must be
    # served from the stored application, not re-fetch the document.
    assert doc_server.hits(path) == 1


@pytest.mark.compliance(SPEC, "4.1", "The document's client_id MUST match the URL it was fetched from")
def test_document_client_id_mismatch_is_rejected(cimd_oauth, cimd_user_session, doc_server):
    client_id = doc_server.add_client(
        "/clients/mismatch.json", client_id="https://attacker.example/other-client.json"
    )
    result = cimd_oauth.authorize(
        cimd_user_session,
        client_id=client_id,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="read",
    )
    assert result.status_code == 400


@pytest.mark.compliance(SPEC, "6.2", "CIMD clients are public: a client_secret in the document is rejected")
def test_document_with_client_secret_is_rejected(cimd_oauth, cimd_user_session, doc_server):
    client_id = doc_server.add_client("/clients/with-secret.json", client_secret="s3cret")
    result = cimd_oauth.authorize(
        cimd_user_session,
        client_id=client_id,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="read",
    )
    assert result.status_code == 400
