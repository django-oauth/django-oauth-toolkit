"""OpenID Connect Discovery 1.0 — provider configuration and JWKS."""

import pytest

from tests.e2e.helpers.jwt_tools import decode_header


@pytest.fixture(scope="module")
def config(oauth):
    resp = oauth.discovery()
    assert resp.status_code == 200
    return resp.json()


@pytest.mark.compliance("OpenID Connect Discovery 1.0", "3", "Provider Metadata")
def test_discovery_advertises_required_endpoints(config, issuer):
    assert config["issuer"] == issuer
    assert config["authorization_endpoint"].endswith("/o/authorize/")
    assert config["token_endpoint"].endswith("/o/token/")
    assert config["userinfo_endpoint"].endswith("/o/userinfo/")
    assert config["jwks_uri"].endswith("/o/.well-known/jwks.json")


@pytest.mark.compliance("OpenID Connect Discovery 1.0", "3", "Supported values")
def test_discovery_advertises_supported_values(config):
    assert config["subject_types_supported"] == ["public"]
    assert "RS256" in config["id_token_signing_alg_values_supported"]
    assert "openid" in config["scopes_supported"]
    assert "code" in config["response_types_supported"]
    assert "S256" in config["code_challenge_methods_supported"]
    assert config["end_session_endpoint"].endswith("/o/logout/")
    assert "sub" in config["claims_supported"]


@pytest.mark.compliance("OpenID Connect Discovery 1.0", "3", "JWKS document")
def test_jwks_publishes_signing_key(oauth):
    resp = oauth.jwks()
    assert resp.status_code == 200
    keys = resp.json()["keys"]
    assert keys, "JWKS MUST publish at least one key"
    rsa_sig_keys = [k for k in keys if k["kty"] == "RSA" and k.get("use") in (None, "sig")]
    assert rsa_sig_keys
    assert all("kid" in k for k in rsa_sig_keys)


@pytest.mark.compliance("OpenID Connect Core 1.0", "10.1", "Signing key rotation / kid match")
def test_id_token_kid_is_present_in_jwks(oauth, user_session):
    from tests.e2e import constants as c

    result = oauth.authorize(
        user_session,
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
        state="s",
    )
    code = result.query_params["code"]
    id_token = oauth.exchange_code(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        code=code,
        redirect_uri=c.REDIRECT_URI,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
    ).json()["id_token"]

    kid = decode_header(id_token)["kid"]
    jwks_kids = {k["kid"] for k in oauth.jwks().json()["keys"]}
    assert kid in jwks_kids
