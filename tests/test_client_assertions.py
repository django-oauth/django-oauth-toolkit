"""
Tests for RFC 7523 JWT client authentication (oauth2_provider.client_assertions).

Module-level tests use lightweight fake oauthlib requests and unsaved
Application instances; endpoint integration tests (token / introspection /
revocation) live further down and use the DB-backed fixtures from conftest.
"""

import json
import time

import pytest
from django.core.cache import cache
from jwcrypto import jwk, jwt
from jwcrypto.common import base64url_encode

from oauth2_provider import client_assertions
from oauth2_provider.models import get_application_model

from . import presets


Application = get_application_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"
TOKEN_AUDIENCE = "http://testserver/o/token/"

RSA_KEY = jwk.JWK.generate(kty="RSA", size=2048, kid="unit-rsa")
EC_KEY = jwk.JWK.generate(kty="EC", crv="P-256", kid="unit-ec")
OTHER_KEY = jwk.JWK.generate(kty="RSA", size=2048, kid="unit-other")


@pytest.fixture(autouse=True)
def _clear_cache():
    """jti replay and JWKS caching state must never leak between tests."""
    cache.clear()
    yield
    cache.clear()


def build_assertion(key, claims, alg="RS256", kid=None, typ="JWT"):
    """Sign an arbitrary claim set — unlike make_client_assertion this allows
    broken/missing claims for negative tests."""
    header = {"alg": alg}
    if typ:
        header["typ"] = typ
    if kid:
        header["kid"] = kid
    token = jwt.JWT(header=header, claims=claims)
    token.make_signed_token(key)
    return token.serialize()


def default_claims(client_id="pkj-client", **overrides):
    now = int(time.time())
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": TOKEN_AUDIENCE,
        "exp": now + 60,
        "iat": now,
        "jti": f"jti-{time.monotonic_ns()}",
    }
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


class FakeRequest:
    """The subset of oauthlib.common.Request the module touches."""

    def __init__(
        self,
        assertion=None,
        assertion_type=client_assertions.JWT_BEARER_CLIENT_ASSERTION_TYPE,
        headers=None,
        uri="/o/token/",
        client_id=None,
        client_secret=None,
    ):
        self.headers = {"HTTP_HOST": "testserver"} if headers is None else headers
        self.uri = uri
        self.client = None
        self.client_id = client_id
        self.client_secret = client_secret
        if assertion is not None:
            self.client_assertion = assertion
        if assertion_type is not None:
            self.client_assertion_type = assertion_type


def pkj_app(client_jwks=None, client_jwks_uri="", client_id="pkj-client", **kwargs):
    if client_jwks is None and not client_jwks_uri:
        client_jwks = '{"keys": [%s, %s]}' % (RSA_KEY.export_public(), EC_KEY.export_public())
    defaults = {
        "client_id": client_id,
        "client_type": Application.CLIENT_CONFIDENTIAL,
        "authorization_grant_type": Application.GRANT_CLIENT_CREDENTIALS,
        "token_endpoint_auth_method": Application.TOKEN_AUTH_METHOD_PRIVATE_KEY_JWT,
        "client_jwks": client_jwks or "",
        "client_jwks_uri": client_jwks_uri,
    }
    defaults.update(kwargs)
    return Application(**defaults)


def csj_app(client_id="csj-client", **kwargs):
    defaults = {
        "client_id": client_id,
        "client_type": Application.CLIENT_CONFIDENTIAL,
        "authorization_grant_type": Application.GRANT_CLIENT_CREDENTIALS,
        "token_endpoint_auth_method": Application.TOKEN_AUTH_METHOD_CLIENT_SECRET_JWT,
        "client_secret": CLEARTEXT_SECRET,
        "hash_client_secret": False,
    }
    defaults.update(kwargs)
    return Application(**defaults)


def loader_for(app):
    def load_application(client_id, request):
        if app is not None and client_id == app.client_id:
            request.client = app
            return app
        return None

    return load_application


def authenticate(assertion, app, **request_kwargs):
    request = FakeRequest(assertion=assertion, **request_kwargs)
    result = client_assertions.authenticate_client_assertion(request, loader_for(app))
    return result, request


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def test_private_key_jwt_rs256_inline_jwks():
    app = pkj_app()
    assertion = build_assertion(RSA_KEY, default_claims(), alg="RS256", kid="unit-rsa")
    ok, request = authenticate(assertion, app)
    assert ok is True
    assert request.client is app
    assert request.client_id == "pkj-client"


def test_private_key_jwt_es256_kid_selection():
    app = pkj_app()
    assertion = build_assertion(EC_KEY, default_claims(), alg="ES256", kid="unit-ec")
    ok, _ = authenticate(assertion, app)
    assert ok is True


def test_private_key_jwt_without_kid_tries_all_keys():
    app = pkj_app()
    assertion = build_assertion(EC_KEY, default_claims(), alg="ES256")
    ok, _ = authenticate(assertion, app)
    assert ok is True


def test_client_secret_jwt_hs256():
    app = csj_app()
    assertion = client_assertions.make_client_assertion(
        "csj-client", CLEARTEXT_SECRET, TOKEN_AUDIENCE, alg="HS256"
    )
    ok, request = authenticate(assertion, app)
    assert ok is True
    assert request.client is app


def test_audience_may_be_a_list_and_issuer():
    app = pkj_app()
    claims = default_claims(aud=["https://other.example", TOKEN_AUDIENCE])
    assertion = build_assertion(RSA_KEY, claims, kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is True


def test_configured_accepted_audiences_take_precedence(oauth2_settings):
    oauth2_settings.CLIENT_ASSERTION_ACCEPTED_AUDIENCES = ["https://as.example.com/token"]
    app = pkj_app()
    good = build_assertion(RSA_KEY, default_claims(aud="https://as.example.com/token/"), kid="unit-rsa")
    ok, _ = authenticate(good, app)
    assert ok is True
    # The derived request-URL audience is no longer accepted once configured.
    bad = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
    ok, _ = authenticate(bad, app)
    assert ok is False


def test_client_id_parameter_matching_sub_is_accepted():
    app = pkj_app()
    assertion = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
    ok, _ = authenticate(assertion, app, client_id="pkj-client")
    assert ok is True


# ---------------------------------------------------------------------------
# Rejections: request shape
# ---------------------------------------------------------------------------


def test_wrong_assertion_type_rejected():
    app = pkj_app()
    assertion = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
    ok, _ = authenticate(assertion, app, assertion_type="urn:example:wrong")
    assert ok is False


def test_missing_assertion_rejected():
    ok, _ = authenticate(None, pkj_app())
    assert ok is False


def test_assertion_with_basic_auth_rejected():
    app = pkj_app()
    assertion = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
    ok, _ = authenticate(
        assertion,
        app,
        headers={"HTTP_HOST": "testserver", "HTTP_AUTHORIZATION": "Basic Zm9vOmJhcg=="},
    )
    assert ok is False


def test_assertion_with_client_secret_rejected():
    app = pkj_app()
    assertion = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
    ok, _ = authenticate(assertion, app, client_secret="topsecret")
    assert ok is False


def test_assertion_with_empty_client_secret_parameter_rejected():
    # RFC 6749 section 2.3 forbids a second auth mechanism by presence, not by
    # value: oauthlib maps client_secret= (empty) to "", absent to None.
    app = pkj_app()
    assertion = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
    ok, _ = authenticate(assertion, app, client_secret="")
    assert ok is False


def test_client_id_parameter_mismatch_rejected():
    app = pkj_app()
    assertion = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
    ok, _ = authenticate(assertion, app, client_id="someone-else")
    assert ok is False


def test_garbage_assertion_rejected():
    ok, _ = authenticate("not-a-jwt", pkj_app())
    assert ok is False


def test_alg_none_rejected():
    header = base64url_encode(json.dumps({"alg": "none"}))
    payload = base64url_encode(json.dumps(default_claims()))
    ok, _ = authenticate(f"{header}.{payload}.", pkj_app())
    assert ok is False


# ---------------------------------------------------------------------------
# Rejections: registration / algorithm binding
# ---------------------------------------------------------------------------


def test_unregistered_application_rejected():
    assertion = build_assertion(RSA_KEY, default_claims(client_id="unknown"), kid="unit-rsa")
    ok, _ = authenticate(assertion, None)
    assert ok is False


def test_blank_method_application_cannot_use_assertions():
    app = pkj_app(token_endpoint_auth_method="")
    assertion = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is False


def test_hs256_assertion_rejected_for_private_key_jwt_client():
    app = pkj_app()
    secret_key = jwk.JWK(kty="oct", k=base64url_encode(CLEARTEXT_SECRET))
    assertion = build_assertion(secret_key, default_claims(), alg="HS256")
    ok, _ = authenticate(assertion, app)
    assert ok is False


def test_rs256_assertion_rejected_for_client_secret_jwt_client():
    app = csj_app()
    assertion = build_assertion(RSA_KEY, default_claims(client_id="csj-client"), kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is False


def test_wrong_signing_key_rejected():
    app = pkj_app()
    assertion = build_assertion(OTHER_KEY, default_claims(), alg="RS256", kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is False


def test_unknown_kid_falls_back_to_all_registered_keys():
    # kid is a hint (RFC 7515 section 4.1.4): a mismatched label must not break
    # verification when the signature checks out against a registered key
    # (e.g. a thumbprint-derived kid vs. a human-named registered kid).
    app = pkj_app()
    assertion = build_assertion(RSA_KEY, default_claims(), kid="rotated-away")
    ok, _ = authenticate(assertion, app)
    assert ok is True


def test_unknown_kid_with_unregistered_key_rejected():
    app = pkj_app()
    assertion = build_assertion(OTHER_KEY, default_claims(), kid="rotated-away")
    ok, _ = authenticate(assertion, app)
    assert ok is False


def test_hashed_secret_client_secret_jwt_rejected():
    hashed = "pbkdf2_sha256$260000$x$y"  # identify_hasher() recognizes this shape
    app = csj_app(client_secret=hashed, hash_client_secret=True)
    key = jwk.JWK(kty="oct", k=base64url_encode(CLEARTEXT_SECRET))
    assertion = build_assertion(key, default_claims(client_id="csj-client"), alg="HS256")
    ok, _ = authenticate(assertion, app)
    assert ok is False


# ---------------------------------------------------------------------------
# Rejections: claims
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("missing", ["iss", "sub", "aud", "exp", "jti"])
def test_missing_required_claim_rejected(missing):
    app = pkj_app()
    claims = default_claims(**{missing: None})
    assertion = build_assertion(RSA_KEY, claims, kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is False


def test_iss_sub_mismatch_rejected():
    app = pkj_app()
    assertion = build_assertion(RSA_KEY, default_claims(iss="somebody-else"), kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is False


def test_expired_assertion_rejected():
    app = pkj_app()
    now = int(time.time())
    claims = default_claims(exp=now - 120, iat=now - 180)
    assertion = build_assertion(RSA_KEY, claims, kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is False


def test_unreasonably_long_lived_assertion_rejected():
    app = pkj_app()
    claims = default_claims(exp=int(time.time()) + 3600)
    assertion = build_assertion(RSA_KEY, claims, kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is False


def test_future_nbf_rejected():
    app = pkj_app()
    claims = default_claims(nbf=int(time.time()) + 300)
    assertion = build_assertion(RSA_KEY, claims, kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is False


def test_future_iat_rejected():
    app = pkj_app()
    claims = default_claims(iat=int(time.time()) + 300)
    assertion = build_assertion(RSA_KEY, claims, kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is False


def test_wrong_audience_rejected():
    app = pkj_app()
    claims = default_claims(aud="https://attacker.example/token")
    assertion = build_assertion(RSA_KEY, claims, kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is False


def test_jti_replay_rejected():
    app = pkj_app()
    assertion = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is True
    ok, _ = authenticate(assertion, app)
    assert ok is False


# ---------------------------------------------------------------------------
# Remote JWKS (jwks_uri)
# ---------------------------------------------------------------------------


def _jwks_document(*keys):
    return {"keys": [json.loads(key.export_public()) for key in keys]}


def test_jwks_uri_fetch_verifies(mocker):
    app = pkj_app(client_jwks_uri="https://client.example.com/jwks.json")
    fetch = mocker.patch.object(
        client_assertions.safe_fetch,
        "fetch_https_json",
        return_value=(_jwks_document(RSA_KEY), {}),
    )
    assertion = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is True
    assert fetch.call_count == 1


def test_jwks_uri_result_is_cached(mocker):
    app = pkj_app(client_jwks_uri="https://client.example.com/jwks.json")
    fetch = mocker.patch.object(
        client_assertions.safe_fetch,
        "fetch_https_json",
        return_value=(_jwks_document(RSA_KEY), {}),
    )
    for _ in range(2):
        assertion = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
        ok, _request = authenticate(assertion, app)
        assert ok is True
    assert fetch.call_count == 1


def test_unknown_kid_triggers_exactly_one_forced_refetch(mocker):
    app = pkj_app(client_jwks_uri="https://client.example.com/jwks.json")
    fetch = mocker.patch.object(
        client_assertions.safe_fetch,
        "fetch_https_json",
        return_value=(_jwks_document(EC_KEY), {}),
    )
    assertion = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is False
    assert fetch.call_count == 2


def test_unknown_kid_refetch_picks_up_rotated_key(mocker):
    app = pkj_app(client_jwks_uri="https://client.example.com/jwks.json")
    fetch = mocker.patch.object(
        client_assertions.safe_fetch,
        "fetch_https_json",
        side_effect=[(_jwks_document(EC_KEY), {}), (_jwks_document(EC_KEY, RSA_KEY), {})],
    )
    assertion = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is True
    assert fetch.call_count == 2


def test_fetch_failure_arms_backoff(mocker):
    app = pkj_app(client_jwks_uri="https://client.example.com/jwks.json")
    fetch = mocker.patch.object(
        client_assertions.safe_fetch,
        "fetch_https_json",
        side_effect=client_assertions.ClientAssertionError("boom"),
    )
    for _ in range(2):
        assertion = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
        ok, _request = authenticate(assertion, app)
        assert ok is False
    # The second attempt hit the backoff flag instead of refetching.
    assert fetch.call_count == 1


def test_remote_jwks_skips_private_and_unusable_keys():
    document = {
        "keys": [
            json.loads(RSA_KEY.export_private()),  # private material: never used
            {"kty": "garbage"},
            json.loads(EC_KEY.export_public()),
        ]
    }
    key_set = client_assertions._build_public_jwks(document)
    assert {key.get("kid") for key in key_set["keys"]} == {"unit-ec"}


def test_remote_jwks_without_usable_keys_fails():
    with pytest.raises(client_assertions.ClientAssertionError):
        client_assertions._build_public_jwks({"keys": []})
    with pytest.raises(client_assertions.ClientAssertionError):
        client_assertions._build_public_jwks({"no_keys": True})


# ---------------------------------------------------------------------------
# make_client_assertion (RP side)
# ---------------------------------------------------------------------------


def test_make_client_assertion_claims_and_header():
    assertion = client_assertions.make_client_assertion("rp-client", RSA_KEY, "https://as.example.com/token")
    token = jwt.JWT(algs=["RS256"])
    token.deserialize(assertion, RSA_KEY)
    claims = json.loads(token.claims)
    assert claims["iss"] == claims["sub"] == "rp-client"
    assert claims["aud"] == "https://as.example.com/token"
    assert claims["exp"] - claims["iat"] == 60
    assert claims["nbf"] == claims["iat"]
    assert len(claims["jti"]) >= 32
    header = json.loads(token.token.objects["protected"])
    assert header["alg"] == "RS256"
    assert header["kid"] == "unit-rsa"


def test_make_client_assertion_fresh_jti_per_call():
    first = client_assertions.make_client_assertion("rp", RSA_KEY, "aud")
    second = client_assertions.make_client_assertion("rp", RSA_KEY, "aud")
    jtis = set()
    for assertion in (first, second):
        token = jwt.JWT(algs=["RS256"])
        token.deserialize(assertion, RSA_KEY)
        jtis.add(json.loads(token.claims)["jti"])
    assert len(jtis) == 2


def test_make_client_assertion_alg_inference_ec():
    assertion = client_assertions.make_client_assertion("rp", EC_KEY, "aud")
    token = jwt.JWT(algs=["ES256"])
    token.deserialize(assertion, EC_KEY)


def test_make_client_assertion_from_pem():
    pem = RSA_KEY.export_to_pem(private_key=True, password=None).decode()
    assertion = client_assertions.make_client_assertion("rp", pem, "aud")
    token = jwt.JWT(algs=["RS256"])
    token.deserialize(assertion, RSA_KEY)


def test_make_client_assertion_from_jwk_json():
    assertion = client_assertions.make_client_assertion("rp", RSA_KEY.export_private(), "aud")
    token = jwt.JWT(algs=["RS256"])
    token.deserialize(assertion, RSA_KEY)


def test_make_client_assertion_raw_secret_requires_hs_alg():
    with pytest.raises(ValueError):
        client_assertions.make_client_assertion("rp", CLEARTEXT_SECRET, "aud")
    assertion = client_assertions.make_client_assertion("rp", CLEARTEXT_SECRET, "aud", alg="HS256")
    key = jwk.JWK(kty="oct", k=base64url_encode(CLEARTEXT_SECRET))
    token = jwt.JWT(algs=["HS256"])
    token.deserialize(assertion, key)


def test_make_client_assertion_extra_claims_and_lifetime():
    assertion = client_assertions.make_client_assertion(
        "rp", RSA_KEY, "aud", lifetime=120, extra_claims={"custom": "x"}
    )
    token = jwt.JWT(algs=["RS256"])
    token.deserialize(assertion, RSA_KEY)
    claims = json.loads(token.claims)
    assert claims["custom"] == "x"
    assert claims["exp"] - claims["iat"] == 120


# ---------------------------------------------------------------------------
# Metadata advertisement helper
# ---------------------------------------------------------------------------


def test_token_endpoint_auth_signing_algs():
    assert client_assertions.token_endpoint_auth_signing_algs(["client_secret_basic"]) == []
    private = client_assertions.token_endpoint_auth_signing_algs(["private_key_jwt"])
    assert "RS256" in private and "ES256" in private and "HS256" not in private
    both = client_assertions.token_endpoint_auth_signing_algs(
        ["client_secret_basic", "private_key_jwt", "client_secret_jwt"]
    )
    assert "RS256" in both and "HS256" in both


# ---------------------------------------------------------------------------
# Endpoint integration (token / introspection / revocation)
# ---------------------------------------------------------------------------


def _assertion_post_data(application, key, audience=TOKEN_AUDIENCE, **extra):
    data = {
        "client_assertion_type": client_assertions.JWT_BEARER_CLIENT_ASSERTION_TYPE,
        "client_assertion": client_assertions.make_client_assertion(application.client_id, key, audience),
    }
    data.update(extra)
    return data


@pytest.mark.django_db(databases="__all__")
def test_token_endpoint_private_key_jwt(client, private_key_jwt_application, client_rsa_jwk):
    from django.urls import reverse

    data = _assertion_post_data(private_key_jwt_application, client_rsa_jwk, grant_type="client_credentials")
    response = client.post(reverse("oauth2_provider:token"), data=data)
    assert response.status_code == 200, response.content
    payload = json.loads(response.content)
    assert payload["token_type"].lower() == "bearer"
    assert "access_token" in payload


@pytest.mark.django_db(databases="__all__")
def test_token_endpoint_private_key_jwt_es256(client, private_key_jwt_application, client_ec_jwk):
    from django.urls import reverse

    data = _assertion_post_data(private_key_jwt_application, client_ec_jwk, grant_type="client_credentials")
    response = client.post(reverse("oauth2_provider:token"), data=data)
    assert response.status_code == 200, response.content


@pytest.mark.django_db(databases="__all__")
def test_token_endpoint_client_secret_jwt(client, client_secret_jwt_application):
    from django.urls import reverse

    assertion = client_assertions.make_client_assertion(
        client_secret_jwt_application.client_id, CLEARTEXT_SECRET, TOKEN_AUDIENCE, alg="HS256"
    )
    response = client.post(
        reverse("oauth2_provider:token"),
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": client_assertions.JWT_BEARER_CLIENT_ASSERTION_TYPE,
            "client_assertion": assertion,
        },
    )
    assert response.status_code == 200, response.content


@pytest.mark.django_db(databases="__all__")
def test_token_endpoint_replayed_assertion_rejected(client, private_key_jwt_application, client_rsa_jwk):
    from django.urls import reverse

    data = _assertion_post_data(private_key_jwt_application, client_rsa_jwk, grant_type="client_credentials")
    first = client.post(reverse("oauth2_provider:token"), data=data)
    assert first.status_code == 200, first.content
    replay = client.post(reverse("oauth2_provider:token"), data=data)
    assert replay.status_code == 401
    assert json.loads(replay.content)["error"] == "invalid_client"


@pytest.mark.django_db(databases="__all__")
def test_token_endpoint_invalid_assertion_does_not_fall_back(client, private_key_jwt_application):
    from django.urls import reverse

    response = client.post(
        reverse("oauth2_provider:token"),
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": client_assertions.JWT_BEARER_CLIENT_ASSERTION_TYPE,
            "client_assertion": "garbage",
            # Even correct secret credentials must not rescue the request.
            "client_id": private_key_jwt_application.client_id,
            "client_secret": CLEARTEXT_SECRET,
        },
    )
    assert response.status_code == 401
    assert json.loads(response.content)["error"] == "invalid_client"


@pytest.mark.django_db(databases="__all__")
def test_token_endpoint_secret_auth_rejected_for_jwt_client(client, private_key_jwt_application):
    from django.urls import reverse

    response = client.post(
        reverse("oauth2_provider:token"),
        data={
            "grant_type": "client_credentials",
            "client_id": private_key_jwt_application.client_id,
            "client_secret": CLEARTEXT_SECRET,
        },
    )
    assert response.status_code == 401


@pytest.mark.django_db(databases="__all__")
def test_introspection_endpoint_accepts_client_assertion(
    client, private_key_jwt_application, client_rsa_jwk, django_user_model
):
    from datetime import timedelta

    from django.urls import reverse
    from django.utils import timezone

    from oauth2_provider.models import get_access_token_model

    token = get_access_token_model().objects.create(
        user=django_user_model.objects.create_user("introspect_user"),
        token="introspectable-token",
        application=private_key_jwt_application,
        expires=timezone.now() + timedelta(days=1),
        scope="read",
    )
    data = _assertion_post_data(
        private_key_jwt_application,
        client_rsa_jwk,
        audience="http://testserver" + reverse("oauth2_provider:introspect"),
        token=token.token,
    )
    response = client.post(reverse("oauth2_provider:introspect"), data=data)
    assert response.status_code == 200, response.content
    assert json.loads(response.content)["active"] is True


@pytest.mark.django_db(databases="__all__")
def test_revocation_endpoint_accepts_client_assertion(
    client, private_key_jwt_application, client_rsa_jwk, django_user_model
):
    from datetime import timedelta

    from django.urls import reverse
    from django.utils import timezone

    from oauth2_provider.models import get_access_token_model

    AccessToken = get_access_token_model()
    token = AccessToken.objects.create(
        user=django_user_model.objects.create_user("revoke_user"),
        token="revocable-token",
        application=private_key_jwt_application,
        expires=timezone.now() + timedelta(days=1),
        scope="read",
    )
    data = _assertion_post_data(
        private_key_jwt_application,
        client_rsa_jwk,
        audience="http://testserver" + reverse("oauth2_provider:revoke-token"),
        token=token.token,
    )
    response = client.post(reverse("oauth2_provider:revoke-token"), data=data)
    assert response.status_code == 200, response.content
    assert not AccessToken.objects.filter(pk=token.pk).exists()


# ---------------------------------------------------------------------------
# Resource-server side: private_key_jwt to a remote introspection endpoint
# ---------------------------------------------------------------------------


class _IntrospectionResponse:
    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def _configure_rs_jwt(oauth2_settings, key):
    oauth2_settings.RESOURCE_SERVER_INTROSPECTION_URL = "https://as.example.com/o/introspect/"
    oauth2_settings.RESOURCE_SERVER_INTROSPECTION_JWT_CLIENT_ID = "rs-client"
    oauth2_settings.RESOURCE_SERVER_INTROSPECTION_JWT_PRIVATE_KEY = key.export_private()
    oauth2_settings.RESOURCE_SERVER_INTROSPECTION_JWT_AUDIENCE = "https://as.example.com"


@pytest.mark.django_db(databases="__all__")
def test_rs_introspection_authenticates_with_client_assertion(oauth2_settings, mocker, client_rsa_jwk):
    from oauthlib.common import Request as OauthlibRequest

    from oauth2_provider.oauth2_validators import OAuth2Validator

    _configure_rs_jwt(oauth2_settings, client_rsa_jwk)
    post = mocker.patch(
        "requests.post", return_value=_IntrospectionResponse({"active": True, "scope": "read"})
    )

    validator = OAuth2Validator()
    assert validator.validate_bearer_token("remote-token", ["read"], OauthlibRequest("/")) is True

    assert post.call_count == 1
    _, kwargs = post.call_args
    body = kwargs.get("data") or post.call_args[0][1]
    assert body["token"] == "remote-token"
    assert body["client_id"] == "rs-client"
    assert body["client_assertion_type"] == client_assertions.JWT_BEARER_CLIENT_ASSERTION_TYPE
    assert kwargs.get("headers") is None

    token = jwt.JWT(algs=["RS256"])
    token.deserialize(body["client_assertion"], client_rsa_jwk)
    claims = json.loads(token.claims)
    assert claims["iss"] == claims["sub"] == "rs-client"
    assert claims["aud"] == "https://as.example.com"


@pytest.mark.django_db(databases="__all__")
def test_rs_introspection_builds_fresh_assertion_per_call(oauth2_settings, mocker, client_rsa_jwk):
    from oauthlib.common import Request as OauthlibRequest

    from oauth2_provider.oauth2_validators import OAuth2Validator

    _configure_rs_jwt(oauth2_settings, client_rsa_jwk)
    post = mocker.patch("requests.post", return_value=_IntrospectionResponse({"active": False}))

    validator = OAuth2Validator()
    jtis = set()
    for candidate in ("token-one", "token-two"):
        validator.validate_bearer_token(candidate, ["read"], OauthlibRequest("/"))
        body = post.call_args.kwargs.get("data") or post.call_args.args[1]
        token = jwt.JWT(algs=["RS256"])
        token.deserialize(body["client_assertion"], client_rsa_jwk)
        jtis.add(json.loads(token.claims)["jti"])
    assert len(jtis) == 2


@pytest.mark.django_db(databases="__all__")
def test_rs_introspection_bearer_token_takes_precedence(oauth2_settings, mocker, client_rsa_jwk):
    from oauthlib.common import Request as OauthlibRequest

    from oauth2_provider.oauth2_validators import OAuth2Validator

    _configure_rs_jwt(oauth2_settings, client_rsa_jwk)
    oauth2_settings.RESOURCE_SERVER_AUTH_TOKEN = "static-bearer"
    post = mocker.patch("requests.post", return_value=_IntrospectionResponse({"active": False}))

    OAuth2Validator().validate_bearer_token("remote-token", ["read"], OauthlibRequest("/"))

    _, kwargs = post.call_args
    body = kwargs.get("data") or post.call_args[0][1]
    assert "client_assertion" not in body
    assert kwargs["headers"]["Authorization"] == "Bearer static-bearer"


@pytest.mark.django_db(databases="__all__")
def test_rs_introspection_partial_jwt_config_is_ignored(oauth2_settings, mocker):
    from oauthlib.common import Request as OauthlibRequest

    from oauth2_provider.oauth2_validators import OAuth2Validator

    oauth2_settings.RESOURCE_SERVER_INTROSPECTION_URL = "https://as.example.com/o/introspect/"
    oauth2_settings.RESOURCE_SERVER_INTROSPECTION_JWT_CLIENT_ID = "rs-client"  # key/audience missing
    post = mocker.patch("requests.post")

    result = OAuth2Validator().validate_bearer_token("remote-token", ["read"], OauthlibRequest("/"))

    assert result is False
    assert post.call_count == 0


# ---------------------------------------------------------------------------
# Edge-case branches (coverage of individual validation helpers)
# ---------------------------------------------------------------------------


def test_non_string_sub_rejected():
    claims = default_claims()
    claims["iss"] = claims["sub"] = 12345
    assertion = build_assertion(RSA_KEY, claims, kid="unit-rsa")
    ok, _ = authenticate(assertion, pkj_app())
    assert ok is False


def test_non_object_claims_rejected():
    from jwcrypto import jws as jws_mod

    signature = jws_mod.JWS(b'["not", "an", "object"]')
    signature.add_signature(RSA_KEY, alg="RS256", protected=json.dumps({"alg": "RS256"}))
    ok, _ = authenticate(signature.serialize(compact=True), pkj_app())
    assert ok is False


def test_unparseable_stored_client_jwks_rejected():
    app = pkj_app(client_jwks="not a jwks")
    assertion = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is False


def test_application_without_any_jwks_rejected():
    app = pkj_app(client_jwks="", client_jwks_uri="")
    assertion = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is False


def test_remote_unknown_kid_falls_back_to_all_keys(mocker):
    # Registered under a different kid label: after the forced refetch still
    # finds no kid match, all registered keys are tried and the signature wins.
    document = {"keys": [dict(json.loads(RSA_KEY.export_public()), kid="other-label")]}
    fetch = mocker.patch.object(client_assertions.safe_fetch, "fetch_https_json", return_value=(document, {}))
    app = pkj_app(client_jwks_uri="https://client.example.com/jwks.json")
    assertion = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is True
    assert fetch.call_count == 2


def test_check_times_rejects_non_numeric_claims():
    now = time.time()
    with pytest.raises(client_assertions.ClientAssertionError):
        client_assertions._check_times({"exp": "tomorrow"})
    with pytest.raises(client_assertions.ClientAssertionError):
        client_assertions._check_times({"exp": now + 60, "iat": "yesterday"})


def test_check_jti_replay_rejects_bad_jti_and_expired():
    now = time.time()
    with pytest.raises(client_assertions.ClientAssertionError):
        client_assertions._check_jti_replay("client", {"jti": 123, "exp": now + 60})
    with pytest.raises(client_assertions.ClientAssertionError):
        client_assertions._check_jti_replay("client", {"jti": "x", "exp": now - 3600})


def test_request_host_fallbacks():
    assert client_assertions._request_host({}) is None
    assert client_assertions._request_host({"SERVER_NAME": "h", "SERVER_PORT": "8443"}) == "h:8443"
    assert client_assertions._request_host({"SERVER_NAME": "h", "SERVER_PORT": "443"}) == "h"


def test_corrupted_jwks_cache_entry_is_refetched(mocker):
    import hashlib as hashlib_mod

    uri = "https://client.example.com/jwks.json"
    digest = hashlib_mod.sha256(uri.encode()).hexdigest()
    cache.set(client_assertions.JWKS_CACHE_PREFIX + digest, "corrupted, not a JWKS", 300)
    fetch = mocker.patch.object(
        client_assertions.safe_fetch,
        "fetch_https_json",
        return_value=(_jwks_document(RSA_KEY), {}),
    )
    key_set = client_assertions.fetch_remote_jwks(pkj_app(client_jwks_uri=uri))
    assert key_set.get_key("unit-rsa") is not None
    assert fetch.call_count == 1


def test_remote_jwks_skips_non_dict_entries():
    document = {"keys": ["a string", json.loads(EC_KEY.export_public())]}
    key_set = client_assertions._build_public_jwks(document)
    assert {key.get("kid") for key in key_set["keys"]} == {"unit-ec"}


def test_make_client_assertion_accepts_pem_bytes():
    pem = RSA_KEY.export_to_pem(private_key=True, password=None)
    assert isinstance(pem, bytes)
    assertion = client_assertions.make_client_assertion("rp", pem, "aud")
    token = jwt.JWT(algs=["RS256"])
    token.deserialize(assertion, RSA_KEY)


def test_make_client_assertion_rejects_non_key_types():
    with pytest.raises(TypeError):
        client_assertions.make_client_assertion("rp", 12345, "aud")


def test_make_client_assertion_infers_hs256_for_oct_jwk():
    key = jwk.JWK(kty="oct", k=base64url_encode(CLEARTEXT_SECRET))
    assertion = client_assertions.make_client_assertion("rp", key, "aud")
    token = jwt.JWT(algs=["HS256"])
    token.deserialize(assertion, key)


def test_make_client_assertion_cannot_infer_alg_for_okp():
    key = jwk.JWK.generate(kty="OKP", crv="Ed25519")
    with pytest.raises(ValueError):
        client_assertions.make_client_assertion("rp", key, "aud")


@pytest.mark.django_db(databases="__all__")
def test_token_endpoint_basic_auth_rejected_for_jwt_client(client, private_key_jwt_application):
    import base64 as base64_mod

    from django.urls import reverse

    creds = f"{private_key_jwt_application.client_id}:{CLEARTEXT_SECRET}".encode()
    response = client.post(
        reverse("oauth2_provider:token"),
        data={"grant_type": "client_credentials"},
        HTTP_AUTHORIZATION="Basic " + base64_mod.b64encode(creds).decode(),
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Discovery advertisement of the JWT methods
# ---------------------------------------------------------------------------

JWT_METHODS_ADVERTISED = [
    "client_secret_post",
    "client_secret_basic",
    "private_key_jwt",
    "client_secret_jwt",
]


@pytest.mark.django_db(databases="__all__")
def test_server_metadata_advertises_auth_signing_algs(client, oauth2_settings):
    from django.urls import reverse

    oauth2_settings.OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED = JWT_METHODS_ADVERTISED
    response = client.get(reverse("oauth2_provider:oauth-server-metadata"))
    assert response.status_code == 200
    data = response.json()
    for endpoint in ("token", "revocation", "introspection"):
        assert data[f"{endpoint}_endpoint_auth_methods_supported"] == JWT_METHODS_ADVERTISED
        algs = data[f"{endpoint}_endpoint_auth_signing_alg_values_supported"]
        assert "RS256" in algs and "ES256" in algs and "HS256" in algs


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_oidc_discovery_advertises_auth_signing_algs(client, oauth2_settings):
    from django.urls import reverse

    oauth2_settings.OIDC_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED = JWT_METHODS_ADVERTISED
    response = client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))
    assert response.status_code == 200
    data = response.json()
    assert data["token_endpoint_auth_methods_supported"] == JWT_METHODS_ADVERTISED
    algs = data["token_endpoint_auth_signing_alg_values_supported"]
    assert "RS256" in algs and "HS256" in algs


def test_encryption_only_jwks_rejected():
    # A registered JWKS whose keys are all use=enc offers nothing to verify
    # signatures with; the assertion must be rejected.
    enc_key = dict(json.loads(RSA_KEY.export_public()), use="enc")
    app = pkj_app(client_jwks=json.dumps({"keys": [enc_key]}))
    assertion = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is False


@pytest.mark.django_db(databases="__all__")
def test_rs_introspection_unusable_key_is_ignored(oauth2_settings, mocker):
    from oauthlib.common import Request as OauthlibRequest

    from oauth2_provider.oauth2_validators import OAuth2Validator

    oauth2_settings.RESOURCE_SERVER_INTROSPECTION_URL = "https://as.example.com/o/introspect/"
    oauth2_settings.RESOURCE_SERVER_INTROSPECTION_JWT_CLIENT_ID = "rs-client"
    oauth2_settings.RESOURCE_SERVER_INTROSPECTION_JWT_PRIVATE_KEY = "not a key at all"
    oauth2_settings.RESOURCE_SERVER_INTROSPECTION_JWT_AUDIENCE = "https://as.example.com"
    post = mocker.patch("requests.post")

    result = OAuth2Validator().validate_bearer_token("remote-token", ["read"], OauthlibRequest("/"))

    assert result is False
    assert post.call_count == 0


def test_key_ops_without_verify_is_skipped():
    # RFC 7517 key_ops constrains a key just like use does: a key that does
    # not permit "verify" must never be tried for JWS verification.
    enc_ops_key = dict(json.loads(RSA_KEY.export_public()), key_ops=["encrypt"])
    app = pkj_app(client_jwks=json.dumps({"keys": [enc_ops_key]}))
    assertion = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is False

    verify_ops_key = dict(json.loads(RSA_KEY.export_public()), key_ops=["verify"])
    app = pkj_app(client_jwks=json.dumps({"keys": [verify_ops_key]}))
    assertion = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is True


def test_empty_accepted_audiences_list_rejects_everything(oauth2_settings):
    # An explicitly configured empty list is authoritative (fail closed), not
    # a signal to fall back to the derived audience set.
    oauth2_settings.CLIENT_ASSERTION_ACCEPTED_AUDIENCES = []
    app = pkj_app()
    assertion = build_assertion(RSA_KEY, default_claims(), kid="unit-rsa")
    ok, _ = authenticate(assertion, app)
    assert ok is False


def test_disallowed_host_header_cannot_pick_the_audience():
    # The derived request-URL audience is only trusted when the Host header
    # passes ALLOWED_HOSTS validation; a crafted Host must not let an attacker
    # choose the accepted audience (the header bypasses HttpRequest.get_host).
    app = pkj_app()
    claims = default_claims(aud="http://evil.example/o/token/")
    assertion = build_assertion(RSA_KEY, claims, kid="unit-rsa")
    ok, _ = authenticate(assertion, app, headers={"HTTP_HOST": "evil.example"})
    assert ok is False


def test_partial_assertion_parameters_still_require_client_authentication():
    # client_assertion_type with an empty/missing client_assertion is an
    # assertion-based auth attempt: it must require client authentication (and
    # then fail closed in authenticate_client) rather than let oauthlib treat
    # the request as an unauthenticated public client on conditional grants.
    from oauthlib.common import Request as OauthlibRequest

    from oauth2_provider.oauth2_validators import OAuth2Validator

    validator = OAuth2Validator()
    body = (
        "grant_type=authorization_code"
        f"&client_assertion_type={client_assertions.JWT_BEARER_CLIENT_ASSERTION_TYPE}"
        "&client_assertion="
    )
    request = OauthlibRequest("/o/token/", http_method="POST", body=body)
    assert validator.client_authentication_required(request) is True
    assert validator.authenticate_client(request) is False

    only_type = OauthlibRequest(
        "/o/token/",
        http_method="POST",
        body=f"grant_type=authorization_code&client_assertion_type={client_assertions.JWT_BEARER_CLIENT_ASSERTION_TYPE}",
    )
    assert validator.client_authentication_required(only_type) is True
    assert validator.authenticate_client(only_type) is False


def test_debug_mode_allows_localhost_hosts(settings):
    # With DEBUG on and ALLOWED_HOSTS empty, get_host()'s localhost allowances
    # apply to the derived audience too.
    settings.DEBUG = True
    settings.ALLOWED_HOSTS = []
    app = pkj_app()
    claims = default_claims(aud="http://127.0.0.1/o/token/")
    assertion = build_assertion(RSA_KEY, claims, kid="unit-rsa")
    ok, _ = authenticate(assertion, app, headers={"HTTP_HOST": "127.0.0.1"})
    assert ok is True

    claims = default_claims(aud="http://evil.example/o/token/")
    assertion = build_assertion(RSA_KEY, claims, kid="unit-rsa")
    ok, _ = authenticate(assertion, app, headers={"HTTP_HOST": "evil.example"})
    assert ok is False


def test_remote_jwks_excludes_non_verification_keys():
    # The cached remote set holds only signature-verification keys, as the
    # fetch_remote_jwks docstring promises.
    document = {
        "keys": [
            dict(json.loads(RSA_KEY.export_public()), use="enc"),
            dict(json.loads(EC_KEY.export_public()), key_ops=["encrypt"]),
            json.loads(EC_KEY.export_public()),
        ]
    }
    key_set = client_assertions._build_public_jwks(document)
    assert [key.get("kid") for key in key_set["keys"]] == ["unit-ec"]
