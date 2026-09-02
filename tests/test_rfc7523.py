"""Unit tests for the shared RFC 7521/7523 assertion helpers."""

import json
import time
from unittest import mock

import pytest
from django.core.cache import caches
from jwcrypto import jwk, jws

from oauth2_provider.authorization_server import rfc7523
from oauth2_provider.authorization_server.rfc7523 import (
    JWTBearerAssertionError,
    check_and_record_jti,
    load_application_keys,
    load_jwks,
    validate_assertion_claims,
    verify_assertion,
)
from oauth2_provider.client.rfc7523 import build_jwt_bearer_assertion


ISSUER = "https://client.example.com"
AUDIENCE = "https://as.example.com/o/token/"


@pytest.fixture
def signing_key():
    key = jwk.JWK.generate(kty="RSA", size=2048, kid="test-key")
    return key


@pytest.fixture
def public_jwks(signing_key):
    keyset = jwk.JWKSet()
    keyset.add(jwk.JWK.from_json(signing_key.export_public()))
    return keyset


@pytest.fixture(autouse=True)
def clear_cache():
    caches["default"].clear()
    yield
    caches["default"].clear()


def make_assertion(signing_key, **overrides):
    kwargs = {
        "key": signing_key,
        "issuer": ISSUER,
        "subject": "alice",
        "audience": AUDIENCE,
    }
    kwargs.update(overrides)
    return build_jwt_bearer_assertion(**kwargs)


def _signed_token_with_raw_payload(signing_key, payload):
    """A validly signed JWS whose payload is not JSON (for error-path tests)."""
    token = jws.JWS(payload)
    token.add_signature(signing_key, alg="RS256", protected=json.dumps({"alg": "RS256"}))
    return token.serialize(compact=True)


class TestBuildAndVerify:
    def test_round_trip(self, signing_key, public_jwks):
        assertion = make_assertion(signing_key)
        claims = verify_assertion(assertion, public_jwks)
        assert claims["iss"] == ISSUER
        assert claims["sub"] == "alice"
        assert claims["aud"] == AUDIENCE
        assert claims["jti"]
        assert claims["exp"] > claims["iat"]

    def test_additional_claims_merged(self, signing_key, public_jwks):
        assertion = make_assertion(signing_key, additional_claims={"scope": "read"})
        claims = verify_assertion(assertion, public_jwks)
        assert claims["scope"] == "read"

    def test_wrong_key_rejected(self, signing_key):
        other = jwk.JWKSet()
        other.add(jwk.JWK.generate(kty="RSA", size=2048))
        assertion = make_assertion(signing_key)
        with pytest.raises(JWTBearerAssertionError) as exc:
            verify_assertion(assertion, other)
        assert exc.value.error == "invalid_grant"

    def test_none_alg_rejected(self, signing_key, public_jwks):
        # An assertion is never accepted under alg=none even if presented as such.
        assertion = make_assertion(signing_key)
        header, _, _ = assertion.split(".")
        with pytest.raises(JWTBearerAssertionError):
            verify_assertion(assertion, public_jwks, allowed_algs=["none"])

    def test_hs256_not_in_default_algs(self, signing_key, public_jwks):
        assertion = make_assertion(signing_key)
        assert "HS256" not in rfc7523.DEFAULT_ALLOWED_ALGS
        # Default algs still verify a legitimate RS256 assertion.
        assert verify_assertion(assertion, public_jwks)["sub"] == "alice"

    def test_malformed_assertion(self, public_jwks):
        with pytest.raises(JWTBearerAssertionError) as exc:
            verify_assertion("not-a-jwt", public_jwks)
        assert exc.value.error == "invalid_grant"


class TestValidateClaims:
    def base_claims(self, **overrides):
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "sub": "alice",
            "aud": AUDIENCE,
            "exp": now + 300,
            "iat": now,
            "jti": "abc123",
        }
        claims.update(overrides)
        return claims

    def test_valid(self):
        validate_assertion_claims(self.base_claims(), expected_audiences={AUDIENCE})

    @pytest.mark.parametrize("missing", ["iss", "sub", "aud", "exp"])
    def test_missing_required(self, missing):
        claims = self.base_claims()
        del claims[missing]
        with pytest.raises(JWTBearerAssertionError, match="required claim"):
            validate_assertion_claims(claims, expected_audiences={AUDIENCE})

    def test_expired(self):
        claims = self.base_claims(exp=int(time.time()) - 3600)
        with pytest.raises(JWTBearerAssertionError, match="expired"):
            validate_assertion_claims(claims, expected_audiences={AUDIENCE})

    def test_not_yet_valid(self):
        claims = self.base_claims(nbf=int(time.time()) + 3600)
        with pytest.raises(JWTBearerAssertionError, match="not yet valid"):
            validate_assertion_claims(claims, expected_audiences={AUDIENCE})

    def test_wrong_audience(self):
        claims = self.base_claims(aud="https://evil.example.com/")
        with pytest.raises(JWTBearerAssertionError, match="audience"):
            validate_assertion_claims(claims, expected_audiences={AUDIENCE})

    def test_audience_list_intersection(self):
        claims = self.base_claims(aud=["https://other/", AUDIENCE])
        validate_assertion_claims(claims, expected_audiences={AUDIENCE})

    def test_lifetime_too_long(self):
        claims = self.base_claims(exp=int(time.time()) + 100000)
        with pytest.raises(JWTBearerAssertionError, match="too long"):
            validate_assertion_claims(claims, expected_audiences={AUDIENCE}, max_lifetime=3600)

    def test_missing_jti_required(self):
        claims = self.base_claims()
        del claims["jti"]
        with pytest.raises(JWTBearerAssertionError, match="jti"):
            validate_assertion_claims(claims, expected_audiences={AUDIENCE}, require_jti=True)

    def test_missing_jti_allowed_when_not_required(self):
        claims = self.base_claims()
        del claims["jti"]
        validate_assertion_claims(claims, expected_audiences={AUDIENCE}, require_jti=False)

    def test_non_numeric_exp(self):
        claims = self.base_claims(exp="soon")
        with pytest.raises(JWTBearerAssertionError, match="not a number"):
            validate_assertion_claims(claims, expected_audiences={AUDIENCE})

    @pytest.mark.parametrize("bad_aud", [[["x"]], [{"k": 1}], [AUDIENCE, 5], {"aud": AUDIENCE}])
    def test_malformed_audience_is_rejected_not_500(self, bad_aud):
        # A non-string aud element must be rejected as invalid_grant, never raise
        # an unhashable-type TypeError that would surface as an HTTP 500.
        claims = self.base_claims(aud=bad_aud)
        with pytest.raises(JWTBearerAssertionError, match="malformed"):
            validate_assertion_claims(claims, expected_audiences={AUDIENCE})


class TestJtiReplay:
    def test_first_use_then_replay(self):
        exp = int(time.time()) + 300
        check_and_record_jti(ISSUER, "jti-1", exp)
        with pytest.raises(JWTBearerAssertionError, match="replay"):
            check_and_record_jti(ISSUER, "jti-1", exp)

    def test_same_jti_different_issuer(self):
        exp = int(time.time()) + 300
        check_and_record_jti(ISSUER, "shared", exp)
        # A different issuer namespaces the jti, so this must not be a replay.
        check_and_record_jti("https://other.example.com", "shared", exp)


class TestKeyLoading:
    def test_load_jwks_set(self):
        key = jwk.JWK.generate(kty="RSA", size=2048)
        keyset = load_jwks(f'{{"keys": [{key.export_public()}]}}')
        assert len(list(keyset)) == 1

    def test_load_jwks_bare_key(self):
        key = jwk.JWK.generate(kty="RSA", size=2048)
        keyset = load_jwks(key.export_public())
        assert len(list(keyset)) == 1

    def test_load_jwks_malformed(self):
        with pytest.raises(JWTBearerAssertionError, match="malformed"):
            load_jwks("{not json")

    def test_load_application_keys_inline(self):
        key = jwk.JWK.generate(kty="RSA", size=2048)

        class FakeApp:
            client_jwks = json.dumps({"keys": [json.loads(key.export_public())]})
            client_jwks_uri = ""

        keyset = load_application_keys(FakeApp())
        assert keyset is not None
        assert len(list(keyset)) == 1

    def test_load_application_keys_none(self):
        class FakeApp:
            client_jwks = ""
            client_jwks_uri = ""

        assert load_application_keys(FakeApp()) is None

    def test_load_jwks_malformed_key_material(self):
        # Valid JSON, but not a valid JWK (no usable key material).
        with pytest.raises(JWTBearerAssertionError, match="malformed"):
            load_jwks(json.dumps({"keys": [{"kty": "RSA"}]}))

    def test_load_application_keys_via_uri(self):
        key = jwk.JWK.generate(kty="RSA", size=2048)
        document = json.dumps({"keys": [json.loads(key.export_public())]})

        class FakeApp:
            client_jwks = ""
            client_jwks_uri = "https://client.example.com/jwks.json"

        with mock.patch.object(rfc7523.safe_fetch, "fetch_https_json", return_value=json.loads(document)):
            keyset = load_application_keys(FakeApp())
        assert keyset is not None
        assert len(list(keyset)) == 1


class TestFetchJwks:
    def test_fetch_and_cache(self):
        key = jwk.JWK.generate(kty="RSA", size=2048)
        data = json.loads(json.dumps({"keys": [json.loads(key.export_public())]}))
        with mock.patch.object(rfc7523.safe_fetch, "fetch_https_json", return_value=data) as fetcher:
            keyset = rfc7523.fetch_jwks("https://issuer.example.com/jwks.json")
            assert len(list(keyset)) == 1
            # Second call is served from cache: the fetcher is not called again.
            rfc7523.fetch_jwks("https://issuer.example.com/jwks.json")
        assert fetcher.call_count == 1

    def test_fetch_failure_maps_to_invalid_client(self):
        with mock.patch.object(
            rfc7523.safe_fetch,
            "fetch_https_json",
            side_effect=rfc7523.safe_fetch.SafeFetchError("boom"),
        ):
            with pytest.raises(JWTBearerAssertionError) as exc:
                rfc7523.fetch_jwks("https://issuer.example.com/jwks.json")
        assert exc.value.error == "invalid_client"


class TestLoadIssuerKeys:
    def test_not_a_dict(self):
        with pytest.raises(JWTBearerAssertionError, match="malformed"):
            rfc7523.load_issuer_keys("not-a-dict")

    def test_inline_jwks_object(self):
        key = jwk.JWK.generate(kty="RSA", size=2048)
        keyset = rfc7523.load_issuer_keys({"jwks": {"keys": [json.loads(key.export_public())]}})
        assert len(list(keyset)) == 1

    def test_jwks_uri(self):
        key = jwk.JWK.generate(kty="RSA", size=2048)
        data = {"keys": [json.loads(key.export_public())]}
        with mock.patch.object(rfc7523.safe_fetch, "fetch_https_json", return_value=data):
            keyset = rfc7523.load_issuer_keys({"jwks_uri": "https://sts.example.com/jwks"})
        assert len(list(keyset)) == 1

    def test_no_keys_configured(self):
        with pytest.raises(JWTBearerAssertionError, match="no keys"):
            rfc7523.load_issuer_keys({})


class TestPeekUnverifiedClaims:
    def test_valid(self, signing_key):
        assertion = make_assertion(signing_key)
        claims = rfc7523.peek_unverified_claims(assertion)
        assert claims["iss"] == ISSUER

    def test_malformed(self):
        with pytest.raises(JWTBearerAssertionError, match="well-formed"):
            rfc7523.peek_unverified_claims("not-a-jwt")

    def test_non_json_payload(self, signing_key):
        token = _signed_token_with_raw_payload(signing_key, b"not-json-payload")
        with pytest.raises(JWTBearerAssertionError, match="not valid JSON"):
            rfc7523.peek_unverified_claims(token)


class TestVerifyAssertionErrors:
    def test_non_json_payload(self, signing_key, public_jwks):
        token = _signed_token_with_raw_payload(signing_key, b"not-json-payload")
        with pytest.raises(JWTBearerAssertionError, match="not valid JSON"):
            verify_assertion(token, public_jwks)


@pytest.mark.django_db(databases="__all__")
class TestResolveSubject:
    def test_missing_sub_returns_none(self):
        assert rfc7523.resolve_subject_by_username({}, None, None) is None

    def test_resolves_active_user(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        user = User.objects.create_user(username="carol", password="x")
        assert rfc7523.resolve_subject_by_username({"sub": "carol"}, None, None) == user

    def test_inactive_user_rejected(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        User.objects.create_user(username="dave", password="x", is_active=False)
        assert rfc7523.resolve_subject_by_username({"sub": "dave"}, None, None) is None

    @pytest.mark.parametrize("flag", ["is_staff", "is_superuser"])
    def test_privileged_subject_refused_by_default(self, flag):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        User.objects.create_user(username="admin", password="x", **{flag: True})
        # A staff/superuser subject is refused out of the box: an assertion mints
        # a token without the user's interactive consent.
        assert rfc7523.resolve_subject_by_username({"sub": "admin"}, None, None) is None

    @pytest.mark.parametrize("flag", ["is_staff", "is_superuser"])
    def test_privileged_subject_allowed_when_enabled(self, flag):
        from django.contrib.auth import get_user_model

        from oauth2_provider.settings import oauth2_settings

        User = get_user_model()
        user = User.objects.create_user(username="admin", password="x", **{flag: True})
        oauth2_settings.JWT_BEARER_ALLOW_PRIVILEGED_SUBJECTS = True
        try:
            assert rfc7523.resolve_subject_by_username({"sub": "admin"}, None, None) == user
        finally:
            oauth2_settings.JWT_BEARER_ALLOW_PRIVILEGED_SUBJECTS = False
