"""Integration tests for the RFC 7523 §2.1 JWT bearer authorization grant."""

import json

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import caches
from django.urls import reverse
from jwcrypto import jwk

from oauth2_provider.models import get_access_token_model, get_application_model
from oauth2_provider.rfc7523 import build_jwt_bearer_assertion

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()

AUDIENCE = "https://as.example.com/o/token/"
CLEARTEXT_SECRET = "abcdefghijklmnopqrstuvwxyz1234567890"

TOKEN_URL = reverse("oauth2_provider:token")


def _resolve_bob(claims, application, request):
    """Custom subject resolver used to test JWT_BEARER_SUBJECT_RESOLVER."""
    if claims.get("sub") == "external-id-42":
        return UserModel.objects.filter(username="bob").first()
    return None


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.JWT_BEARER_SETTINGS)
class BaseJWTBearerTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")
        cls.alice = UserModel.objects.create_user("alice", "alice@example.com", "123456")

        cls.key = jwk.JWK.generate(kty="RSA", size=2048, kid="rsa-1")
        cls.es_key = jwk.JWK.generate(kty="EC", crv="P-256", kid="ec-1")

        public_jwks = json.dumps(
            {
                "keys": [
                    json.loads(cls.key.export_public()),
                    json.loads(cls.es_key.export_public()),
                ]
            }
        )

        cls.application = Application.objects.create(
            name="jwt_bearer_app",
            user=cls.dev_user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_JWT_BEARER,
            client_jwks=public_jwks,
        )

    def setUp(self):
        super().setUp()
        caches["default"].clear()

    def make_assertion(self, key=None, **overrides):
        kwargs = {
            "key": key or self.key,
            "issuer": self.application.client_id,
            "subject": "alice",
            "audience": AUDIENCE,
        }
        kwargs.update(overrides)
        return build_jwt_bearer_assertion(**kwargs)

    def post_assertion(self, assertion, client_id=None, extra=None, **auth):
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        }
        if client_id is not None:
            data["client_id"] = client_id
        elif "HTTP_AUTHORIZATION" not in auth:
            data["client_id"] = self.application.client_id
        if extra:
            data.update(extra)
        return self.client.post(TOKEN_URL, data=data, **auth)


class TestHappyPath(BaseJWTBearerTest):
    def test_rs256_assertion_issues_token(self):
        response = self.post_assertion(self.make_assertion())
        self.assertEqual(response.status_code, 200, response.content)
        content = json.loads(response.content)
        self.assertIn("access_token", content)
        self.assertEqual(content["token_type"], "Bearer")

        token = AccessToken.objects.get(token=content["access_token"])
        self.assertEqual(token.user, self.alice)
        self.assertEqual(token.application, self.application)

    def test_es256_assertion_issues_token(self):
        assertion = self.make_assertion(key=self.es_key, algorithm="ES256")
        response = self.post_assertion(assertion)
        self.assertEqual(response.status_code, 200, response.content)

    def test_requested_scope_honored(self):
        response = self.post_assertion(self.make_assertion(), extra={"scope": "read"})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(json.loads(response.content)["scope"], "read")

    def test_out_of_scope_rejected(self):
        response = self.post_assertion(self.make_assertion(), extra={"scope": "destroy"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_scope")

    def test_no_refresh_token_by_default(self):
        response = self.post_assertion(self.make_assertion())
        self.assertNotIn("refresh_token", json.loads(response.content))

    def test_refresh_token_when_enabled(self):
        self.oauth2_settings.JWT_BEARER_ISSUE_REFRESH_TOKENS = True
        response = self.post_assertion(self.make_assertion())
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn("refresh_token", json.loads(response.content))


class TestTrust(BaseJWTBearerTest):
    def test_unknown_issuer_rejected(self):
        assertion = self.make_assertion(issuer="https://stranger.example.com")
        response = self.post_assertion(assertion)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_grant")

    def test_wrong_signing_key_rejected(self):
        stranger_key = jwk.JWK.generate(kty="RSA", size=2048)
        response = self.post_assertion(self.make_assertion(key=stranger_key))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_grant")

    def test_trusted_third_party_issuer(self):
        issuer_key = jwk.JWK.generate(kty="RSA", size=2048, kid="sts-1")
        self.oauth2_settings.JWT_BEARER_TRUSTED_ISSUERS = {
            "https://sts.example.com": {"jwks": json.loads(issuer_key.export_public())},
        }
        assertion = self.make_assertion(key=issuer_key, issuer="https://sts.example.com")
        response = self.post_assertion(assertion)
        self.assertEqual(response.status_code, 200, response.content)


class TestClaims(BaseJWTBearerTest):
    def test_expired_assertion(self):
        response = self.post_assertion(self.make_assertion(lifetime_seconds=-3600))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_grant")

    def test_wrong_audience(self):
        response = self.post_assertion(self.make_assertion(audience="https://evil.example.com/"))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_grant")

    def test_lifetime_too_long(self):
        self.oauth2_settings.JWT_BEARER_MAX_ASSERTION_LIFETIME_SECONDS = 300
        response = self.post_assertion(self.make_assertion(lifetime_seconds=100000))
        self.assertEqual(response.status_code, 400)

    def test_missing_assertion(self):
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "client_id": self.application.client_id,
        }
        response = self.client.post(TOKEN_URL, data=data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_request")

    def test_missing_jti_rejected(self):
        # build_jwt_bearer_assertion always sets jti; strip it by overriding.
        assertion = self.make_assertion(additional_claims={"jti": None})
        response = self.post_assertion(assertion)
        self.assertEqual(response.status_code, 400)

    def test_jti_replay_rejected(self):
        assertion = self.make_assertion()
        first = self.post_assertion(assertion)
        self.assertEqual(first.status_code, 200, first.content)
        second = self.post_assertion(assertion)
        self.assertEqual(second.status_code, 400)
        self.assertEqual(json.loads(second.content)["error"], "invalid_grant")


class TestSubjectResolution(BaseJWTBearerTest):
    def test_unknown_subject_rejected(self):
        response = self.post_assertion(self.make_assertion(subject="nobody"))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_grant")

    def test_inactive_user_rejected(self):
        self.alice.is_active = False
        self.alice.save()
        response = self.post_assertion(self.make_assertion())
        self.assertEqual(response.status_code, 400)

    def test_custom_resolver(self):
        self.oauth2_settings.JWT_BEARER_SUBJECT_RESOLVER = _resolve_bob
        bob = UserModel.objects.create_user("bob", "bob@example.com", "123456")
        assertion = self.make_assertion(subject="external-id-42")
        response = self.post_assertion(assertion)
        self.assertEqual(response.status_code, 200, response.content)
        token = AccessToken.objects.get(token=json.loads(response.content)["access_token"])
        self.assertEqual(token.user, bob)


class TestGating(BaseJWTBearerTest):
    def test_grant_disabled_unsupported(self):
        self.oauth2_settings.JWT_BEARER_GRANT_ENABLED = False
        response = self.post_assertion(self.make_assertion())
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "unsupported_grant_type")

    def test_application_not_allowed_grant(self):
        other = Application.objects.create(
            name="cc_app",
            user=self.dev_user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            client_jwks=self.application.client_jwks,
        )
        assertion = self.make_assertion(issuer=other.client_id)
        response = self.post_assertion(assertion, client_id=other.client_id)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "unauthorized_client")

    def test_confidential_client_requires_authentication(self):
        confidential = Application.objects.create(
            name="conf_app",
            user=self.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_JWT_BEARER,
            client_secret=CLEARTEXT_SECRET,
            client_jwks=self.application.client_jwks,
        )
        assertion = self.make_assertion(issuer=confidential.client_id)
        # No credentials → cannot authenticate the confidential client.
        response = self.post_assertion(assertion, client_id=confidential.client_id)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(json.loads(response.content)["error"], "invalid_client")

        # With HTTP Basic credentials the same request succeeds.
        auth = get_basic_auth_header(confidential.client_id, CLEARTEXT_SECRET)
        assertion = self.make_assertion(issuer=confidential.client_id)
        response = self.post_assertion(assertion, **auth)
        self.assertEqual(response.status_code, 200, response.content)
