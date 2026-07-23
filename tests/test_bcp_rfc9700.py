"""
Tests for the RFC 9700 (OAuth 2.0 Security Best Current Practice) gates.

Every gate is exercised in both positions: with the legacy default (``False``)
the behavior is preserved but warns, and with the compliant value (``True``) the
behavior is enforced.
"""

import hashlib
import json
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.core import checks
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone

from oauth2_provider.models import get_access_token_model, get_application_model
from oauth2_provider.oauth2_backends import _add_iss_to_redirect
from oauth2_provider.views import ProtectedResourceView

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"


class ResourceView(ProtectedResourceView):
    def get(self, request, *args, **kwargs):
        return "This is a protected resource"


# ---------------------------------------------------------------------------
# Password (ROPC) grant gate
# ---------------------------------------------------------------------------
@pytest.mark.usefixtures("oauth2_settings")
class TestPasswordGrantGate(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("po", "po@example.com", "123456")
        cls.application = Application.objects.create(
            name="pw",
            user=cls.user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_PASSWORD,
            client_secret=CLEARTEXT_SECRET,
        )

    def _request_token(self):
        data = {"grant_type": "password", "username": "po", "password": "123456"}
        headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        return self.client.post(reverse("oauth2_provider:token"), data=data, **headers)

    def test_allowed_by_default(self):
        # Insecure default is preserved but warns when exercised.
        with self.assertWarns(DeprecationWarning):
            response = self._request_token()
        self.assertEqual(response.status_code, 200)

    def test_rejected_when_gate_enabled(self):
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_PASSWORD_GRANT = True
        response = self._request_token()
        self.assertEqual(response.status_code, 400)
        # oauthlib maps a rejected grant type to unauthorized_client.
        self.assertEqual(json.loads(response.content)["error"], "unauthorized_client")


# ---------------------------------------------------------------------------
# Implicit grant gate
# ---------------------------------------------------------------------------
@pytest.mark.usefixtures("oauth2_settings")
class TestImplicitGrantGate(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("io", "io@example.com", "123456")
        cls.application = Application.objects.create(
            name="imp",
            user=cls.user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_IMPLICIT,
            redirect_uris="https://example.org/cb",
        )

    def _authorize(self):
        self.client.login(username="io", password="123456")
        return self.client.get(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": self.application.client_id,
                "response_type": "token",
                "redirect_uri": "https://example.org/cb",
                "scope": "read",
            },
        )

    def test_allowed_by_default(self):
        # The consent page renders (HTTP 200) when implicit is permitted, and warns.
        with self.assertWarns(DeprecationWarning):
            response = self._authorize()
        self.assertEqual(response.status_code, 200)

    def test_rejected_when_gate_enabled(self):
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT = True
        response = self._authorize()
        # Rejected via an error redirect to the client (oauthlib maps a disallowed
        # response type to unauthorized_client), not by rendering consent or issuing
        # a token.
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=unauthorized_client", response["Location"])
        self.assertNotIn("access_token", response["Location"])


# ---------------------------------------------------------------------------
# PKCE "plain" method gate
# ---------------------------------------------------------------------------
@pytest.mark.usefixtures("oauth2_settings")
class TestPkcePlainGate(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("co", "co@example.com", "123456")
        cls.application = Application.objects.create(
            name="pkce",
            user=cls.user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="https://example.org/cb",
        )

    def _authorize_and_confirm(self):
        self.client.login(username="co", password="123456")
        return self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": self.application.client_id,
                "response_type": "code",
                "redirect_uri": "https://example.org/cb",
                "scope": "read",
                "code_challenge": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "code_challenge_method": "plain",
                "state": "abc",
                "allow": True,
            },
        )

    def test_allowed_by_default(self):
        with self.assertWarns(DeprecationWarning):
            response = self._authorize_and_confirm()
        self.assertEqual(response.status_code, 302)
        self.assertIn("code=", response["Location"])

    def test_rejected_when_gate_enabled(self):
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_PKCE_METHOD = True
        response = self._authorize_and_confirm()
        # Redirect back to the client carrying an error, no authorization code.
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("code=", response["Location"])
        self.assertIn("error=", response["Location"])

    def test_iss_added_to_authorization_redirect(self):
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS = True
        self.client.login(username="co", password="123456")
        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": self.application.client_id,
                "response_type": "code",
                "redirect_uri": "https://example.org/cb",
                "scope": "read",
                "state": "abc",
                "allow": True,
            },
        )
        self.assertEqual(response.status_code, 302)
        # RFC 9207: the issuer (matching the metadata issuer) is echoed on the redirect.
        self.assertIn("iss=http%3A%2F%2Ftestserver%2Fo", response["Location"])

    def test_iss_omitted_by_default(self):
        self.client.login(username="co", password="123456")
        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": self.application.client_id,
                "response_type": "code",
                "redirect_uri": "https://example.org/cb",
                "scope": "read",
                "state": "abc",
                "allow": True,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("iss=", response["Location"])


# ---------------------------------------------------------------------------
# Access token in query string gate
# ---------------------------------------------------------------------------
@pytest.mark.usefixtures("oauth2_settings")
class TestAccessTokenInQueryGate(TestCase):
    factory = RequestFactory()

    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("qo", "qo@example.com", "123456")
        cls.application = Application.objects.create(
            name="q",
            user=cls.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            client_secret=CLEARTEXT_SECRET,
        )

    def _make_token(self):
        return AccessToken.objects.create(
            user=self.user,
            token="querytoken123",
            application=self.application,
            expires=timezone.now() + timedelta(seconds=300),
            scope="read",
        )

    def test_query_token_allowed_by_default(self):
        self._make_token()
        request = self.factory.get("/fake-resource?access_token=querytoken123")
        request.user = self.user
        with self.assertWarns(DeprecationWarning):
            response = ResourceView.as_view()(request)
        self.assertEqual(response, "This is a protected resource")

    def test_query_token_rejected_when_gate_enabled(self):
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_ACCESS_TOKEN_TRANSPORT = True
        self._make_token()
        request = self.factory.get("/fake-resource?access_token=querytoken123")
        request.user = self.user
        response = ResourceView.as_view()(request)
        self.assertEqual(response.status_code, 403)


# ---------------------------------------------------------------------------
# RFC 9207 iss parameter
# ---------------------------------------------------------------------------
def test_authorization_server_issuer_uses_oidc_iss_endpoint(oauth2_settings):
    oauth2_settings.OIDC_ISS_ENDPOINT = "https://issuer.example/o"
    from oauth2_provider.settings import oauth2_settings as live_settings

    assert live_settings.oauth2_authorization_server_issuer(None) == "https://issuer.example/o"


def test_authorization_server_issuer_falls_back_when_url_unresolvable(monkeypatch):
    from django.test import RequestFactory
    from django.urls import NoReverseMatch

    from oauth2_provider import settings as settings_module
    from oauth2_provider.settings import oauth2_settings as live_settings

    def _raise(*args, **kwargs):
        raise NoReverseMatch

    monkeypatch.setattr(settings_module, "reverse", _raise)
    request = RequestFactory().get("/o/authorize/")
    assert live_settings.oauth2_authorization_server_issuer(request) == "http://testserver"


def test_implicit_response_type_rejected_for_non_implicit_client():
    # A client that does not allow the implicit grant is rejected for the ``token``
    # response type before the gate is consulted (no DB access needed).
    from oauth2_provider.oauth2_validators import OAuth2Validator

    class _Client:
        def allows_grant_type(self, *grant_types):
            return False

    validator = OAuth2Validator()
    assert validator.validate_response_type(None, "token", _Client(), None) is False


def test_set_token_value_clears_stale_raw_token_in_plaintext_mode():
    # With plaintext storage (the default), _set_token_value must clear any stale
    # _raw_token so a later save derives the checksum from the plaintext token.
    from oauth2_provider.oauth2_validators import OAuth2Validator

    class _Tok:
        pass

    tok = _Tok()
    tok._raw_token = "STALE"  # left over from a prior hashed-mode assignment
    OAuth2Validator()._set_token_value(tok, "freshtoken")
    assert tok.token == "freshtoken"
    assert tok._raw_token is None


def test_bcp_filter_response_types_is_token_order_independent(oauth2_settings):
    # Response types are space-separated sets: implicit types must be filtered
    # regardless of token order; hybrid (code ...) types are kept.
    from oauth2_provider.views.metadata import bcp_filter_response_types

    oauth2_settings.COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT = True
    filtered = bcp_filter_response_types(["code", "token id_token", "id_token token", "token", "code token"])
    assert "token id_token" not in filtered
    assert "id_token token" not in filtered
    assert "token" not in filtered
    assert "code" in filtered
    assert "code token" in filtered  # hybrid is not gated


def test_add_iss_to_redirect_query():
    result = _add_iss_to_redirect("https://c.example/cb?code=abc&state=x", "https://as.example")
    assert result == "https://c.example/cb?code=abc&state=x&iss=https%3A%2F%2Fas.example"


def test_add_iss_to_redirect_replaces_existing_iss():
    # RFC 9207 requires a single issuer: a pre-existing iss must be dropped.
    result = _add_iss_to_redirect("https://c.example/cb?code=abc&iss=evil", "https://as.example")
    assert result.count("iss=") == 1
    assert "iss=https%3A%2F%2Fas.example" in result
    assert "evil" not in result


def test_add_iss_to_redirect_single_iss_across_query_and_fragment():
    # A query iss on a fragment (implicit/hybrid) response must not leave two iss values.
    result = _add_iss_to_redirect("https://c.example/cb?iss=evil#access_token=abc", "https://as.example")
    assert result.count("iss=") == 1
    assert "evil" not in result
    assert "iss=https%3A%2F%2Fas.example" in result


def test_add_iss_to_redirect_fragment():
    result = _add_iss_to_redirect("https://c.example/cb#access_token=abc", "https://as.example")
    assert result.startswith("https://c.example/cb#")
    assert "iss=https%3A%2F%2Fas.example" in result
    assert "?" not in result  # added to the fragment, not the query


@pytest.mark.usefixtures("oauth2_settings")
class TestMetadataGating(TestCase):
    def _metadata(self):
        response = self.client.get(reverse("oauth2_provider:oauth-server-metadata"))
        return json.loads(response.content)

    def test_advertises_insecure_by_default(self):
        data = self._metadata()
        self.assertIn("implicit", data["grant_types_supported"])
        self.assertIn("password", data["grant_types_supported"])
        self.assertIn("token", data["response_types_supported"])
        self.assertIn("plain", data["code_challenge_methods_supported"])
        self.assertNotIn("authorization_response_iss_parameter_supported", data)

    def test_hides_gated_behavior(self):
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT = True
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_PASSWORD_GRANT = True
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_PKCE_METHOD = True
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS = True
        data = self._metadata()
        self.assertNotIn("implicit", data["grant_types_supported"])
        self.assertNotIn("password", data["grant_types_supported"])
        self.assertNotIn("token", data["response_types_supported"])
        self.assertNotIn("plain", data["code_challenge_methods_supported"])
        self.assertTrue(data["authorization_response_iss_parameter_supported"])


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestOIDCDiscoveryGating(TestCase):
    """The OIDC discovery document must mirror the RFC 8414 metadata gating."""

    def _discovery(self):
        return json.loads(self.client.get("/o/.well-known/openid-configuration").content)

    def test_advertises_insecure_by_default(self):
        data = self._discovery()
        self.assertIn("token", data["response_types_supported"])
        self.assertIn("plain", data["code_challenge_methods_supported"])
        self.assertNotIn("authorization_response_iss_parameter_supported", data)

    def test_hides_gated_behavior(self):
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT = True
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_PKCE_METHOD = True
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS = True
        data = self._discovery()
        for implicit_rt in ("token", "id_token", "id_token token"):
            self.assertNotIn(implicit_rt, data["response_types_supported"])
        # Hybrid response types are not gated and remain advertised.
        self.assertIn("code id_token", data["response_types_supported"])
        self.assertNotIn("plain", data["code_challenge_methods_supported"])
        self.assertTrue(data["authorization_response_iss_parameter_supported"])


# ---------------------------------------------------------------------------
# Plaintext token storage gate
# ---------------------------------------------------------------------------
@pytest.mark.usefixtures("oauth2_settings")
class TestTokenStorageGate(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("to", "to@example.com", "123456")
        cls.application = Application.objects.create(
            name="cc",
            user=cls.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            client_secret=CLEARTEXT_SECRET,
        )

    def _get_token(self):
        data = {"grant_type": "client_credentials"}
        headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        response = self.client.post(reverse("oauth2_provider:token"), data=data, **headers)
        return json.loads(response.content)["access_token"]

    def test_plaintext_by_default(self):
        raw = self._get_token()
        at = AccessToken.objects.get(token_checksum=hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(at.token, raw)

    def test_hashed_when_gate_enabled(self):
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_TOKEN_STORAGE = True
        raw = self._get_token()
        expected_checksum = hashlib.sha256(raw.encode()).hexdigest()
        at = AccessToken.objects.get(token_checksum=expected_checksum)
        # The raw token is not persisted; the column is blank and only the hash is kept.
        self.assertEqual(at.token, "")
        self.assertEqual(at.token_checksum, expected_checksum)

    def test_hashed_token_still_authenticates(self):
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_TOKEN_STORAGE = True
        raw = self._get_token()
        request = RequestFactory().get("/fake-resource", HTTP_AUTHORIZATION="Bearer " + raw)
        request.user = self.user
        response = ResourceView.as_view()(request)
        self.assertEqual(response, "This is a protected resource")

    def test_raw_token_marker_cleared_after_save(self):
        # Hardening: the _raw_token stash exists only to compute token_checksum at
        # save time; it must not outlive the save (in-memory token exposure).
        from oauth2_provider.oauth2_validators import OAuth2Validator

        self.oauth2_settings.COMPLIANT_BCP_RFC9700_TOKEN_STORAGE = True
        at = AccessToken(expires=timezone.now() + timedelta(seconds=60), scope="read")
        OAuth2Validator()._set_token_value(at, "raw-secret-token")
        at.save()
        self.assertIsNone(at._raw_token)
        self.assertEqual(at.token, "")
        self.assertEqual(at.token_checksum, hashlib.sha256(b"raw-secret-token").hexdigest())

    def test_hashed_token_checksum_survives_resave(self):
        # Regression: re-saving a hashed token (e.g. via revoke()) must not recompute
        # token_checksum from the blank/hashed column and corrupt it.
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_TOKEN_STORAGE = True
        raw = self._get_token()
        checksum = hashlib.sha256(raw.encode()).hexdigest()
        at = AccessToken.objects.get(token_checksum=checksum)
        at.expires = at.expires + timedelta(seconds=1)
        at.save()
        at.refresh_from_db()
        self.assertEqual(at.token_checksum, checksum)


@pytest.mark.usefixtures("oauth2_settings")
class TestHashedRefreshTokenRotation(TestCase):
    """Rotation revokes the previous refresh token (which re-saves it)."""

    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("ro", "ro@example.com", "123456")
        cls.application = Application.objects.create(
            name="rot",
            user=cls.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
            client_secret=CLEARTEXT_SECRET,
        )

    def test_rotation_with_hashed_storage(self):
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_TOKEN_STORAGE = True
        headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        first = self.client.post(
            reverse("oauth2_provider:token"),
            data={"grant_type": "password", "username": "ro", "password": "123456"},
            **headers,
        )
        refresh = json.loads(first.content)["refresh_token"]
        # Using the refresh token rotates it and revokes the old one (a re-save that
        # previously corrupted the checksum). The refresh must succeed.
        second = self.client.post(
            reverse("oauth2_provider:token"),
            data={"grant_type": "refresh_token", "refresh_token": refresh},
            **headers,
        )
        self.assertEqual(second.status_code, 200)
        self.assertIn("access_token", json.loads(second.content))


@pytest.mark.usefixtures("oauth2_settings")
class TestHashedNonRotatingRefreshToken(TestCase):
    """Non-rotating refresh reuses request.refresh_token, which is blank at rest
    under hashed storage unless the raw presented token is used."""

    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("nr", "nr@example.com", "123456")
        cls.application = Application.objects.create(
            name="nonrot",
            user=cls.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
            client_secret=CLEARTEXT_SECRET,
        )

    def test_non_rotating_refresh_with_hashed_storage(self):
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_TOKEN_STORAGE = True
        self.oauth2_settings.ROTATE_REFRESH_TOKEN = False
        headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        first = self.client.post(
            reverse("oauth2_provider:token"),
            data={"grant_type": "password", "username": "nr", "password": "123456"},
            **headers,
        )
        refresh = json.loads(first.content)["refresh_token"]
        second = self.client.post(
            reverse("oauth2_provider:token"),
            data={"grant_type": "refresh_token", "refresh_token": refresh},
            **headers,
        )
        self.assertEqual(second.status_code, 200)
        # Non-rotating: the same (non-blank) refresh token is returned.
        self.assertEqual(json.loads(second.content)["refresh_token"], refresh)


# ---------------------------------------------------------------------------
# Deploy-time system checks
# ---------------------------------------------------------------------------
@pytest.mark.usefixtures("oauth2_settings")
class TestDeployChecks(TestCase):
    def _run(self):
        from oauth2_provider.checks import validate_bcp_configuration

        return validate_bcp_configuration(None)

    def test_warns_on_insecure_defaults(self):
        ids = {m.id for m in self._run()}
        for expected in [
            "oauth2_provider.W001",
            "oauth2_provider.W002",
            "oauth2_provider.W003",
            "oauth2_provider.W004",
            "oauth2_provider.W005",
            "oauth2_provider.W006",
            "oauth2_provider.W007",
            "oauth2_provider.W008",
        ]:
            self.assertIn(expected, ids)

    def test_clean_when_compliant(self):
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT = True
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_PASSWORD_GRANT = True
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_PKCE_METHOD = True
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_ACCESS_TOKEN_TRANSPORT = True
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS = True
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_TOKEN_STORAGE = True
        self.oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION = True
        self.oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES = ["https"]
        self.assertEqual(self._run(), [])

    def test_error_on_hashed_storage_with_grace_period(self):
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_TOKEN_STORAGE = True
        self.oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS = 60
        errors = [m for m in self._run() if isinstance(m, checks.Error)]
        self.assertEqual([m.id for m in errors], ["oauth2_provider.E001"])


@pytest.mark.usefixtures("oauth2_settings")
class TestConfigValidationGates(TestCase):
    """The config-validation gates set severity for the canonical settings: an
    insecure value warns while the gate is False and errors once it is True."""

    def _run(self):
        from oauth2_provider.checks import validate_bcp_configuration

        return validate_bcp_configuration(None)

    def _ids(self, kind):
        return {m.id for m in self._run() if isinstance(m, kind)}

    def test_refresh_replay_warns_then_errors(self):
        # Default: REFRESH_TOKEN_REUSE_PROTECTION=False, gate False -> W007.
        self.assertIn("oauth2_provider.W007", self._ids(checks.Warning))
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_REFRESH_TOKEN = True
        self.assertIn("oauth2_provider.E002", self._ids(checks.Error))
        # A compliant value is silent in either gate position.
        self.oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION = True
        self.assertNotIn("oauth2_provider.E002", self._ids(checks.Error))
        self.assertNotIn("oauth2_provider.W007", self._ids(checks.Warning))

    def test_http_redirect_warns_then_errors(self):
        self.assertIn("oauth2_provider.W008", self._ids(checks.Warning))
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_REDIRECT_URI_SCHEME = True
        self.assertIn("oauth2_provider.E003", self._ids(checks.Error))
        self.oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES = ["https"]
        self.assertNotIn("oauth2_provider.E003", self._ids(checks.Error))

    def test_wildcard_redirect_warns_then_errors(self):
        # Default ALLOW_URI_WILDCARDS=False is compliant -> silent.
        self.assertNotIn("oauth2_provider.W009", self._ids(checks.Warning))
        self.oauth2_settings.ALLOW_URI_WILDCARDS = True
        self.assertIn("oauth2_provider.W009", self._ids(checks.Warning))
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_REDIRECT_URI_MATCHING = True
        self.assertIn("oauth2_provider.E004", self._ids(checks.Error))

    def test_pkce_optional_warns_then_errors(self):
        # Default PKCE_REQUIRED=True is compliant -> silent.
        self.assertNotIn("oauth2_provider.W010", self._ids(checks.Warning))
        self.oauth2_settings.PKCE_REQUIRED = False
        self.assertIn("oauth2_provider.W010", self._ids(checks.Warning))
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_PKCE_REQUIRED = True
        self.assertIn("oauth2_provider.E005", self._ids(checks.Error))

    def test_callable_pkce_required_is_not_flagged(self):
        self.oauth2_settings.PKCE_REQUIRED = lambda client_id: False
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_PKCE_REQUIRED = True
        self.assertNotIn("oauth2_provider.W010", self._ids(checks.Warning))
        self.assertNotIn("oauth2_provider.E005", self._ids(checks.Error))
