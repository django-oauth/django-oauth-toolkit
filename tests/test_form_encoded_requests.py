"""
Tests for ``REQUIRE_FORM_ENCODED_REQUEST_BODY`` (issue #657).

The OAuth 2.0 endpoints this library serves take the parameters comprising the request
in an ``application/x-www-form-urlencoded`` body. Enforcement is opt-in: with the setting
at its ``False`` default every endpoint keeps its previous behavior, and with it ``True``
a POST sent with any other media type is answered with HTTP 415.
"""

import json
import warnings
from urllib.parse import urlencode

import pytest
from django.contrib.auth import get_user_model
from django.core import checks
from django.urls import reverse

from oauth2_provider.core.backends_oauthlib import JSONOAuthLibCore
from oauth2_provider.core.checks import validate_request_body_configuration
from oauth2_provider.models import get_application_model

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header


Application = get_application_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"
FORM_ENCODED = "application/x-www-form-urlencoded"

# The endpoints whose request bodies the specifications define as form-encoded. Each is
# probed with a body that is valid for the endpoint had it been form-encoded, so the
# legacy (gate off) status is the endpoint's own error rather than an artifact of the
# probe.
FORM_ENCODED_ENDPOINTS = [
    ("oauth2_provider:token", {"grant_type": "client_credentials"}),
    ("oauth2_provider:revoke-token", {"token": "no-such-token"}),
    ("oauth2_provider:introspect", {"token": "no-such-token"}),
    ("oauth2_provider:device-authorization", {"client_id": "no-such-client"}),
    ("oauth2_provider:pushed-authorization-request", {"client_id": "no-such-client"}),
]


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.DEFAULT_SCOPES_RW)
class BaseTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")
        cls.application = Application.objects.create(
            name="test_form_encoding_app",
            user=cls.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            client_secret=CLEARTEXT_SECRET,
        )

    def token_request(self, **kwargs):
        kwargs.update(get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET))
        return self.client.post(reverse("oauth2_provider:token"), **kwargs)


class TestFormEncodingNotEnforced(BaseTest):
    """With the gate at its default the previously accepted bodies still work."""

    def test_json_body_keeps_legacy_error(self):
        """
        The behavior issue #657 reports: a JSON body leaves the view with no parameters,
        so the grant type the client did send is reported as unsupported. Preserved
        while the gate is off.
        """
        response = self.token_request(
            data=json.dumps({"grant_type": "client_credentials"}), content_type="application/json"
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "unsupported_grant_type")

    def test_multipart_body_is_accepted(self):
        """Django parses multipart into request.POST, so it works even though no spec allows it."""
        response = self.token_request(data={"grant_type": "client_credentials"})

        self.assertEqual(response.status_code, 200)

    def test_non_compliant_body_warns_about_the_coming_default(self):
        """The ``False`` default is deprecated, so each non-compliant body nags."""
        with self.assertWarns(DeprecationWarning) as caught:
            self.token_request(
                data=json.dumps({"grant_type": "client_credentials"}),
                content_type="application/json",
            )

        message = str(caught.warning)
        self.assertIn("REQUIRE_FORM_ENCODED_REQUEST_BODY", message)
        self.assertIn("django-oauth-toolkit 4.0", message)
        self.assertIn("application/json", message)

    def test_compliant_body_does_not_warn(self):
        """A deployment whose clients already comply sees nothing."""
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            response = self.token_request(
                data=urlencode({"grant_type": "client_credentials"}), content_type=FORM_ENCODED
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual([w for w in caught if "REQUIRE_FORM_ENCODED_REQUEST_BODY" in str(w.message)], [])

    def test_get_request_does_not_warn(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            self.client.get(reverse("oauth2_provider:introspect"), data={"token": "no-such-token"})

        self.assertEqual([w for w in caught if "REQUIRE_FORM_ENCODED_REQUEST_BODY" in str(w.message)], [])

    def test_no_endpoint_answers_415(self):
        for url_name, data in FORM_ENCODED_ENDPOINTS:
            with self.subTest(url_name=url_name):
                response = self.client.post(
                    reverse(url_name), data=json.dumps(data), content_type="application/json"
                )

                self.assertNotEqual(response.status_code, 415)


class TestFormEncodingEnforced(BaseTest):
    def setUp(self):
        super().setUp()
        self.oauth2_settings.REQUIRE_FORM_ENCODED_REQUEST_BODY = True

    def test_form_encoded_body_is_accepted(self):
        response = self.token_request(
            data=urlencode({"grant_type": "client_credentials"}), content_type=FORM_ENCODED
        )

        self.assertEqual(response.status_code, 200)

    def test_charset_parameter_is_accepted(self):
        """The media type is compared without its parameters, per RFC 9110 section 8.3."""
        response = self.token_request(
            data=urlencode({"grant_type": "client_credentials"}),
            content_type=f"{FORM_ENCODED}; charset=UTF-8",
        )

        self.assertEqual(response.status_code, 200)

    def test_json_body_is_rejected(self):
        response = self.token_request(
            data=json.dumps({"grant_type": "client_credentials"}), content_type="application/json"
        )

        self.assertEqual(response.status_code, 415)
        body = response.json()
        self.assertEqual(body["error"], "invalid_request")
        self.assertIn(FORM_ENCODED, body["error_description"])
        self.assertIn("RFC 6749 section 3.2", body["error_description"])
        self.assertIn("application/json", body["error_description"])

    def test_multipart_body_is_rejected(self):
        response = self.token_request(data={"grant_type": "client_credentials"})

        self.assertEqual(response.status_code, 415)
        self.assertIn("multipart/form-data", response.json()["error_description"])

    def test_missing_content_type_is_rejected(self):
        response = self.token_request(data=b"", content_type="")

        self.assertEqual(response.status_code, 415)
        self.assertIn("no Content-Type header", response.json()["error_description"])

    def test_every_form_encoded_endpoint_is_covered(self):
        for url_name, data in FORM_ENCODED_ENDPOINTS:
            with self.subTest(url_name=url_name):
                response = self.client.post(
                    reverse(url_name), data=json.dumps(data), content_type="application/json"
                )

                self.assertEqual(response.status_code, 415)
                self.assertEqual(response.json()["error"], "invalid_request")

    def test_get_requests_are_unaffected(self):
        """A GET carries its parameters in the query string, where no media type applies."""
        url = reverse("oauth2_provider:introspect")
        self.oauth2_settings.REQUIRE_FORM_ENCODED_REQUEST_BODY = False
        enforced_off = self.client.get(url, data={"token": "no-such-token"}).status_code

        self.oauth2_settings.REQUIRE_FORM_ENCODED_REQUEST_BODY = True
        response = self.client.get(url, data={"token": "no-such-token"})

        self.assertNotEqual(response.status_code, 415)
        self.assertEqual(response.status_code, enforced_off)

    def test_disabled_endpoint_still_reports_not_found(self):
        """The endpoint-enabled gate runs first: a disabled endpoint stays absent."""
        self.oauth2_settings.PAR_ENABLED = False

        response = self.client.post(
            reverse("oauth2_provider:pushed-authorization-request"),
            data=json.dumps({"client_id": "no-such-client"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 404)


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.DCR_SETTINGS)
class TestDynamicClientRegistrationIsNotCovered(TestCase):
    """RFC 7591 defines the registration request body as ``application/json``."""

    def test_json_registration_still_succeeds(self):
        self.oauth2_settings.REQUIRE_FORM_ENCODED_REQUEST_BODY = True
        user = UserModel.objects.create_user("dcr_user", "dcr@example.com", "pass")
        self.client.force_login(user)

        response = self.client.post(
            reverse("oauth2_provider:dcr-register"),
            data=json.dumps(
                {"redirect_uris": ["https://example.com/cb"], "grant_types": ["authorization_code"]}
            ),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 201)


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestUserInfoIsNotCovered(TestCase):
    """
    OpenID Connect Core section 5.3.1 allows a UserInfo POST whose only credential is the
    ``Authorization`` header, and RFC 6750 section 2.2 constrains a client that puts the
    access token in the body rather than the endpoint, so UserInfo is left alone.
    """

    def test_userinfo_post_is_not_rejected(self):
        self.oauth2_settings.REQUIRE_FORM_ENCODED_REQUEST_BODY = True

        response = self.client.post(
            reverse("oauth2_provider:user-info"), data="{}", content_type="application/json"
        )

        self.assertNotEqual(response.status_code, 415)


@pytest.mark.usefixtures("oauth2_settings")
class TestRequestBodyConfigurationCheck(TestCase):
    def test_no_error_by_default(self):
        self.assertEqual(validate_request_body_configuration(None), [])

    def test_no_error_when_only_the_gate_is_set(self):
        self.oauth2_settings.REQUIRE_FORM_ENCODED_REQUEST_BODY = True

        self.assertEqual(validate_request_body_configuration(None), [])

    def test_no_error_when_only_the_json_backend_is_set(self):
        self.oauth2_settings.OAUTH2_BACKEND_CLASS = JSONOAuthLibCore

        self.assertEqual(validate_request_body_configuration(None), [])

    def test_error_when_the_json_backend_can_never_be_reached(self):
        self.oauth2_settings.REQUIRE_FORM_ENCODED_REQUEST_BODY = True
        self.oauth2_settings.OAUTH2_BACKEND_CLASS = JSONOAuthLibCore

        errors = validate_request_body_configuration(None)

        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], checks.Error)
        self.assertEqual(errors[0].id, "oauth2_provider.E006")
