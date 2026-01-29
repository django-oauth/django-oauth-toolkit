import json
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django.urls import reverse

from oauth2_provider.models import get_application_model

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header


Application = get_application_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"

# CORS is allowed for https only
CLIENT_URI = "https://example.org"

CLIENT_URI_HTTP = "http://example.org"


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.DEFAULT_SCOPES_RW)
class TestTokenEndpointCors(TestCase):
    """
    Test that CORS headers can be managed by OAuthLib.
    The objective is: http request 'Origin' header should be passed to OAuthLib
    """

    factory = RequestFactory()

    @classmethod
    def setUpTestData(cls):
        cls.test_user = UserModel.objects.create_user("test_user", "test@example.com", "123456")
        cls.dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")

        cls.application = Application.objects.create(
            name="Test Application",
            redirect_uris=CLIENT_URI,
            user=cls.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
            allowed_origins=CLIENT_URI,
        )

    def setUp(self):
        self.oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES = ["https"]
        self.oauth2_settings.PKCE_REQUIRED = False

    def test_valid_origin_with_https(self):
        """
        Test that /token endpoint has Access-Control-Allow-Origin
        """
        authorization_code = self._get_authorization_code()

        # exchange authorization code for a valid access token
        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": CLIENT_URI,
        }

        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        auth_headers["HTTP_ORIGIN"] = CLIENT_URI
        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)

        content = json.loads(response.content.decode("utf-8"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Access-Control-Allow-Origin"], CLIENT_URI)

        token_request_data = {
            "grant_type": "refresh_token",
            "refresh_token": content["refresh_token"],
            "scope": content["scope"],
        }
        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Access-Control-Allow-Origin"], CLIENT_URI)

    def test_valid_origin_no_https(self):
        """
        Test that CORS is not allowed if origin uri does not have https:// schema
        """
        authorization_code = self._get_authorization_code()

        # exchange authorization code for a valid access token
        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": CLIENT_URI,
        }

        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        auth_headers["HTTP_ORIGIN"] = CLIENT_URI_HTTP
        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.has_header("Access-Control-Allow-Origin"))

    def test_origin_not_from_allowed_origins(self):
        """
        Test that /token endpoint does not have Access-Control-Allow-Origin
        when request origin is not in Application.allowed_origins
        """
        authorization_code = self._get_authorization_code()

        # exchange authorization code for a valid access token
        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": CLIENT_URI,
        }

        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        auth_headers["HTTP_ORIGIN"] = "https://another_example.org"
        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.has_header("Access-Control-Allow-Origin"))

    def test_no_origin(self):
        """
        Test that /token endpoint does not have Access-Control-Allow-Origin
        """
        authorization_code = self._get_authorization_code()

        # exchange authorization code for a valid access token
        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": CLIENT_URI,
        }

        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)
        # No CORS headers, because request did not have Origin
        self.assertFalse(response.has_header("Access-Control-Allow-Origin"))

    def _get_authorization_code(self):
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "https://example.org",
            "response_type": "code",
            "allow": True,
        }
        response = self.client.post(reverse("oauth2_provider:authorize"), data=authcode_data)
        query_dict = parse_qs(urlparse(response["Location"]).query)
        return query_dict["code"].pop()
