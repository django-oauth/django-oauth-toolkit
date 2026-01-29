import json
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import SuspiciousOperation
from django.test import RequestFactory
from django.urls import reverse
from django.views.generic import View
from oauthlib.oauth2 import BackendApplicationServer

from oauth2_provider.models import get_access_token_model, get_application_model
from oauth2_provider.oauth2_backends import OAuthLibCore
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauth2_provider.views import ProtectedResourceView
from oauth2_provider.views.mixins import OAuthLibMixin

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "abcdefghijklmnopqrstuvwxyz1234567890"


# mocking a protected resource view
class ResourceView(ProtectedResourceView):
    def get(self, request, *args, **kwargs):
        return "This is a protected resource"


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.DEFAULT_SCOPES_RW)
class BaseTest(TestCase):
    factory = RequestFactory()

    @classmethod
    def setUpTestData(cls):
        cls.test_user = UserModel.objects.create_user("test_user", "test@example.com", "123456")
        cls.dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")

        cls.application = Application.objects.create(
            name="test_client_credentials_app",
            user=cls.dev_user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            client_secret=CLEARTEXT_SECRET,
        )


class TestClientCredential(BaseTest):
    def test_client_credential_access_allowed(self):
        """
        Request an access token using Client Credential Flow with hashed secrets
        """
        self.assertNotEqual(self.application.client_secret, CLEARTEXT_SECRET)

        token_request_data = {
            "grant_type": "client_credentials",
        }
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        # secret mismatch should return a 401
        auth_headers = get_basic_auth_header(self.application.client_id, "not-the-secret")
        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 401)

    def test_client_credential_does_not_issue_refresh_token(self):
        token_request_data = {
            "grant_type": "client_credentials",
        }
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        self.assertNotIn("refresh_token", content)

    def test_client_credential_user_is_none_on_access_token(self):
        token_request_data = {"grant_type": "client_credentials"}
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        access_token = AccessToken.objects.get(token=content["access_token"])
        self.assertIsNone(access_token.user)


class ExampleView(OAuthLibMixin, View):
    server_class = BackendApplicationServer
    validator_class = OAuth2Validator
    oauthlib_backend_class = OAuthLibCore

    def get_scopes(self):
        return ["read", "write"]


class TestExtendedRequest(BaseTest):
    @classmethod
    def setUpClass(cls):
        cls.request_factory = RequestFactory()
        super().setUpClass()

    def test_extended_request(self):
        token_request_data = {
            "grant_type": "client_credentials",
        }
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        access_token = content["access_token"]

        # use token to access the resource
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + access_token,
        }

        request = self.request_factory.get("/fake-req", **auth_headers)
        request.user = "fake"

        test_view = ExampleView()
        self.assertIsInstance(test_view.get_server(), BackendApplicationServer)

        valid, r = test_view.verify_request(request)
        self.assertTrue(valid)
        self.assertIsNone(r.user)
        self.assertEqual(r.client, self.application)
        self.assertEqual(r.scopes, ["read", "write"])

    def test_raises_error_with_invalid_hex_in_query_params(self):
        request = self.request_factory.get("/fake-req?auth_token=%%7A")

        with pytest.raises(SuspiciousOperation):
            ExampleView().verify_request(request)

    @patch("oauth2_provider.views.mixins.OAuthLibMixin.get_oauthlib_core")
    def test_reraises_value_errors_as_is(self, patched_core):
        patched_core.return_value.verify_request.side_effect = ValueError("Generic error")

        request = self.request_factory.get("/fake-req")

        with pytest.raises(ValueError):
            ExampleView().verify_request(request)


class TestClientResourcePasswordBased(BaseTest):
    def test_client_resource_password_based(self):
        """
        Request an access token using Resource Owner Password Based flow
        """

        self.application.delete()
        self.application = Application.objects.create(
            name="test_client_credentials_app",
            user=self.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
            client_secret=CLEARTEXT_SECRET,
        )

        token_request_data = {"grant_type": "password", "username": "test_user", "password": "123456"}
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        access_token = content["access_token"]

        # use token to access the resource
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + access_token,
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ResourceView.as_view()
        response = view(request)
        self.assertEqual(response, "This is a protected resource")
