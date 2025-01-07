from unittest import mock
from urllib.parse import urlencode

import django.http.response
import pytest
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django.urls import reverse

import oauth2_provider.models
from oauth2_provider.models import get_access_token_model, get_application_model, get_device_model

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()
DeviceModel: oauth2_provider.models.Device = get_device_model()


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.DEFAULT_SCOPES_RW)
class DeviceFlowBaseTestCase(TestCase):
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
            client_secret="abcdefghijklmnopqrstuvwxyz1234567890",
        )


class TestDeviceFlow(DeviceFlowBaseTestCase):
    """
    The first 2 tests test the device flow in order
    how the device flow works
    """

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "abc",
    )
    def test_device_flow_authorization_initiation(self):
        """
        Tests the initial stage of the flow when the device sends its device authorization
        request to the authorization server.

        Device Authorization Request(https://datatracker.ietf.org/doc/html/rfc8628#section-3.1)

        This request shape:
            POST /device_authorization HTTP/1.1
            Host: server.example.com
            Content-Type: application/x-www-form-urlencoded

            client_id=1406020730&scope=example_scope

        Should respond with this response shape:
            Device Authorization Response (https://datatracker.ietf.org/doc/html/rfc8628#section-3.2)
                {
                "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
                "user_code": "WDJB-MJHT",
                "verification_uri": "https://example.com/device",
                "expires_in": 1800,
                "interval": 5
              }
        """

        self.oauth2_settings.OAUTH_DEVICE_VERIFICATION_URI = "example.com/device"
        self.oauth2_settings.OAUTH_DEVICE_USER_CODE_GENERATOR = lambda: "xyz"

        request_data: dict[str, str] = {
            "client_id": self.application.client_id,
        }
        request_as_x_www_form_urlencoded: str = urlencode(request_data)

        response: django.http.response.JsonResponse = self.client.post(
            reverse("oauth2_provider:device-authorization"),
            data=request_as_x_www_form_urlencoded,
            content_type="application/x-www-form-urlencoded",
        )

        assert response.status_code == 200

        # let's make sure the device was created in the db
        assert DeviceModel.objects.get(device_code="abc")

        assert response.json() == {
            "verification_uri": "example.com/device",
            "expires_in": 1800,
            "user_code": "xyz",
            "device_code": "abc",
            "interval": 5,
        }

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "abc",
    )
    def test_device_polling_interval_can_be_changed(self):
        """
        Tests the device polling rate(interval) can be changed to something other than the default
        of 5 seconds.
        """

        self.oauth2_settings.OAUTH_DEVICE_VERIFICATION_URI = "example.com/device"
        self.oauth2_settings.OAUTH_DEVICE_USER_CODE_GENERATOR = lambda: "xyz"

        self.oauth2_settings.DEVICE_FLOW_INTERVAL = 10

        request_data: dict[str, str] = {
            "client_id": self.application.client_id,
        }
        request_as_x_www_form_urlencoded: str = urlencode(request_data)

        response: django.http.response.JsonResponse = self.client.post(
            reverse("oauth2_provider:device-authorization"),
            data=request_as_x_www_form_urlencoded,
            content_type="application/x-www-form-urlencoded",
        )

        assert response.status_code == 200

        assert response.json() == {
            "verification_uri": "example.com/device",
            "expires_in": 1800,
            "user_code": "xyz",
            "device_code": "abc",
            "interval": 10,
        }

    def test_incorrect_client_id_sent(self):
        """
        Ensure the correct error is returned when an invalid client is sent
        """
        request_data: dict[str, str] = {
            "client_id": "client_id_that_does_not_exist",
        }
        request_as_x_www_form_urlencoded: str = urlencode(request_data)

        response: django.http.response.JsonResponse = self.client.post(
            reverse("oauth2_provider:device-authorization"),
            data=request_as_x_www_form_urlencoded,
            content_type="application/x-www-form-urlencoded",
        )

        assert response.status_code == 400

        assert response.json() == {
            "error": "invalid_request",
            "error_description": "Invalid client_id parameter value.",
        }
