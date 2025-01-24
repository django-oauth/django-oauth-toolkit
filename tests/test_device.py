from unittest import mock
from urllib.parse import urlencode

import django.http.response
import pytest
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django.urls import reverse

import oauth2_provider.models
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_device_model,
    get_refresh_token_model,
)
from oauth2_provider.utils import set_oauthlib_user_to_device_request_user

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()
AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()
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
            authorization_grant_type=Application.GRANT_DEVICE_CODE,
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
    def test_device_flow_authorization_user_code_confirm_and_access_token(self):
        """
        1. User visits the /device endpoint in their browsers and submits the user code

        the device and approve deny actions occur concurrently
        (i.e the device is polling the token endpoint while the user
        either approves or denies the device)

        -2(3)-. User approves or denies the device
        -3(2)-. Device polls the /token endpoint
        """

        # -----------------------
        #  0: Setup device flow
        # -----------------------
        self.oauth2_settings.OAUTH_DEVICE_VERIFICATION_URI = "example.com/device"
        self.oauth2_settings.OAUTH_DEVICE_USER_CODE_GENERATOR = lambda: "xyz"
        self.oauth2_settings.OAUTH_DEVICE_USER_CODE_GENERATOR = lambda: "xyz"
        self.oauth2_settings.OAUTH_PRE_TOKEN_VALIDATION = [set_oauthlib_user_to_device_request_user]

        request_data: dict[str, str] = {
            "client_id": self.application.client_id,
        }
        request_as_x_www_form_urlencoded: str = urlencode(request_data)

        django.http.response.JsonResponse = self.client.post(
            reverse("oauth2_provider:device-authorization"),
            data=request_as_x_www_form_urlencoded,
            content_type="application/x-www-form-urlencoded",
        )

        # /device and /device_confirm require a user to be logged in
        # to access it
        UserModel.objects.create_user(
            username="test_user_device_flow",
            email="test_device@example.com",
            password="password123",
        )
        self.client.login(username="test_user_device_flow", password="password123")

        # --------------------------------------------------------------------------------
        #  1. User visits the /device endpoint in their browsers and submits the user code
        #  submits wrong code then right code
        # --------------------------------------------------------------------------------

        # 1. User visits the /device endpoint in their browsers and submits the user code
        # (GET Request to load it)
        get_response = self.client.get(reverse("oauth2_provider:device"))
        assert get_response.status_code == 200
        assert "form" in get_response.context  # Ensure the form is rendered in the context

        # 1.1.0  User visits the /device endpoint in their browsers and submits wrong user code
        with pytest.raises(oauth2_provider.models.Device.DoesNotExist):
            self.client.post(
                reverse("oauth2_provider:device"),
                data={"user_code": "invalid_code"},
            )

        # 1.1.1: user submits valid user code
        post_response_valid = self.client.post(
            reverse("oauth2_provider:device"),
            data={"user_code": "xyz"},
        )

        device_confirm_url = reverse("oauth2_provider:device-confirm", kwargs={"device_code": "abc"})
        assert post_response_valid.status_code == 308  # Ensure it redirects with 308 status
        assert post_response_valid["Location"] == device_confirm_url

        # --------------------------------------------------------------------------------
        # 2: We redirect to the accept/deny form (the user is still in their browser)
        #  and approves
        # --------------------------------------------------------------------------------
        get_confirm = self.client.get(device_confirm_url)
        assert get_confirm.status_code == 200

        approve_response = self.client.post(device_confirm_url, data={"action": "accept"})
        assert approve_response.status_code == 200
        assert approve_response.content.decode() == "approved"

        device = DeviceModel.objects.get(device_code="abc")
        assert device.status == device.AUTHORIZED

        # -------------------------
        # 3: Device polls /token
        # -------------------------
        token_payload = {
            "device_code": device.device_code,
            "client_id": self.application.client_id,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        }

        token_response = self.client.post(
            "/o/token/",
            data=urlencode(token_payload),
            content_type="application/x-www-form-urlencoded",
        )

        assert token_response.status_code == 200

        token_data = token_response.json()

        assert "access_token" in token_data
        assert token_data["token_type"].lower() == "bearer"
        assert "scope" in token_data

        # ensure the access token and refresh token have the same user as the device that just authenticated
        access_token: oauth2_provider.models.AccessToken = AccessToken.objects.get(
            token=token_data["access_token"]
        )
        assert access_token.user == device.user

        refresh_token: oauth2_provider.models.RefreshToken = RefreshToken.objects.get(
            token=token_data["refresh_token"]
        )
        assert refresh_token.user == device.user

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
