from datetime import datetime, timedelta, timezone
from unittest import mock
from urllib.parse import urlencode

import django.http.response
import pytest
from django import http
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django.urls import reverse

import oauth2_provider.models
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_device_grant_model,
    get_refresh_token_model,
)
from oauth2_provider.utils import set_oauthlib_user_to_device_request_user

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()
AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()
UserModel = get_user_model()
DeviceModel: oauth2_provider.models.DeviceGrant = get_device_grant_model()


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

    def tearDown(self):
        DeviceModel.objects.all().delete()
        return super().tearDown()


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
        assert DeviceModel.objects.get(device_code="abc").status == DeviceModel.AUTHORIZATION_PENDING

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
        This is a full user journey test.

        The device initiates the flow by calling the /device-authorization endpoint and starts
        polling the /authorize endpoint getting back error until the user approves in the
        browser.

        In the meantime, the user visits the /device endpoint in their browsers to submit the
        user code and approve, after which the /authorize returns the tokens to the device.
        """

        # -----------------------
        #  0: Setup device flow, where the device sends an authorization request and
        #  starts polling. The polling will fail because the user has not approved yet
        # -----------------------
        self.oauth2_settings.OAUTH_DEVICE_VERIFICATION_URI = "example.com/device"
        self.oauth2_settings.OAUTH_DEVICE_USER_CODE_GENERATOR = lambda: "xyz"
        self.oauth2_settings.OAUTH_PRE_TOKEN_VALIDATION = [set_oauthlib_user_to_device_request_user]

        request_data: dict[str, str] = {
            "client_id": self.application.client_id,
        }
        request_as_x_www_form_urlencoded: str = urlencode(request_data)

        device_authorization_response: http.response.JsonResponse = self.client.post(
            reverse("oauth2_provider:device-authorization"),
            data=request_as_x_www_form_urlencoded,
            content_type="application/x-www-form-urlencoded",
        )

        assert device_authorization_response.__getitem__("content-type") == "application/json"
        device = DeviceModel.objects.get(device_code="abc")
        self.assertJSONEqual(
            raw=device_authorization_response.content,
            expected_data={
                "verification_uri": "example.com/device",
                "expires_in": 1800,
                "user_code": device.user_code,
                "device_code": device.device_code,
                "interval": 5,
            },
        )

        # Device polls /token and gets back error because the user hasn't approved yet
        token_payload = {
            "device_code": device.device_code,
            "client_id": self.application.client_id,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        }

        token_response: http.response.JsonResponse = self.client.post(
            "/o/token/",
            data=urlencode(token_payload),
            content_type="application/x-www-form-urlencoded",
        )
        # TokenView should always respond with application/json as it's meant to be
        # consumed by devices.
        assert token_response.__getitem__("content-type") == "application/json"
        assert token_response.status_code == 400
        self.assertJSONEqual(raw=token_response.content, expected_data={"error": "authorization_pending"})

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
        self.assertContains(
            self.client.post(reverse("oauth2_provider:device"), data={"user_code": "invalid_code"}),
            status_code=200,
            text="Incorrect user code",
            count=1,
        )

        # Note: the device not being in the expected test covered in the other tests

        # 1.1.1: user submits valid user code
        device_confirm_url = reverse(
            "oauth2_provider:device-confirm",
            kwargs={"user_code": "xyz", "client_id": self.application.client_id},
        )

        self.assertRedirects(
            response=self.client.post(
                reverse("oauth2_provider:device"),
                data={"user_code": "xyz"},
            ),
            expected_url=device_confirm_url,
        )

        # --------------------------------------------------------------------------------
        # 2: We redirect to the accept/deny form (the user is still in their browser)
        #  and approves
        # --------------------------------------------------------------------------------
        device_grant_status_url = reverse(
            "oauth2_provider:device-grant-status",
            kwargs={"user_code": "xyz", "client_id": self.application.client_id},
        )

        self.assertRedirects(
            response=self.client.post(device_confirm_url, data={"action": "accept"}),
            expected_url=device_grant_status_url,
        )

        # --------------------------------------------------------------------------------
        # 3: We redirect to the device grant status page (the user is still in their browser)
        # --------------------------------------------------------------------------------
        self.assertContains(
            response=self.client.get(device_grant_status_url),
            text="Device Authorized",
            count=1,
        )

        device = DeviceModel.objects.get(device_code="abc")
        assert device.status == device.AUTHORIZED

        # -------------------------
        # 4: Device polls /token successfully
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
        # TokenView should always respond with application/json as it's meant to be
        # consumed by devices.
        assert token_response.__getitem__("content-type") == "application/json"
        assert token_response.status_code == 200

        token_data = token_response.json()
        assert token_data == {
            "access_token": mock.ANY,
            "expires_in": 36000,
            "token_type": "Bearer",
            "scope": "read write",
            "refresh_token": mock.ANY,
        }

        # ensure the access token and refresh token have the same user as the device that just authenticated
        access_token: oauth2_provider.models.AccessToken = AccessToken.objects.get(
            token=token_data["access_token"]
        )
        assert access_token.user == device.user

        refresh_token: oauth2_provider.models.RefreshToken = RefreshToken.objects.get(
            token=token_data["refresh_token"]
        )
        assert refresh_token.user == device.user

    def test_user_denies_access(self):
        """
        This test asserts the when the user denies access, the state of the grant is saved
        and the user is redirected to the page where they can see the "denied" state.

        The /token View returning the appropriate message for the "denied" state is covered
        in test_token_view_returns_error_if_device_in_invalid_state.
        """
        UserModel.objects.create_user(
            username="test_user_device_flow",
            email="test_device@example.com",
            password="password123",
        )
        self.client.login(username="test_user_device_flow", password="password123")

        device = DeviceModel(
            client_id="client_id",
            device_code="device_code",
            user_code="user_code",
            scope="scope",
            expires=datetime.now() + timedelta(days=1),
            status=DeviceModel.AUTHORIZATION_PENDING,
        )
        device.save()

        device_confirm_url = reverse(
            "oauth2_provider:device-confirm",
            kwargs={"user_code": "user_code", "client_id": "client_id"},
        )

        device_grant_status_url = reverse(
            "oauth2_provider:device-grant-status",
            kwargs={"user_code": "user_code", "client_id": "client_id"},
        )

        self.assertRedirects(
            response=self.client.post(device_confirm_url, data={"action": "deny"}),
            expected_url=device_grant_status_url,
        )

        device.refresh_from_db()
        assert device.status == device.DENIED

    def test_device_confirm_view_returns_400_on_incorrect_action(self):
        """
        This test asserts that the confirm view returns 400 if action is not
        "accept" or "deny".
        """
        UserModel.objects.create_user(
            username="test_user_device_flow",
            email="test_device@example.com",
            password="password123",
        )
        self.client.login(username="test_user_device_flow", password="password123")

        device = DeviceModel(
            client_id="client_id",
            device_code="device_code",
            user_code="user_code",
            scope="scope",
            expires=datetime.now() + timedelta(days=1),
            status=DeviceModel.AUTHORIZATION_PENDING,
        )
        device.save()

        device_confirm_url = reverse(
            "oauth2_provider:device-confirm",
            kwargs={"user_code": "user_code", "client_id": "client_id"},
        )
        response = self.client.post(device_confirm_url, data={"action": "inccorect_action"})

        assert response.status_code == 400

    def test_device_flow_authorization_device_invalid_state_returns_form_error(self):
        """
        This test asserts that only devices in the expected state (authorization-pending)
        can be approved/denied by the user.
        """

        UserModel.objects.create_user(
            username="test_user_device_flow",
            email="test_device@example.com",
            password="password123",
        )
        self.client.login(username="test_user_device_flow", password="password123")

        device = DeviceModel(
            client_id="client_id",
            device_code="device_code",
            user_code="user_code",
            scope="scope",
            expires=datetime.now() + timedelta(days=1),
        )
        device.save()

        # This simulates pytest.mark.parameterize, which unfortunately does not work with unittest
        # and consequently with Django TestCase.
        for invalid_state in ["authorized", "denied", "LOL_status"]:
            # Set the device into an incorrect state.
            device.status = invalid_state
            device.save(update_fields=["status"])

            self.assertContains(
                response=self.client.post(
                    reverse("oauth2_provider:device"),
                    data={"user_code": "user_code"},
                ),
                status_code=200,
                text="User code has already been used",
                count=1,
            )

    def test_device_flow_authorization_device_expired_returns_form_error(self):
        """
        This test asserts that only devices in the expected state (authorization-pending)
        can be approved/denied by the user.
        """

        UserModel.objects.create_user(
            username="test_user_device_flow",
            email="test_device@example.com",
            password="password123",
        )
        self.client.login(username="test_user_device_flow", password="password123")

        device = DeviceModel(
            client_id="client_id",
            device_code="device_code",
            user_code="user_code",
            scope="scope",
            expires=datetime.now() + timedelta(seconds=-1),  # <- essentially expired
        )
        device.save()

        self.assertContains(
            response=self.client.post(
                reverse("oauth2_provider:device"),
                data={"user_code": "user_code"},
            ),
            status_code=200,
            text="Expired user code",
            count=1,
        )

    def test_token_view_returns_error_if_device_in_invalid_state(self):
        """
        This test asserts that the token view returns the appropriate errors as specified
        in https://datatracker.ietf.org/doc/html/rfc8628#section-3.5, in case the device
        has not yet been approved by the user.
        """

        device = DeviceModel(
            client_id="client_id",
            device_code="device_code",
            user_code="user_code",
            scope="scope",
            expires=datetime.now() + timedelta(seconds=60),
        )
        device.save()

        token_payload = {
            "device_code": "device_code",
            "client_id": "client_id",
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        }

        testcases = [
            ("authorization-pending", '{"error": "authorization_pending"}', 400),
            ("expired", '{"error": "expired_token"}', 400),
            ("denied", '{"error": "access_denied"}', 400),
            ("LOL_status", '{"error": "internal_error"}', 500),
        ]
        for invalid_state, expected_error_message, expected_error_code in testcases:
            device.status = invalid_state
            device.save(update_fields=["status"])

            response = self.client.post(
                "/o/token/",
                data=urlencode(token_payload),
                content_type="application/x-www-form-urlencoded",
            )
            self.assertContains(
                response=response,
                status_code=expected_error_code,
                text=expected_error_message,
                count=1,
            )
            # TokenView should always respond with application/json as it's meant to be
            # consumed by devices.
            self.assertEqual(response.__getitem__("content-type"), "application/json")

    def test_token_view_returns_404_error_if_device_not_found(self):
        device = DeviceModel(
            client_id="client_id",
            device_code="device_code",
            user_code="user_code",
            scope="scope",
            expires=datetime.now() + timedelta(seconds=60),
        )
        device.save()

        token_payload = {
            "device_code": "another_device_code",
            "client_id": "client_id",
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        }

        response = self.client.post(
            "/o/token/",
            data=urlencode(token_payload),
            content_type="application/x-www-form-urlencoded",
        )
        self.assertContains(
            response=response,
            status_code=404,
            text="device_not_found",
            count=1,
        )
        # TokenView should always respond with application/json as it's meant to be
        # consumed by devices.
        self.assertEqual(response.__getitem__("content-type"), "application/json")

    def test_token_view_status_equals_what_oauthlib_token_response_method_returns(self):
        """
        Tests the use case where oauthlib create_token_response returns a status different
        than 200.
        """

        class MockOauthlibCoreClass:
            def create_token_response(self, _):
                return "url", {"headers_are_ignored": True}, '{"Key": "Value"}', 299

        device = DeviceModel(
            client_id="client_id",
            device_code="device_code",
            user_code="user_code",
            scope="scope",
            expires=datetime.now() + timedelta(seconds=60),
            status="authorized",
        )
        device.save()

        token_payload = {
            "device_code": "device_code",
            "client_id": "client_id",
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        }

        with mock.patch(
            "oauth2_provider.views.mixins.OAuthLibMixin.get_oauthlib_core", MockOauthlibCoreClass
        ):
            response = self.client.post(
                "/o/token/",
                data=urlencode(token_payload),
                content_type="application/x-www-form-urlencoded",
            )

        self.assertEqual(response["content-type"], "application/json")
        self.assertContains(
            response=response,
            status_code=299,
            text='{"Key": "Value"}',
            count=1,
        )
        assert not response.has_header("headers_are_ignored")

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

    def test_missing_client_id(self):
        """
        Ensure the correct error is returned when the client id is missing.
        """
        request_data: dict[str, str] = {
            "not_client_id": "client_id_that_does_not_exist",
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
            "error_description": "Missing client_id parameter.",
        }

    def test_device_confirm_and_user_code_views_require_login(self):
        URLs = [
            reverse("oauth2_provider:device-confirm", kwargs={"user_code": None, "client_id": "abc"}),
            reverse("oauth2_provider:device-confirm", kwargs={"user_code": "abc", "client_id": "abc"}),
            reverse("oauth2_provider:device"),
        ]

        for url in URLs:
            r = self.client.get(url)
            assert r.status_code == 302
            assert r["Location"] == f"{settings.LOGIN_URL}?next={url}"

            r = self.client.post(url)
            assert r.status_code == 302
            assert r["Location"] == f"{settings.LOGIN_URL}?next={url}"

    def test_device_confirm_view_GET_returns_404_when_device_does_not_exist(self):
        UserModel.objects.create_user(
            username="test_user_device_flow",
            email="test_device@example.com",
            password="password123",
        )
        self.client.login(username="test_user_device_flow", password="password123")

        device = DeviceModel(
            client_id="client_id",
            device_code="device_code",
            user_code="user_code",
            scope="scope",
            expires=datetime.now(),
        )
        device.save()

        self.assertContains(
            response=self.client.get(
                reverse(
                    "oauth2_provider:device-confirm",
                    kwargs={"user_code": "not_user_code", "client_id": "not_client_id"},
                )
            ),
            status_code=404,
            text="The requested resource was not found on this server.",
        )

        # Asserts for valid user_code and client_id but invalid states
        for invalid_state in ["authorized", "denied", "expired"]:
            device.status = invalid_state
            device.save(update_fields=["status"])

            self.assertContains(
                response=self.client.get(
                    reverse(
                        "oauth2_provider:device-confirm",
                        kwargs={"user_code": "not_user_code", "client_id": "client_id"},
                    )
                ),
                status_code=404,
                text="The requested resource was not found on this server.",
            )

    def test_device_confirm_view_POST_returns_404_when_device_does_not_exist(self):
        UserModel.objects.create_user(
            username="test_user_device_flow",
            email="test_device@example.com",
            password="password123",
        )
        self.client.login(username="test_user_device_flow", password="password123")

        device = DeviceModel(
            client_id="client_id",
            device_code="device_code",
            user_code="user_code",
            scope="scope",
            expires=datetime.now(),
        )
        device.save()

        self.assertContains(
            response=self.client.post(
                reverse(
                    "oauth2_provider:device-confirm",
                    kwargs={"user_code": "not_user_code", "client_id": "client_id"},
                ),
                data={"action": "accept"},
            ),
            status_code=404,
            text="The requested resource was not found on this server.",
            count=1,
        )

        # Asserts for valid user_code and client_id but invalid states
        for invalid_state in ["authorized", "denied", "expired"]:
            device.status = invalid_state
            device.save(update_fields=["status"])

            self.assertContains(
                response=self.client.post(
                    reverse(
                        "oauth2_provider:device-confirm",
                        kwargs={"user_code": "user_code", "client_id": "client_id"},
                    ),
                    data={"action": "accept"},
                ),
                status_code=404,
                text="The requested resource was not found on this server.",
                count=1,
            )

    def test_device_is_expired_method_sets_status_to_expired_if_deadline_passed(self):
        device = DeviceModel(
            client_id="client_id",
            device_code="device_code",
            user_code="user_code",
            scope="scope",
            expires=datetime.now(tz=timezone.utc) + timedelta(seconds=-1),  # <- essentially expired
        )
        device.save()

        assert device.status == device.AUTHORIZATION_PENDING  # default value

        # call is_expired() which should update the state
        is_expired = device.is_expired()

        assert is_expired
        assert device.status == device.EXPIRED

        # calling again is_expired() should return true and not change the state
        is_expired = device.is_expired()

        assert is_expired
        assert device.status == device.EXPIRED
