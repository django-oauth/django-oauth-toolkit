from datetime import datetime, timedelta, timezone
from unittest import mock, skipUnless
from urllib.parse import urlencode

import django.http.response
import pytest
from django import http
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import IntegrityError, models
from django.test import RequestFactory
from django.urls import reverse
from oauthlib.common import Request as OauthlibRequest
from oauthlib.oauth2.rfc6749.errors import InvalidGrantError
from oauthlib.oauth2.rfc8628.grant_types import DeviceCodeGrant

import oauth2_provider.models
from oauth2_provider.authorization_server.views.device import DeviceConfirmView
from oauth2_provider.core.compat import OAUTHLIB_VALIDATES_DEVICE_CODE
from oauth2_provider.core.utils import set_oauthlib_user_to_device_request_user
from oauth2_provider.models import (
    DeviceCodeResponse,
    DeviceRequest,
    create_device_grant,
    get_access_token_model,
    get_application_model,
    get_device_grant_model,
    get_refresh_token_model,
)
from oauth2_provider.oauth2_validators import OAuth2Validator

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()
AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()
UserModel = get_user_model()
DeviceModel: oauth2_provider.models.DeviceGrant = get_device_grant_model()

# A device authorization response as oauthlib before 4.0.1 returns it: without the
# ``scope`` key 4.0.1 added, so the view resolves the scope itself.
OAUTHLIB_RESPONSE_WITHOUT_SCOPE = {
    "verification_uri": "example.com/device",
    "expires_in": 1800,
    "user_code": "XYZ",
    "device_code": "abc",
    "interval": 5,
}


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

    def _run_full_device_flow_journey(
        self,
        *,
        scope: str | None,
        expected_confirm_scope_descriptions: list[str],
        expected_token_scope: str,
    ) -> None:
        """
        Runs the full device flow user journey from device authorization through token issuance.

        The device initiates the flow by calling the /device-authorization endpoint and starts
        polling the /token endpoint getting back errors until the user approves in the browser.

        In the meantime, the user visits the /device endpoint in their browsers to submit the
        user code and approve, after which the /token returns the tokens to the device.
        """

        # -----------------------
        #  0: Setup device flow, where the device sends an authorization request and
        #  starts polling. The polling will fail because the user has not approved yet
        # -----------------------
        self.oauth2_settings.OAUTH_DEVICE_VERIFICATION_URI = "example.com/device"
        self.oauth2_settings.OAUTH_DEVICE_USER_CODE_GENERATOR = lambda: "xyz"
        self.oauth2_settings.OAUTH_PRE_TOKEN_VALIDATION = [set_oauthlib_user_to_device_request_user]

        request_data: dict[str, str] = {"client_id": self.application.client_id}
        if scope is not None:
            request_data["scope"] = scope

        device_authorization_response: http.response.JsonResponse = self.client.post(
            reverse("oauth2_provider:device-authorization"),
            data=urlencode(request_data),
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

        get_response = self.client.get(device_confirm_url)
        assert get_response.status_code == 200
        assert "application" in get_response.context
        assert get_response.context["application"] == self.application
        assert "scopes_descriptions" in get_response.context
        for expected_scope in expected_confirm_scope_descriptions:
            assert expected_scope in get_response.context["scopes_descriptions"]
            self.assertContains(get_response, expected_scope)
        self.assertContains(get_response, self.application.name)

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
            "scope": expected_token_scope,
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

        # -------------------------
        # 5: The device code is spent (#1965). Polling again with it is answered with
        #  invalid_grant (RFC 6749 section 5.2) and mints no second token.
        # -------------------------
        device.refresh_from_db()
        assert device.status == device.USED

        reused_response = self.client.post(
            "/o/token/",
            data=urlencode(token_payload),
            content_type="application/x-www-form-urlencoded",
        )
        assert reused_response.__getitem__("content-type") == "application/json"
        assert reused_response.status_code == 400
        assert reused_response.json() == {"error": "invalid_grant"}
        assert AccessToken.objects.count() == 1
        assert RefreshToken.objects.count() == 1

        # The user's status page reports that the device has used its code.
        self.assertContains(
            response=self.client.get(device_grant_status_url),
            text="Device Used",
            count=1,
        )

    def test_token_view_returns_invalid_grant_for_used_device_code(self):
        """
        A device grant that was already redeemed for a token answers every later poll with
        invalid_grant, whether or not its deadline has passed since, and stays used (#1965).
        Covers the view's own check on oauthlib before 4.0.1 and the validate_device_code
        hook on 4.0.1 and later.
        """
        for label, expires in (
            ("before its deadline", datetime.now(tz=timezone.utc) + timedelta(seconds=60)),
            ("past its deadline", datetime.now(tz=timezone.utc) - timedelta(seconds=10)),
        ):
            with self.subTest(label):
                device = DeviceModel.objects.create(
                    client_id=self.application.client_id,
                    device_code=f"device_code {label}",
                    user_code=f"user_code {label}",
                    scope="read",
                    expires=expires,
                    status=DeviceModel.USED,
                    user=self.test_user,
                )

                response = self.client.post(
                    "/o/token/",
                    data=urlencode(
                        {
                            "device_code": device.device_code,
                            "client_id": self.application.client_id,
                            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        }
                    ),
                    content_type="application/x-www-form-urlencoded",
                )

                assert response.status_code == 400
                assert response["content-type"] == "application/json"
                assert response.json() == {"error": "invalid_grant"}
                assert not AccessToken.objects.exists()
                device.refresh_from_db()
                assert device.status == DeviceModel.USED

    def test_device_grant_status_view_reports_a_used_grant(self):
        """
        The status page the approving user lands on keeps working once the device has
        redeemed its code, which usually happens within one polling interval (#1965).
        """
        DeviceModel.objects.create(
            client_id=self.application.client_id,
            device_code="device_code",
            user_code="user_code",
            scope="read",
            expires=datetime.now(tz=timezone.utc) + timedelta(seconds=60),
            status=DeviceModel.USED,
            user=self.test_user,
        )
        self.client.force_login(self.test_user)

        response = self.client.get(
            reverse(
                "oauth2_provider:device-grant-status",
                kwargs={"client_id": self.application.client_id, "user_code": "user_code"},
            )
        )

        self.assertContains(response, "Device Used", count=1)

    def test_device_user_code_view_get_prefills_form_from_query_param(self):
        """
        A GET to the device user-code view with ?user_code=... should render a form
        whose initial value for user_code is pre-populated from the query parameter.
        """
        UserModel.objects.create_user(
            username="test_user_device_flow",
            email="test_device@example.com",
            password="password123",
        )
        self.client.login(username="test_user_device_flow", password="password123")

        response = self.client.get(reverse("oauth2_provider:device"), data={"user_code": "WDJB-MJHT"})

        assert response.status_code == 200
        assert "form" in response.context
        assert response.context["form"].initial.get("user_code") == "WDJB-MJHT"
        assert b'value="WDJB-MJHT"' in response.content

    def test_device_user_code_view_get_without_query_param_has_empty_initial(self):
        """
        A GET to the device user-code view without a user_code query parameter should
        render a form with an empty initial value for user_code.
        """
        UserModel.objects.create_user(
            username="test_user_device_flow",
            email="test_device@example.com",
            password="password123",
        )
        self.client.login(username="test_user_device_flow", password="password123")

        response = self.client.get(reverse("oauth2_provider:device"))

        assert response.status_code == 200
        assert "form" in response.context
        assert response.context["form"].initial.get("user_code", "") == ""
        assert b'name="user_code"' in response.content
        assert b'value="WDJB-MJHT"' not in response.content

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "abc",
    )
    def test_device_flow_authorization_user_code_confirm_and_access_token(self):
        """
        Full user journey with an explicit scope. The confirm page shows the requested
        scope and the issued token contains only that scope.
        """
        self._run_full_device_flow_journey(
            scope="read",
            expected_confirm_scope_descriptions=["Reading scope"],
            expected_token_scope="read",
        )

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "abc",
    )
    def test_device_flow_authorization_user_code_confirm_and_access_token_default_scopes(self):
        """
        Full user journey without an explicit scope. The server falls back to DEFAULT_SCOPES,
        the confirm page shows all default scopes, and the issued token reflects them.
        """
        self._run_full_device_flow_journey(
            scope=None,
            expected_confirm_scope_descriptions=["Reading scope", "Writing scope"],
            expected_token_scope="read write",
        )

    def test_user_denies_access(self):
        """
        This test asserts the when the user denies access, the state of the grant is saved
        and the user is redirected to the page where they can see the "denied" state.

        The /token View returning the appropriate message for the "denied" state is covered
        in test_token_view_returns_error_if_device_in_invalid_state.
        """
        user = UserModel.objects.create_user(
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
            user=user,
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
        user = UserModel.objects.create_user(
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
            user=user,
        )
        device.save()

        device_confirm_url = reverse(
            "oauth2_provider:device-confirm",
            kwargs={"user_code": "user_code", "client_id": "client_id"},
        )
        response = self.client.post(device_confirm_url, data={"action": "inccorect_action"})

        assert response.status_code == 400

    def test_device_confirm_view_rejects_different_authenticated_user(self):
        """
        A user must not be able to approve or deny a device grant that was
        associated with another user during the user-code step, nor view its
        status.
        """
        UserModel.objects.create_user(
            username="attacker",
            email="attacker@example.com",
            password="password123",
        )
        self.client.login(username="attacker", password="password123")

        device = DeviceModel.objects.create(
            client_id=self.application.client_id,
            device_code="device_code",
            user_code="user_code",
            scope="scope",
            expires=datetime.now() + timedelta(days=1),
            status=DeviceModel.AUTHORIZATION_PENDING,
            user=self.test_user,
        )
        device_confirm_url = reverse(
            "oauth2_provider:device-confirm",
            kwargs={"user_code": device.user_code, "client_id": device.client_id},
        )

        get_response = self.client.get(device_confirm_url)
        assert get_response.status_code == 404

        post_response = self.client.post(device_confirm_url, data={"action": "accept"})
        assert post_response.status_code == 404

        device_grant_status_url = reverse(
            "oauth2_provider:device-grant-status",
            kwargs={"user_code": device.user_code, "client_id": device.client_id},
        )
        status_response = self.client.get(device_grant_status_url)
        assert status_response.status_code == 404

        device.refresh_from_db()
        assert device.status == DeviceModel.AUTHORIZATION_PENDING

    def test_device_confirm_view_does_not_decide_a_grant_that_is_no_longer_pending(self):
        """
        The decision is a conditional update on a pending grant, so a stale form post (one
        that loaded the grant while it was pending, then lost a race with another decision
        or with the device redeeming the code) is answered with 404 and changes nothing: in
        particular it cannot turn a used grant back into an authorized one (#1965).
        """
        self.client.force_login(self.test_user)
        for action, current_status in (
            ("accept", DeviceModel.USED),
            ("deny", DeviceModel.USED),
            ("accept", DeviceModel.DENIED),
            ("deny", DeviceModel.AUTHORIZED),
        ):
            with self.subTest(action=action, status=current_status):
                device = DeviceModel.objects.create(
                    client_id=self.application.client_id,
                    device_code=f"device_code-{action}-{current_status}",
                    user_code=f"user_code-{action}-{current_status}",
                    scope="read",
                    expires=datetime.now(tz=timezone.utc) + timedelta(seconds=60),
                    status=DeviceModel.AUTHORIZATION_PENDING,
                    user=self.test_user,
                )
                # The instance the view loaded while the grant was still pending ...
                stale_device = DeviceModel.objects.get(pk=device.pk)
                # ... and the decision (or redemption) that landed in the meantime.
                DeviceModel.objects.filter(pk=device.pk).update(status=current_status)

                with mock.patch.object(DeviceConfirmView, "get_object", return_value=stale_device):
                    response = self.client.post(
                        reverse(
                            "oauth2_provider:device-confirm",
                            kwargs={"user_code": device.user_code, "client_id": device.client_id},
                        ),
                        data={"action": action},
                    )

                assert response.status_code == 404
                device.refresh_from_db()
                assert device.status == current_status

    def test_device_user_code_view_reports_a_used_grant_as_already_used_past_its_deadline(self):
        """
        Submitting the user code of a grant whose device code was already redeemed is refused
        as already used, and the grant stays used, also once its deadline has passed: the form
        checks expiry first, and ``is_expired()`` must not turn a spent grant into an expired
        one (#1965).
        """
        self.client.force_login(self.test_user)
        for label, expires in (
            ("before its deadline", datetime.now(tz=timezone.utc) + timedelta(seconds=60)),
            ("past its deadline", datetime.now(tz=timezone.utc) - timedelta(seconds=10)),
        ):
            with self.subTest(label):
                device = DeviceModel.objects.create(
                    client_id=self.application.client_id,
                    device_code=f"device_code {label}",
                    user_code=f"user_code {label}",
                    scope="read",
                    expires=expires,
                    status=DeviceModel.USED,
                    user=self.test_user,
                )

                self.assertContains(
                    response=self.client.post(
                        reverse("oauth2_provider:device"), data={"user_code": device.user_code}
                    ),
                    status_code=200,
                    text="User code has already been used",
                    count=1,
                )
                device.refresh_from_db()
                assert device.status == DeviceModel.USED

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
            client_id=self.application.client_id,
            device_code="device_code",
            user_code="user_code",
            scope="read",
            expires=datetime.now() + timedelta(seconds=60),
        )
        device.save()

        token_payload = {
            "device_code": "device_code",
            "client_id": self.application.client_id,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        }

        testcases = [
            ("authorization-pending", '{"error": "authorization_pending"}', 400),
            ("expired", '{"error": "expired_token"}', 400),
            ("denied", '{"error": "access_denied"}', 400),
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

    def test_token_view_returns_expired_token_when_device_grant_deadline_passed(self):
        """
        When a DeviceGrant's expires timestamp is in the past, polling /o/token/
        must call is_expired(), transition the grant to EXPIRED, and return
        expired_token (RFC 8628 section 3.5) rather than authorization_pending
        or issuing an access token.
        """
        for initial_status, user, expected_error, expected_status in (
            (DeviceModel.AUTHORIZATION_PENDING, None, "expired_token", DeviceModel.EXPIRED),
            (DeviceModel.AUTHORIZED, self.test_user, "expired_token", DeviceModel.EXPIRED),
            (DeviceModel.DENIED, self.test_user, "access_denied", DeviceModel.DENIED),
        ):
            with self.subTest(status=initial_status):
                device = DeviceModel.objects.create(
                    client_id=self.application.client_id,
                    device_code=f"expired_{initial_status}",
                    user_code=f"code_{initial_status}",
                    scope="read",
                    expires=datetime.now(tz=timezone.utc) - timedelta(seconds=10),
                    status=initial_status,
                    user=user,
                )

                response = self.client.post(
                    "/o/token/",
                    data=urlencode(
                        {
                            "device_code": device.device_code,
                            "client_id": self.application.client_id,
                            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        }
                    ),
                    content_type="application/x-www-form-urlencoded",
                )

                assert response.status_code == 400
                self.assertJSONEqual(raw=response.content, expected_data={"error": expected_error})
                device.refresh_from_db()
                assert device.status == expected_status

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
            "oauth2_provider.authorization_server.views.mixins."
            "AuthorizationServerViewMixin.get_oauthlib_core",
            MockOauthlibCoreClass,
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

    def test_device_is_expired_method_leaves_a_used_grant_used(self):
        """
        A grant whose device code was redeemed is spent, not expired: ``is_expired()`` neither
        reports it expired nor overwrites the used status once the deadline has passed, so a
        later poll keeps getting invalid_grant and the status page keeps saying used (#1965).
        """
        device = DeviceModel.objects.create(
            client_id="client_id",
            device_code="device_code",
            user_code="user_code",
            scope="scope",
            expires=datetime.now(tz=timezone.utc) - timedelta(seconds=1),
            status=DeviceModel.USED,
        )

        assert not device.is_expired()

        device.refresh_from_db()
        assert device.status == DeviceModel.USED

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "def",
    )
    def test_device_flow_uses_requested_scope_not_default(self):
        """
        Test that requested scope in device authorization is used in the token,
        not DEFAULT_SCOPES.
        """
        self.oauth2_settings.OAUTH_DEVICE_VERIFICATION_URI = "example.com/device"
        self.oauth2_settings.OAUTH_DEVICE_USER_CODE_GENERATOR = lambda: "XYZ"
        self.oauth2_settings.OAUTH_PRE_TOKEN_VALIDATION = [set_oauthlib_user_to_device_request_user]

        device_authorization_response = self.client.post(
            reverse("oauth2_provider:device-authorization"),
            data=urlencode({"client_id": self.application.client_id, "scope": "read"}),
            content_type="application/x-www-form-urlencoded",
        )
        assert device_authorization_response.status_code == 200

        self.client.login(username="test_user", password="123456")
        self.client.post(reverse("oauth2_provider:device"), data={"user_code": "XYZ"})
        self.client.post(
            reverse(
                "oauth2_provider:device-confirm",
                kwargs={"user_code": "XYZ", "client_id": self.application.client_id},
            ),
            data={"action": "accept"},
        )

        token_response = self.client.post(
            "/o/token/",
            data=urlencode(
                {
                    "device_code": "def",
                    "client_id": self.application.client_id,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                }
            ),
            content_type="application/x-www-form-urlencoded",
        )

        assert token_response.status_code == 200
        assert token_response.json()["scope"] == "read"

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "def",
    )
    def test_device_flow_default_scopes_stored_on_grant_when_no_scope_requested(self):
        """
        When the device omits `scope`, DEFAULT_SCOPES must be stored on the DeviceGrant
        at authorization time so the consent screen shows the correct scopes and the
        issued token matches what the user approved.
        """
        self.oauth2_settings.OAUTH_DEVICE_VERIFICATION_URI = "example.com/device"
        self.oauth2_settings.OAUTH_DEVICE_USER_CODE_GENERATOR = lambda: "XYZ"
        self.oauth2_settings.OAUTH_PRE_TOKEN_VALIDATION = [set_oauthlib_user_to_device_request_user]

        # Device sends authorization request with no scope
        device_authorization_response = self.client.post(
            reverse("oauth2_provider:device-authorization"),
            data=urlencode({"client_id": self.application.client_id}),
            content_type="application/x-www-form-urlencoded",
        )
        assert device_authorization_response.status_code == 200

        # DEFAULT_SCOPES ("read write") must be persisted on the grant immediately
        DeviceGrantModel = get_device_grant_model()
        grant = DeviceGrantModel.objects.get(device_code="def")
        assert grant.scope == "read write"

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "def",
    )
    @mock.patch("oauth2_provider.authorization_server.views.device.OAUTHLIB_VALIDATES_DEVICE_CODE", True)
    def test_device_authorization_stores_no_scope_when_oauthlib_resolved_none(self):
        """
        oauthlib 4.0.1 and later leave the ``scope`` key out when they resolved no scopes
        (no scope asked for and no default scopes). The grant then stores none: the view must
        not ask the scopes backend a second time and store the defaults it returns now.
        """
        self.oauth2_settings.OAUTH_DEVICE_VERIFICATION_URI = "example.com/device"

        with mock.patch(
            "oauth2_provider.authorization_server.views.mixins."
            "AuthorizationServerViewMixin.create_device_authorization_response",
            return_value=({}, dict(OAUTHLIB_RESPONSE_WITHOUT_SCOPE), 200),
        ):
            response = self.client.post(
                reverse("oauth2_provider:device-authorization"),
                data=urlencode({"client_id": self.application.client_id}),
                content_type="application/x-www-form-urlencoded",
            )

        assert response.status_code == 200
        assert DeviceModel.objects.get(device_code="abc").scope == ""

    @mock.patch("oauth2_provider.authorization_server.views.device.OAUTHLIB_VALIDATES_DEVICE_CODE", False)
    def test_device_flow_whitespace_only_scope_falls_back_to_default_scopes_when_view_resolves_scope(self):
        """
        When oauthlib does not resolve the scope (before 4.0.1), the view resolves it:
        a scope consisting only of whitespace (e.g. scope="   ") is treated as if scope was
        omitted, so DEFAULT_SCOPES are stored on the DeviceGrant, not the raw whitespace
        string. The oauthlib response is mocked so this holds on every oauthlib.
        """
        self.oauth2_settings.OAUTH_DEVICE_VERIFICATION_URI = "example.com/device"

        with mock.patch(
            "oauth2_provider.authorization_server.views.mixins."
            "AuthorizationServerViewMixin.create_device_authorization_response",
            return_value=({}, dict(OAUTHLIB_RESPONSE_WITHOUT_SCOPE), 200),
        ):
            response = self.client.post(
                reverse("oauth2_provider:device-authorization"),
                data=urlencode({"client_id": self.application.client_id, "scope": "   "}),
                content_type="application/x-www-form-urlencoded",
            )

        assert response.status_code == 200
        assert "scope" not in response.json()
        grant = DeviceModel.objects.get(device_code="abc")
        assert grant.scope == "read write"

    @mock.patch("oauth2_provider.authorization_server.views.device.OAUTHLIB_VALIDATES_DEVICE_CODE", False)
    def test_device_flow_requested_scope_is_stored_when_view_resolves_scope(self):
        """
        When oauthlib does not resolve the scope (before 4.0.1), the view stores the scope
        the device asked for.
        """
        self.oauth2_settings.OAUTH_DEVICE_VERIFICATION_URI = "example.com/device"

        with mock.patch(
            "oauth2_provider.authorization_server.views.mixins."
            "AuthorizationServerViewMixin.create_device_authorization_response",
            return_value=({}, dict(OAUTHLIB_RESPONSE_WITHOUT_SCOPE), 200),
        ):
            response = self.client.post(
                reverse("oauth2_provider:device-authorization"),
                data=urlencode({"client_id": self.application.client_id, "scope": "read"}),
                content_type="application/x-www-form-urlencoded",
            )

        assert response.status_code == 200
        assert DeviceModel.objects.get(device_code="abc").scope == "read"

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "def",
    )
    @skipUnless(OAUTHLIB_VALIDATES_DEVICE_CODE, "oauthlib before 4.0.1 leaves the scope to the view")
    def test_device_flow_whitespace_only_scope_is_rejected_as_invalid_scope(self):
        """
        From oauthlib 4.0.1 on, the device authorization endpoint validates the scope: one
        consisting only of whitespace (e.g. scope="   ") is not a scope the application may
        use, so it is rejected with invalid_scope (RFC 6749 section 3.3), as the
        authorization endpoint does, and no grant is stored.
        """
        self.oauth2_settings.OAUTH_DEVICE_VERIFICATION_URI = "example.com/device"
        self.oauth2_settings.OAUTH_DEVICE_USER_CODE_GENERATOR = lambda: "XYZ"

        device_authorization_response = self.client.post(
            reverse("oauth2_provider:device-authorization"),
            data=urlencode({"client_id": self.application.client_id, "scope": "   "}),
            content_type="application/x-www-form-urlencoded",
        )
        assert device_authorization_response.status_code == 400
        assert device_authorization_response.json() == {"error": "invalid_scope"}
        assert not get_device_grant_model().objects.filter(device_code="def").exists()

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "def",
    )
    def test_device_flow_scope_longer_than_64_chars_is_stored_intact(self):
        """
        DeviceGrant.scope used to be a CharField(max_length=64), which silently truncated
        (or rejected, depending on the backend) longer scope strings. Real-world providers
        allow much longer scopes (Okta 1024, Google 2048), so scope is now a TextField and
        must store long values intact. Regression test for issue #1693.
        """
        self.oauth2_settings.OAUTH_DEVICE_VERIFICATION_URI = "example.com/device"
        self.oauth2_settings.OAUTH_DEVICE_USER_CODE_GENERATOR = lambda: "XYZ"
        # The requested scopes must be ones the application may use: oauthlib (4.0.1 and
        # later) validates them at the device authorization endpoint.
        self.oauth2_settings.SCOPES = {f"scope{i}": f"Scope {i}" for i in range(300)}

        long_scope = " ".join(f"scope{i}" for i in range(300))
        assert len(long_scope) > 2048

        device_authorization_response = self.client.post(
            reverse("oauth2_provider:device-authorization"),
            data=urlencode({"client_id": self.application.client_id, "scope": long_scope}),
            content_type="application/x-www-form-urlencoded",
        )
        assert device_authorization_response.status_code == 200

        DeviceGrantModel = get_device_grant_model()
        # SQLite does not enforce varchar lengths, so also assert the field type directly.
        assert isinstance(DeviceGrantModel._meta.get_field("scope"), models.TextField)
        grant = DeviceGrantModel.objects.get(device_code="def")
        assert grant.scope == long_scope

    def test_create_device_grant_stores_empty_string_when_scope_is_none(self):
        """
        DeviceGrant.scope is non-nullable (like the other grant and token models), so
        create_device_grant must coerce a missing scope to an empty string.
        """
        device_request = DeviceRequest(client_id=self.application.client_id, scope=None)
        device_response = DeviceCodeResponse(
            verification_uri="example.com/device",
            expires_in=3600,
            user_code="ABC",
            device_code="ghi",
            interval=5,
        )
        grant = create_device_grant(device_request, device_response)

        grant.refresh_from_db()
        assert grant.scope == ""

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "def",
    )
    def test_device_flow_default_scopes_not_re_evaluated_at_token_time(self):
        """
        If DEFAULT_SCOPES changes between user consent and device polling, the token
        must reflect the scopes that were shown on the consent screen (locked in at
        authorization time), not the new DEFAULT_SCOPES.
        """
        self.oauth2_settings.OAUTH_DEVICE_VERIFICATION_URI = "example.com/device"
        self.oauth2_settings.OAUTH_DEVICE_USER_CODE_GENERATOR = lambda: "XYZ"
        self.oauth2_settings.OAUTH_PRE_TOKEN_VALIDATION = [set_oauthlib_user_to_device_request_user]

        # Device sends authorization request with no scope; DEFAULT_SCOPES = ["read", "write"]
        device_authorization_response = self.client.post(
            reverse("oauth2_provider:device-authorization"),
            data=urlencode({"client_id": self.application.client_id}),
            content_type="application/x-www-form-urlencoded",
        )
        assert device_authorization_response.status_code == 200

        self.client.login(username="test_user", password="123456")
        self.client.post(reverse("oauth2_provider:device"), data={"user_code": "XYZ"})
        self.client.post(
            reverse(
                "oauth2_provider:device-confirm",
                kwargs={"user_code": "XYZ", "client_id": self.application.client_id},
            ),
            data={"action": "accept"},
        )

        # Admin changes DEFAULT_SCOPES after consent but before the device polls.
        # "admin" must also be in SCOPES or oauth2_settings raises ImproperlyConfigured
        # when _DEFAULT_SCOPES is re-evaluated after reload().
        self.oauth2_settings.SCOPES = {
            "read": "Reading scope",
            "write": "Writing scope",
            "admin": "Admin scope",
        }
        self.oauth2_settings.DEFAULT_SCOPES = ["read", "write", "admin"]
        # Clear only the computed scope caches so the new SCOPES/DEFAULT_SCOPES
        # values take effect without wiping the overrides we just set above.
        # Calling reload() would delete those overrides and fall back to Django settings.
        for _attr in ("_SCOPES", "_DEFAULT_SCOPES"):
            try:
                delattr(self.oauth2_settings, _attr)
            except AttributeError:
                pass
            self.oauth2_settings._cached_attrs.discard(_attr)

        token_response = self.client.post(
            "/o/token/",
            data=urlencode(
                {
                    "device_code": "def",
                    "client_id": self.application.client_id,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                }
            ),
            content_type="application/x-www-form-urlencoded",
        )

        assert token_response.status_code == 200
        # Token must reflect the scopes from consent time, not the expanded DEFAULT_SCOPES
        assert token_response.json()["scope"] == "read write"

    @mock.patch("oauth2_provider.authorization_server.views.device.OAUTHLIB_VALIDATES_DEVICE_CODE", True)
    def test_device_authorization_stores_scope_resolved_by_oauthlib_and_omits_it_from_response(self):
        """
        oauthlib 4.0.1 adds the scopes it resolved to the device authorization response as a
        ``scope`` key. RFC 8628 section 3.2 does not define it: the device gets the RFC
        response, and the grant stores oauthlib's scope rather than resolving it again
        (regression test for #1950). The response and the compat flag are mocked so this holds
        on every oauthlib.
        """
        self.oauth2_settings.OAUTH_DEVICE_VERIFICATION_URI = "example.com/device"
        oauthlib_response = {
            "verification_uri": "example.com/device",
            "expires_in": 1800,
            "user_code": "XYZ",
            "device_code": "abc",
            "interval": 5,
            "scope": "read",
        }

        with mock.patch(
            "oauth2_provider.authorization_server.views.mixins."
            "AuthorizationServerViewMixin.create_device_authorization_response",
            return_value=({}, oauthlib_response, 200),
        ):
            # No scope in the request: the view would fall back to the default scopes
            # ("read write"), so a grant with "read" shows oauthlib's resolution was kept.
            response = self.client.post(
                reverse("oauth2_provider:device-authorization"),
                data=urlencode({"client_id": self.application.client_id}),
                content_type="application/x-www-form-urlencoded",
            )

        assert response.status_code == 200
        assert response.json() == {
            "verification_uri": "example.com/device",
            "expires_in": 1800,
            "user_code": "XYZ",
            "device_code": "abc",
            "interval": 5,
        }
        grant = DeviceModel.objects.get(device_code="abc")
        assert grant.scope == "read"
        assert grant.status == DeviceModel.AUTHORIZATION_PENDING

    @mock.patch("oauth2_provider.authorization_server.views.device.OAUTHLIB_VALIDATES_DEVICE_CODE", False)
    def test_device_authorization_returns_invalid_client_when_application_deleted_before_scope_resolution(
        self,
    ):
        """
        If the Application is deleted between oauthlib validating the client and DOT
        resolving default scopes, the view must return an invalid_client error rather
        than silently proceeding with application=None.

        This covers the DoesNotExist branch in DeviceAuthorizationView.post() that is
        only reached when scope is omitted (so default-scope resolution is attempted) and
        oauthlib does not resolve the scopes itself (it does from 4.0.1 on), so the compat
        flag is patched off and the oauthlib response is mocked without a ``scope`` key.
        """
        self.oauth2_settings.OAUTH_DEVICE_VERIFICATION_URI = "example.com/device"
        self.oauth2_settings.OAUTH_DEVICE_USER_CODE_GENERATOR = lambda: "XYZ"

        Application = get_application_model()

        # Patch get_application_model as imported in the view to simulate a race where
        # the Application row is deleted between oauthlib validation and scope resolution.
        # We use a spec'd mock so that DoesNotExist is accessible as an attribute.
        mock_model = mock.MagicMock(spec=Application)
        mock_model.DoesNotExist = Application.DoesNotExist
        mock_model.objects.get.side_effect = Application.DoesNotExist

        with (
            mock.patch(
                "oauth2_provider.authorization_server.views.device.get_application_model",
                return_value=mock_model,
            ),
            mock.patch(
                "oauth2_provider.authorization_server.views.mixins."
                "AuthorizationServerViewMixin.create_device_authorization_response",
                return_value=({}, dict(OAUTHLIB_RESPONSE_WITHOUT_SCOPE), 200),
            ),
        ):
            response = self.client.post(
                reverse("oauth2_provider:device-authorization"),
                data=urlencode({"client_id": self.application.client_id}),
                content_type="application/x-www-form-urlencoded",
            )

        assert response.status_code == 401
        assert response.json()["error"] == "invalid_client"


@mock.patch("oauth2_provider.authorization_server.views.base.OAUTHLIB_VALIDATES_DEVICE_CODE", False)
class TestTokenViewDeviceGrantPreCheck(DeviceFlowBaseTestCase):
    """
    TokenView's own check of the device grant, which it runs before handing the poll to
    oauthlib when oauthlib (before 4.0.1) does not call validate_device_code. The compat
    flag is patched so the check runs on every oauthlib.
    """

    def poll(self, device_code: str, **extra_params: str) -> http.HttpResponse:
        return self.client.post(
            "/o/token/",
            data=urlencode(
                {
                    "device_code": device_code,
                    "client_id": self.application.client_id,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    **extra_params,
                }
            ),
            content_type="application/x-www-form-urlencoded",
        )

    def create_grant(self, **kwargs) -> oauth2_provider.models.DeviceGrant:
        fields = {
            "client_id": self.application.client_id,
            "device_code": "device_code",
            "user_code": "user_code",
            "scope": "read",
            "expires": datetime.now(tz=timezone.utc) + timedelta(seconds=60),
        }
        fields.update(kwargs)
        return DeviceModel.objects.create(**fields)

    def test_grant_not_yet_authorized_is_answered_with_its_rfc8628_error(self):
        grant = self.create_grant()
        for grant_status, expected_error in (
            (DeviceModel.AUTHORIZATION_PENDING, "authorization_pending"),
            (DeviceModel.EXPIRED, "expired_token"),
            (DeviceModel.DENIED, "access_denied"),
        ):
            with self.subTest(status=grant_status):
                DeviceModel.objects.filter(pk=grant.pk).update(status=grant_status)

                response = self.poll("device_code")

                assert response.status_code == 400
                assert response["content-type"] == "application/json"
                assert response.json() == {"error": expected_error}

    def test_authorized_grant_is_handed_to_oauthlib(self):
        self.create_grant(status=DeviceModel.AUTHORIZED, user=self.test_user)

        response = self.poll("device_code")

        assert response.status_code == 200
        assert AccessToken.objects.get(token=response.json()["access_token"]).user == self.test_user

    def test_grant_approved_without_scopes_yields_token_without_scopes(self):
        """
        The default OAUTH_PRE_TOKEN_VALIDATION validator puts the grant's empty scope set on
        the request; oauthlib's fallbacks to the poll's own scope parameter and to
        DEFAULT_SCOPES ("read write") must not apply.
        """
        self.create_grant(status=DeviceModel.AUTHORIZED, user=self.test_user, scope="")

        response = self.poll("device_code", scope="write")

        assert response.status_code == 200
        token_data = response.json()
        assert token_data["scope"] == ""
        assert AccessToken.objects.get(token=token_data["access_token"]).scope == ""

    def test_unknown_device_code_is_device_not_found(self):
        self.create_grant()

        response = self.poll("another_device_code")

        self.assertContains(response, status_code=404, text="device_not_found", count=1)
        # TokenView should always respond with application/json as it's meant to be
        # consumed by devices.
        assert response["content-type"] == "application/json"

    def test_unknown_device_status_is_internal_error(self):
        """
        A status the view does not know is answered with HTTP 500, as a reminder to handle
        new statuses here.
        """
        grant = self.create_grant()
        DeviceModel.objects.filter(pk=grant.pk).update(status="LOL_status")

        response = self.poll("device_code")

        self.assertContains(response, status_code=500, text='{"error": "internal_error"}', count=1)
        assert response["content-type"] == "application/json"

    def test_used_grant_is_invalid_grant(self):
        """
        A grant whose code was already redeemed is refused before oauthlib sees the poll, with
        the same invalid_grant the hook answers on newer oauthlib (#1965).
        """
        self.create_grant(status=DeviceModel.USED, user=self.test_user)

        response = self.poll("device_code")

        assert response.status_code == 400
        assert response["content-type"] == "application/json"
        assert response.json() == {"error": "invalid_grant"}
        assert not AccessToken.objects.exists()


class TestDeviceFlowWithSwappedDeviceGrantModel(DeviceFlowBaseTestCase):
    def setUp(self):
        super().setUp()
        self._original_device_grant_model = self.oauth2_settings.DEVICE_GRANT_MODEL
        self.oauth2_settings.DEVICE_GRANT_MODEL = "tests.SampleDeviceGrant"

    def tearDown(self):
        get_device_grant_model().objects.all().delete()
        self.oauth2_settings.DEVICE_GRANT_MODEL = self._original_device_grant_model
        super().tearDown()

    @mock.patch(
        "oauthlib.oauth2.rfc8628.endpoints.device_authorization.generate_token",
        lambda: "abc",
    )
    def test_full_device_flow_uses_swapped_device_grant_model(self):
        self.oauth2_settings.OAUTH_DEVICE_VERIFICATION_URI = "example.com/device"
        self.oauth2_settings.OAUTH_DEVICE_USER_CODE_GENERATOR = lambda: "xyz"
        self.oauth2_settings.OAUTH_PRE_TOKEN_VALIDATION = [set_oauthlib_user_to_device_request_user]

        device_model = get_device_grant_model()
        assert device_model._meta.label == "tests.SampleDeviceGrant"

        device_authorization_response: http.response.JsonResponse = self.client.post(
            reverse("oauth2_provider:device-authorization"),
            data=urlencode({"client_id": self.application.client_id}),
            content_type="application/x-www-form-urlencoded",
        )

        assert device_authorization_response.status_code == 200
        assert device_model.objects.get(device_code="abc").status == device_model.AUTHORIZATION_PENDING
        if not oauth2_provider.models.DeviceGrant._meta.swapped:
            assert not oauth2_provider.models.DeviceGrant.objects.filter(device_code="abc").exists()

        token_payload = {
            "device_code": "abc",
            "client_id": self.application.client_id,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        }
        pending_response = self.client.post(
            "/o/token/",
            data=urlencode(token_payload),
            content_type="application/x-www-form-urlencoded",
        )
        self.assertJSONEqual(
            raw=pending_response.content,
            expected_data={"error": "authorization_pending"},
        )

        UserModel.objects.create_user(
            username="test_user_swapped_device_flow",
            email="test_swapped_device@example.com",
            password="password123",
        )
        self.client.login(username="test_user_swapped_device_flow", password="password123")

        device_confirm_url = reverse(
            "oauth2_provider:device-confirm",
            kwargs={"user_code": "xyz", "client_id": self.application.client_id},
        )
        device_grant_status_url = reverse(
            "oauth2_provider:device-grant-status",
            kwargs={"user_code": "xyz", "client_id": self.application.client_id},
        )

        self.assertRedirects(
            response=self.client.post(reverse("oauth2_provider:device"), data={"user_code": "xyz"}),
            expected_url=device_confirm_url,
        )
        self.assertRedirects(
            response=self.client.post(device_confirm_url, data={"action": "accept"}),
            expected_url=device_grant_status_url,
        )
        self.assertContains(
            response=self.client.get(device_grant_status_url),
            text="Device Authorized",
            count=1,
        )

        token_response = self.client.post(
            "/o/token/",
            data=urlencode(token_payload),
            content_type="application/x-www-form-urlencoded",
        )
        assert token_response.status_code == 200
        assert token_response.json() == {
            "access_token": mock.ANY,
            "expires_in": 36000,
            "token_type": "Bearer",
            "scope": "read write",
            "refresh_token": mock.ANY,
        }

        # The swapped grant is consumed too (its `used` status needs the tests app migration).
        assert device_model.objects.get(device_code="abc").status == device_model.USED
        reused_response = self.client.post(
            "/o/token/",
            data=urlencode(token_payload),
            content_type="application/x-www-form-urlencoded",
        )
        assert reused_response.status_code == 400
        assert reused_response.json() == {"error": "invalid_grant"}
        assert AccessToken.objects.count() == 1

    def test_invalid_user_code_returns_form_error_with_swapped_device_model(self):
        UserModel.objects.create_user(
            username="test_user_swapped_invalid_code",
            email="test_swapped_invalid_code@example.com",
            password="password123",
        )
        self.client.login(username="test_user_swapped_invalid_code", password="password123")

        self.assertContains(
            response=self.client.post(reverse("oauth2_provider:device"), data={"user_code": "invalid_code"}),
            status_code=200,
            text="Incorrect user code",
            count=1,
        )


class TestOAuth2ValidatorValidateDeviceCode(DeviceFlowBaseTestCase):
    """
    OAuth2Validator.validate_device_code is the hook oauthlib (4.0.1 and later) calls from
    the device code grant's token request (#1950). It is called directly here, so the tests
    cover it whatever oauthlib is installed.
    """

    def setUp(self):
        super().setUp()
        self.validator = OAuth2Validator()
        self.request = OauthlibRequest("/o/token/")

    def create_grant(self, **kwargs) -> oauth2_provider.models.DeviceGrant:
        fields = {
            "client_id": self.application.client_id,
            "device_code": "device_code",
            "user_code": "user_code",
            "scope": "read",
            "expires": datetime.now(tz=timezone.utc) + timedelta(seconds=60),
        }
        fields.update(kwargs)
        return DeviceModel.objects.create(**fields)

    @skipUnless(OAUTHLIB_VALIDATES_DEVICE_CODE, "oauthlib before 4.0.1 has no validate_device_code hook")
    def test_statuses_match_oauthlib_constants(self):
        self.create_grant(status=DeviceModel.AUTHORIZED, user=self.test_user)
        authorized = self.validator.validate_device_code(
            self.application.client_id, "device_code", self.request
        )
        assert authorized == DeviceCodeGrant.DEVICE_CODE_AUTHORIZED

        for grant_status, expected in (
            (DeviceModel.AUTHORIZATION_PENDING, DeviceCodeGrant.DEVICE_CODE_PENDING),
            (DeviceModel.DENIED, DeviceCodeGrant.DEVICE_CODE_DENIED),
            (DeviceModel.EXPIRED, DeviceCodeGrant.DEVICE_CODE_EXPIRED),
        ):
            with self.subTest(status=grant_status):
                DeviceModel.objects.filter(device_code="device_code").update(status=grant_status)
                status = self.validator.validate_device_code(
                    self.application.client_id, "device_code", self.request
                )
                assert status == expected

    def test_authorized_grant_sets_user_and_scopes_on_request(self):
        self.create_grant(status=DeviceModel.AUTHORIZED, user=self.test_user, scope="read write")

        status = self.validator.validate_device_code(self.application.client_id, "device_code", self.request)

        assert status == "authorized"
        assert self.request.user == self.test_user
        assert self.request.scope == "read write"
        assert self.request.scopes == ["read", "write"]

    def test_authorized_grant_without_scope_sets_empty_scopes(self):
        """
        oauthlib treats an empty ``request.scopes`` as unset and falls back to the poll's
        ``scope`` parameter, then to ``get_default_scopes``, either of which would give the
        token scopes the user never approved. The grant's scopes replace the parameter, and
        with the grant on the request the default-scope fallback answers with them too.
        """
        self.create_grant(status=DeviceModel.AUTHORIZED, user=self.test_user, scope="")
        request = OauthlibRequest("/o/token/", http_method="POST", body="scope=write")
        assert request.scope == "write"

        status = self.validator.validate_device_code(self.application.client_id, "device_code", request)

        assert status == "authorized"
        assert request.scope is None
        assert request.scopes == []
        assert self.validator.get_default_scopes(self.application.client_id, request) == []

    def test_default_scopes_are_the_clients_without_a_device_grant(self):
        self.request.client = self.application

        assert self.validator.get_default_scopes(self.application.client_id, self.request) == [
            "read",
            "write",
        ]

    def test_default_scopes_ignore_a_device_grant_parameter_sent_by_the_client(self):
        """
        oauthlib's Request answers attribute reads with form and query parameters, so only
        the grant this server put on the request counts, not a ``device_grant`` parameter.
        """
        request = OauthlibRequest("/o/token/", http_method="POST", body="device_grant=evil")
        request.client = self.application
        assert request.device_grant == "evil"

        assert self.validator.get_default_scopes(self.application.client_id, request) == ["read", "write"]

    def test_pending_and_denied_grants_report_their_rfc8628_error(self):
        for grant_status, expected in (
            (DeviceModel.AUTHORIZATION_PENDING, "authorization_pending"),
            (DeviceModel.DENIED, "access_denied"),
        ):
            with self.subTest(status=grant_status):
                self.create_grant(device_code=grant_status, status=grant_status)

                status = self.validator.validate_device_code(
                    self.application.client_id, grant_status, self.request
                )

                assert status == expected
                assert self.request.user is None
                assert self.request.scopes is None

    def test_grant_past_its_deadline_is_expired(self):
        for initial_status, expected in (
            (DeviceModel.AUTHORIZATION_PENDING, "expired_token"),
            (DeviceModel.AUTHORIZED, "expired_token"),
            (DeviceModel.DENIED, "access_denied"),
        ):
            with self.subTest(status=initial_status):
                grant = self.create_grant(
                    device_code=initial_status,
                    status=initial_status,
                    user=self.test_user,
                    expires=datetime.now(tz=timezone.utc) - timedelta(seconds=10),
                )

                status = self.validator.validate_device_code(
                    self.application.client_id, initial_status, self.request
                )

                assert status == expected
                grant.refresh_from_db()
                expected_grant_status = (
                    DeviceModel.DENIED if initial_status == DeviceModel.DENIED else DeviceModel.EXPIRED
                )
                assert grant.status == expected_grant_status
                assert self.request.user is None

    def test_unknown_device_code_is_invalid(self):
        self.create_grant(status=DeviceModel.AUTHORIZED, user=self.test_user)

        status = self.validator.validate_device_code(
            self.application.client_id, "another_device_code", self.request
        )

        assert status is None
        assert self.request.user is None

    def test_device_code_issued_to_another_client_is_invalid(self):
        self.create_grant(status=DeviceModel.AUTHORIZED, user=self.test_user, client_id="another_client")

        status = self.validator.validate_device_code(self.application.client_id, "device_code", self.request)

        assert status is None
        assert self.request.user is None

    def test_unexpected_status_is_invalid(self):
        grant = self.create_grant(status=DeviceModel.AUTHORIZED, user=self.test_user)
        DeviceModel.objects.filter(pk=grant.pk).update(status="LOL_status")

        status = self.validator.validate_device_code(self.application.client_id, "device_code", self.request)

        assert status is None
        assert self.request.user is None

    def test_used_grant_is_invalid(self):
        """
        A grant whose code was already redeemed is reported as invalid with ``None``, oauthlib's
        documented return for an invalid device_code (a status string it does not know would
        make it log a warning), and the approving user is not put on the request (#1965).
        """
        for label, expires in (
            ("before its deadline", datetime.now(tz=timezone.utc) + timedelta(seconds=60)),
            ("past its deadline", datetime.now(tz=timezone.utc) - timedelta(seconds=10)),
        ):
            with self.subTest(label):
                grant = self.create_grant(
                    device_code=label, status=DeviceModel.USED, user=self.test_user, expires=expires
                )

                status = self.validator.validate_device_code(self.application.client_id, label, self.request)

                assert status is None
                assert self.request.user is None
                assert self.request.scopes is None
                grant.refresh_from_db()
                assert grant.status == DeviceModel.USED


class TestOAuth2ValidatorSaveBearerTokenConsumesDeviceGrant(DeviceFlowBaseTestCase):
    """
    OAuth2Validator.save_bearer_token spends the device code of a device code grant token
    request (#1965), on every oauthlib version: oauthlib calls it once the request has passed
    validation, so a request that fails validation leaves the grant authorized.
    """

    def setUp(self):
        super().setUp()
        self.validator = OAuth2Validator()

    def create_grant(self, **kwargs) -> oauth2_provider.models.DeviceGrant:
        fields = {
            "client_id": self.application.client_id,
            "device_code": "device_code",
            "user_code": "user_code",
            "scope": "read",
            "expires": datetime.now(tz=timezone.utc) + timedelta(seconds=60),
            "status": DeviceModel.AUTHORIZED,
            "user": self.test_user,
        }
        fields.update(kwargs)
        return DeviceModel.objects.create(**fields)

    def token_request(self, grant_type: str, **params) -> OauthlibRequest:
        request = OauthlibRequest(
            "/o/token/",
            http_method="POST",
            body=urlencode({"grant_type": grant_type, "client_id": self.application.client_id, **params}),
        )
        request.client = self.application
        request.user = self.test_user
        request.scopes = ["read"]
        return request

    def save_token(
        self, request: OauthlibRequest, *, refresh_token: bool = True, value: str = "token"
    ) -> None:
        token = {
            "access_token": f"access_{value}",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "read",
        }
        if refresh_token:
            token["refresh_token"] = f"refresh_{value}"
        self.validator.save_bearer_token(token, request)

    def test_device_code_grant_token_marks_the_grant_used(self):
        grant = self.create_grant()

        self.save_token(
            self.token_request("urn:ietf:params:oauth:grant-type:device_code", device_code="device_code")
        )

        grant.refresh_from_db()
        assert grant.status == DeviceModel.USED
        assert AccessToken.objects.get(token="access_token").user == self.test_user
        assert RefreshToken.objects.filter(token="refresh_token").exists()

    def test_device_code_grant_token_is_refused_once_the_grant_is_no_longer_authorized(self):
        """
        The grant is consumed with one conditional update, so when two polls race for the same
        code (both passed validation while it was still authorized) only the first gets a
        token; the second is refused with invalid_grant and its token is rolled back.
        """
        for label, fields in (
            ("already used", {"status": DeviceModel.USED}),
            ("issued to another client", {"client_id": "another_client"}),
        ):
            with self.subTest(label):
                grant = self.create_grant(device_code=label, **fields)

                with self.assertRaises(InvalidGrantError):
                    self.save_token(
                        self.token_request("urn:ietf:params:oauth:grant-type:device_code", device_code=label),
                        value=label,
                    )

                assert not AccessToken.objects.exists()
                assert not RefreshToken.objects.exists()
                grant.refresh_from_db()
                assert grant.status == fields.get("status", DeviceModel.AUTHORIZED)

    def test_grant_stays_authorized_when_the_token_cannot_be_saved(self):
        """
        The grant is consumed in the transaction that saves the token, so a failure to save
        the token rolls the consumption back and the device can poll again.
        """
        grant = self.create_grant()

        with (
            mock.patch.object(OAuth2Validator, "_save_bearer_token", side_effect=IntegrityError("boom")),
            self.assertRaises(IntegrityError),
        ):
            self.save_token(
                self.token_request("urn:ietf:params:oauth:grant-type:device_code", device_code="device_code")
            )

        grant.refresh_from_db()
        assert grant.status == DeviceModel.AUTHORIZED
        assert not AccessToken.objects.exists()

    def test_other_grant_types_leave_device_grants_alone(self):
        grant = self.create_grant()

        # Client credentials tokens come without a refresh token (RFC 6749 section 4.4.3).
        self.save_token(self.token_request("client_credentials"), refresh_token=False)

        grant.refresh_from_db()
        assert grant.status == DeviceModel.AUTHORIZED
        assert AccessToken.objects.filter(token="access_token").exists()


@skipUnless(OAUTHLIB_VALIDATES_DEVICE_CODE, "oauthlib before 4.0.1 does not call validate_device_code")
class TestDeviceFlowTokenEndpointWithOauthlibDeviceCodeValidation(DeviceFlowBaseTestCase):
    """
    The token endpoint on oauthlib 4.0.1 and later, where TokenView hands the poll straight
    to oauthlib and OAuth2Validator.validate_device_code decides (#1950).
    """

    def poll(self, device_code: str, **extra_params: str) -> http.HttpResponse:
        return self.client.post(
            "/o/token/",
            data=urlencode(
                {
                    "device_code": device_code,
                    "client_id": self.application.client_id,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    **extra_params,
                }
            ),
            content_type="application/x-www-form-urlencoded",
        )

    def create_grant(self, **kwargs) -> oauth2_provider.models.DeviceGrant:
        fields = {
            "client_id": self.application.client_id,
            "device_code": "device_code",
            "user_code": "user_code",
            "scope": "read",
            "expires": datetime.now(tz=timezone.utc) + timedelta(seconds=60),
            "status": DeviceModel.AUTHORIZED,
            "user": self.test_user,
        }
        fields.update(kwargs)
        return DeviceModel.objects.create(**fields)

    def test_issued_token_carries_the_grants_user_and_scope(self):
        """
        With no pre-token validator, the hook alone has to put the approving user and the
        stored scope on the request; the token proves it did.
        """
        self.oauth2_settings.OAUTH_PRE_TOKEN_VALIDATION = []
        self.create_grant(scope="read")

        response = self.poll("device_code")

        assert response.status_code == 200
        assert response["content-type"] == "application/json"
        token_data = response.json()
        assert token_data["scope"] == "read"
        access_token = AccessToken.objects.get(token=token_data["access_token"])
        assert access_token.user == self.test_user
        assert access_token.scope == "read"
        assert RefreshToken.objects.get(token=token_data["refresh_token"]).user == self.test_user

    def test_grant_approved_without_scopes_yields_token_without_scopes(self):
        """
        DEFAULT_SCOPES is "read write" when the device polls, and the poll even asks for
        "write" (RFC 8628 section 3.4 defines no scope parameter), but the user approved a
        grant with no scopes; neither oauthlib's fallback to the poll's scope nor the one to
        the default scopes may apply.
        """
        self.oauth2_settings.OAUTH_PRE_TOKEN_VALIDATION = []
        self.create_grant(scope="")

        response = self.poll("device_code", scope="write")

        assert response.status_code == 200
        token_data = response.json()
        assert token_data["scope"] == ""
        assert AccessToken.objects.get(token=token_data["access_token"]).scope == ""

    def test_unknown_device_code_is_invalid_grant(self):
        self.create_grant()

        response = self.poll("another_device_code")

        assert response.status_code == 400
        assert response["content-type"] == "application/json"
        assert response.json() == {"error": "invalid_grant"}
        assert not AccessToken.objects.exists()

    def test_device_code_issued_to_another_client_is_invalid_grant(self):
        other_application = Application.objects.create(
            name="other device app",
            user=self.dev_user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_DEVICE_CODE,
        )
        self.create_grant(client_id=other_application.client_id)

        response = self.poll("device_code")

        assert response.status_code == 400
        assert response.json() == {"error": "invalid_grant"}
        assert not AccessToken.objects.exists()

    def test_unknown_device_status_is_invalid_grant(self):
        grant = self.create_grant()
        DeviceModel.objects.filter(pk=grant.pk).update(status="LOL_status")

        response = self.poll("device_code")

        assert response.status_code == 400
        assert response.json() == {"error": "invalid_grant"}
        assert not AccessToken.objects.exists()

    def test_used_device_code_is_invalid_grant(self):
        self.create_grant(status=DeviceModel.USED)

        response = self.poll("device_code")

        assert response.status_code == 400
        assert response.json() == {"error": "invalid_grant"}
        assert not AccessToken.objects.exists()
