import calendar
import datetime

import pytest
from django.conf import settings
from django.conf.urls import include
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.test import override_settings
from django.urls import path
from django.utils import timezone
from oauthlib.common import Request

from oauth2_provider.compat import login_not_required
from oauth2_provider.models import get_access_token_model, get_application_model
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.views import ScopedProtectedResourceView

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase


try:
    from unittest import mock
except ImportError:
    import mock


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()

default_exp = datetime.datetime.now() + datetime.timedelta(days=1)


class ScopeResourceView(ScopedProtectedResourceView):
    required_scopes = ["dolphin"]

    def get(self, request, *args, **kwargs):
        return HttpResponse("This is a protected resource", 200)

    def post(self, request, *args, **kwargs):
        return HttpResponse("This is a protected resource", 200)


class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code

    def json(self):
        return self.json_data


def mocked_requests_post(url, data, *args, **kwargs):
    """
    Mock the response from the authentication server
    """

    if "token" in data and data["token"] and data["token"] != "12345678900":
        return MockResponse(
            {
                "active": True,
                "scope": "read write dolphin",
                "client_id": "client_id_{}".format(data["token"]),
                "username": "{}_user".format(data["token"]),
                "exp": int(calendar.timegm(default_exp.timetuple())),
            },
            200,
        )

    return MockResponse(
        {
            "active": False,
        },
        200,
    )


def mocked_introspect_request_short_living_token(url, data, *args, **kwargs):
    exp = datetime.datetime.now() + datetime.timedelta(minutes=30)

    return MockResponse(
        {
            "active": True,
            "scope": "read write dolphin",
            "client_id": "client_id_{}".format(data["token"]),
            "username": "{}_user".format(data["token"]),
            "exp": int(calendar.timegm(exp.timetuple())),
        },
        200,
    )


urlpatterns = [
    path("oauth2/", include("oauth2_provider.urls")),
    path("oauth2-test-resource/", login_not_required(ScopeResourceView.as_view())),
]


@override_settings(ROOT_URLCONF=__name__)
@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.INTROSPECTION_SETTINGS)
class TestTokenIntrospectionAuth(TestCase):
    """
    Tests for Authorization through token introspection
    """

    @classmethod
    def setUpTestData(cls):
        cls.validator = OAuth2Validator()
        cls.request = mock.MagicMock(wraps=Request)
        cls.resource_server_user = UserModel.objects.create_user(
            "resource_server", "test@example.com", "123456"
        )

        cls.application = Application.objects.create(
            name="Test Application",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=cls.resource_server_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

        cls.resource_server_token = AccessToken.objects.create(
            user=cls.resource_server_user,
            token="12345678900",
            application=cls.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="introspection",
        )

        cls.invalid_token = AccessToken.objects.create(
            user=cls.resource_server_user,
            token="12345678901",
            application=cls.application,
            expires=timezone.now() + datetime.timedelta(days=-1),
            scope="read write dolphin",
        )

    def setUp(self):
        self.oauth2_settings.RESOURCE_SERVER_AUTH_TOKEN = self.resource_server_token.token

    @mock.patch("requests.post", side_effect=mocked_requests_post)
    def test_get_token_from_authentication_server_not_existing_token(self, mock_get):
        """
        Test method _get_token_from_authentication_server with non existing token
        """
        token = self.validator._get_token_from_authentication_server(
            self.resource_server_token.token,
            self.oauth2_settings.RESOURCE_SERVER_INTROSPECTION_URL,
            self.oauth2_settings.RESOURCE_SERVER_AUTH_TOKEN,
            self.oauth2_settings.RESOURCE_SERVER_INTROSPECTION_CREDENTIALS,
        )
        self.assertIsNone(token)

    @mock.patch("requests.post", side_effect=mocked_requests_post)
    def test_get_token_from_authentication_server_existing_token(self, mock_get):
        """
        Test method _get_token_from_authentication_server with existing token
        """
        token = self.validator._get_token_from_authentication_server(
            "foo",
            self.oauth2_settings.RESOURCE_SERVER_INTROSPECTION_URL,
            self.oauth2_settings.RESOURCE_SERVER_AUTH_TOKEN,
            self.oauth2_settings.RESOURCE_SERVER_INTROSPECTION_CREDENTIALS,
        )
        self.assertIsInstance(token, AccessToken)
        self.assertEqual(token.user.username, "foo_user")
        self.assertEqual(token.scope, "read write dolphin")

    @mock.patch("requests.post", side_effect=mocked_introspect_request_short_living_token)
    def test_get_token_from_authentication_server_expires_no_timezone(self, mock_get):
        """
        Test method _get_token_from_authentication_server for projects with USE_TZ False
        """
        settings_use_tz_backup = settings.USE_TZ
        settings.USE_TZ = False
        try:
            access_token = self.validator._get_token_from_authentication_server(
                "foo",
                oauth2_settings.RESOURCE_SERVER_INTROSPECTION_URL,
                oauth2_settings.RESOURCE_SERVER_AUTH_TOKEN,
                oauth2_settings.RESOURCE_SERVER_INTROSPECTION_CREDENTIALS,
            )

            self.assertFalse(access_token.is_expired())
        except ValueError as exception:
            self.fail(str(exception))
        finally:
            settings.USE_TZ = settings_use_tz_backup

    @mock.patch("requests.post", side_effect=mocked_introspect_request_short_living_token)
    def test_get_token_from_authentication_server_expires_utc_timezone(self, mock_get):
        """
        Test method _get_token_from_authentication_server for projects with USE_TZ True and a UTC Timezone
        """
        settings_use_tz_backup = settings.USE_TZ
        settings_time_zone_backup = settings.TIME_ZONE
        settings.USE_TZ = True
        settings.TIME_ZONE = "UTC"
        try:
            access_token = self.validator._get_token_from_authentication_server(
                "foo",
                oauth2_settings.RESOURCE_SERVER_INTROSPECTION_URL,
                oauth2_settings.RESOURCE_SERVER_AUTH_TOKEN,
                oauth2_settings.RESOURCE_SERVER_INTROSPECTION_CREDENTIALS,
            )

            self.assertFalse(access_token.is_expired())
        except ValueError as exception:
            self.fail(str(exception))
        finally:
            settings.USE_TZ = settings_use_tz_backup
            settings.TIME_ZONE = settings_time_zone_backup

    @mock.patch("requests.post", side_effect=mocked_introspect_request_short_living_token)
    def test_get_token_from_authentication_server_expires_non_utc_timezone(self, mock_get):
        """
        Test method _get_token_from_authentication_server for projects with USE_TZ True and a non UTC Timezone

        This test is important to check if the UTC Exp. date gets converted correctly
        """
        settings_use_tz_backup = settings.USE_TZ
        settings_time_zone_backup = settings.TIME_ZONE
        settings.USE_TZ = True
        settings.TIME_ZONE = "Europe/Amsterdam"
        try:
            access_token = self.validator._get_token_from_authentication_server(
                "foo",
                oauth2_settings.RESOURCE_SERVER_INTROSPECTION_URL,
                oauth2_settings.RESOURCE_SERVER_AUTH_TOKEN,
                oauth2_settings.RESOURCE_SERVER_INTROSPECTION_CREDENTIALS,
            )

            self.assertFalse(access_token.is_expired())
        except ValueError as exception:
            self.fail(str(exception))
        finally:
            settings.USE_TZ = settings_use_tz_backup
            settings.TIME_ZONE = settings_time_zone_backup

    @mock.patch("requests.post", side_effect=mocked_requests_post)
    def test_validate_bearer_token(self, mock_get):
        """
        Test method validate_bearer_token
        """
        # with token = None
        self.assertFalse(self.validator.validate_bearer_token(None, ["dolphin"], self.request))
        # with valid token and scope
        self.assertTrue(
            self.validator.validate_bearer_token(
                self.resource_server_token.token, ["introspection"], self.request
            )
        )
        # with initially invalid token, but validated through request
        self.assertTrue(
            self.validator.validate_bearer_token(self.invalid_token.token, ["dolphin"], self.request)
        )
        # with locally unavailable token, but validated through request
        self.assertTrue(self.validator.validate_bearer_token("butzi", ["dolphin"], self.request))
        # with valid token but invalid scope
        self.assertFalse(self.validator.validate_bearer_token("foo", ["kaudawelsch"], self.request))
        # with token validated through request, but invalid scope
        self.assertFalse(self.validator.validate_bearer_token("butz", ["kaudawelsch"], self.request))
        # with token validated through request and valid scope
        self.assertTrue(self.validator.validate_bearer_token("butzi", ["dolphin"], self.request))

    @mock.patch("requests.post", side_effect=mocked_requests_post)
    def test_get_resource(self, mock_get):
        """
        Test that we can access the resource with a get request and a remotely validated token
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer bar",
        }
        response = self.client.get("/oauth2-test-resource/", **auth_headers)
        self.assertEqual(response.content.decode("utf-8"), "This is a protected resource")

    @mock.patch("requests.post", side_effect=mocked_requests_post)
    def test_post_resource(self, mock_get):
        """
        Test that we can access the resource with a post request and a remotely validated token
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer batz",
        }
        response = self.client.post("/oauth2-test-resource/", **auth_headers)
        self.assertEqual(response.content.decode("utf-8"), "This is a protected resource")
