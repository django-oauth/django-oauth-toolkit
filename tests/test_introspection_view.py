import calendar
import datetime

import pytest
from django.contrib.auth import get_user_model
from django.db import router
from django.urls import reverse
from django.utils import timezone

from oauth2_provider.models import get_access_token_model, get_application_model

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.INTROSPECTION_SETTINGS)
class TestTokenIntrospectionViews(TestCase):
    """
    Tests for Authorized Token Introspection Views
    """

    @classmethod
    def setUpTestData(cls):
        cls.resource_server_user = UserModel.objects.create_user("resource_server", "test@example.com")
        cls.test_user = UserModel.objects.create_user("bar_user", "dev@example.com")

        cls.application = Application.objects.create(
            name="Test Application",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=cls.test_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
        )

        cls.resource_server_token = AccessToken.objects.create(
            user=cls.resource_server_user,
            token="12345678900",
            application=cls.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="introspection",
        )

        cls.valid_token = AccessToken.objects.create(
            user=cls.test_user,
            token="12345678901",
            application=cls.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write dolphin",
        )

        cls.invalid_token = AccessToken.objects.create(
            user=cls.test_user,
            token="12345678902",
            application=cls.application,
            expires=timezone.now() + datetime.timedelta(days=-1),
            scope="read write dolphin",
        )

        cls.token_without_user = AccessToken.objects.create(
            user=None,
            token="12345678903",
            application=cls.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write dolphin",
        )

        cls.token_without_app = AccessToken.objects.create(
            user=cls.test_user,
            token="12345678904",
            application=None,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write dolphin",
        )

    def test_view_forbidden(self):
        """
        Test that the view is restricted for logged-in users.
        """
        response = self.client.get(reverse("oauth2_provider:introspect"))
        self.assertEqual(response.status_code, 403)

    def test_view_get_valid_token(self):
        """
        Test that when you pass a valid token as URL parameter,
        a json with an active token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.get(
            reverse("oauth2_provider:introspect"), {"token": self.valid_token.token}, **auth_headers
        )

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(
            content,
            {
                "active": True,
                "scope": self.valid_token.scope,
                "client_id": self.valid_token.application.client_id,
                "username": self.valid_token.user.get_username(),
                "exp": int(calendar.timegm(self.valid_token.expires.timetuple())),
            },
        )

    def test_view_get_valid_token_without_user(self):
        """
        Test that when you pass a valid token as URL parameter,
        a json with an active token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.get(
            reverse("oauth2_provider:introspect"), {"token": self.token_without_user.token}, **auth_headers
        )

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(
            content,
            {
                "active": True,
                "scope": self.token_without_user.scope,
                "client_id": self.token_without_user.application.client_id,
                "exp": int(calendar.timegm(self.token_without_user.expires.timetuple())),
            },
        )

    def test_view_get_valid_token_without_app(self):
        """
        Test that when you pass a valid token as URL parameter,
        a json with an active token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.get(
            reverse("oauth2_provider:introspect"), {"token": self.token_without_app.token}, **auth_headers
        )

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(
            content,
            {
                "active": True,
                "scope": self.token_without_app.scope,
                "username": self.token_without_app.user.get_username(),
                "exp": int(calendar.timegm(self.token_without_app.expires.timetuple())),
            },
        )

    def test_view_get_invalid_token(self):
        """
        Test that when you pass an invalid token as URL parameter,
        a json with an inactive token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.get(
            reverse("oauth2_provider:introspect"), {"token": self.invalid_token.token}, **auth_headers
        )

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(
            content,
            {
                "active": False,
            },
        )

    def test_view_get_notexisting_token(self):
        """
        Test that when you pass an non existing token as URL parameter,
        a json with an inactive token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.get(
            reverse("oauth2_provider:introspect"), {"token": "kaudawelsch"}, **auth_headers
        )

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(
            content,
            {
                "active": False,
            },
        )

    def test_view_post_valid_token(self):
        """
        Test that when you pass a valid token as form parameter,
        a json with an active token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.post(
            reverse("oauth2_provider:introspect"), {"token": self.valid_token.token}, **auth_headers
        )

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(
            content,
            {
                "active": True,
                "scope": self.valid_token.scope,
                "client_id": self.valid_token.application.client_id,
                "username": self.valid_token.user.get_username(),
                "exp": int(calendar.timegm(self.valid_token.expires.timetuple())),
            },
        )

    def test_view_post_invalid_token(self):
        """
        Test that when you pass an invalid token as form parameter,
        a json with an inactive token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.post(
            reverse("oauth2_provider:introspect"), {"token": self.invalid_token.token}, **auth_headers
        )

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(
            content,
            {
                "active": False,
            },
        )

    def test_view_post_notexisting_token(self):
        """
        Test that when you pass an non existing token as form parameter,
        a json with an inactive token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.post(
            reverse("oauth2_provider:introspect"), {"token": "kaudawelsch"}, **auth_headers
        )

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(
            content,
            {
                "active": False,
            },
        )

    def test_view_post_no_token(self):
        """
        Test that when you pass no token HTTP 400 is returned
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.post(reverse("oauth2_provider:introspect"), **auth_headers)

        self.assertEqual(response.status_code, 400)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertEqual(content["error"], "invalid_request")

    def test_view_post_valid_client_creds_basic_auth(self):
        """Test HTTP basic auth working"""
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        response = self.client.post(
            reverse("oauth2_provider:introspect"), {"token": self.valid_token.token}, **auth_headers
        )
        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(
            content,
            {
                "active": True,
                "scope": self.valid_token.scope,
                "client_id": self.valid_token.application.client_id,
                "username": self.valid_token.user.get_username(),
                "exp": int(calendar.timegm(self.valid_token.expires.timetuple())),
            },
        )

    def test_view_post_invalid_client_creds_basic_auth(self):
        """Must fail for invalid client credentials"""
        auth_headers = get_basic_auth_header(self.application.client_id, f"{CLEARTEXT_SECRET}_so_wrong")
        response = self.client.post(
            reverse("oauth2_provider:introspect"), {"token": self.valid_token.token}, **auth_headers
        )
        self.assertEqual(response.status_code, 403)

    def test_view_post_valid_client_creds_plaintext(self):
        """Test introspecting with credentials in request body"""
        response = self.client.post(
            reverse("oauth2_provider:introspect"),
            {
                "token": self.valid_token.token,
                "client_id": self.application.client_id,
                "client_secret": CLEARTEXT_SECRET,
            },
        )
        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(
            content,
            {
                "active": True,
                "scope": self.valid_token.scope,
                "client_id": self.valid_token.application.client_id,
                "username": self.valid_token.user.get_username(),
                "exp": int(calendar.timegm(self.valid_token.expires.timetuple())),
            },
        )

    def test_view_post_invalid_client_creds_plaintext(self):
        """Must fail for invalid creds in request body."""
        response = self.client.post(
            reverse("oauth2_provider:introspect"),
            {
                "token": self.valid_token.token,
                "client_id": self.application.client_id,
                "client_secret": f"{CLEARTEXT_SECRET}_so_wrong",
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_select_related_in_view_for_less_db_queries(self):
        token_database = router.db_for_write(AccessToken)
        with self.assertNumQueries(1, using=token_database):
            self.client.post(reverse("oauth2_provider:introspect"))
