from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import SuspiciousOperation
from django.http import HttpResponse
from django.test import RequestFactory
from django.test.utils import modify_settings, override_settings
from django.utils.timezone import now, timedelta

from oauth2_provider.backends import OAuth2Backend
from oauth2_provider.middleware import OAuth2ExtraTokenMiddleware, OAuth2TokenMiddleware
from oauth2_provider.models import get_access_token_model, get_application_model

from .common_testing import OAuth2ProviderTestCase as TestCase


UserModel = get_user_model()
ApplicationModel = get_application_model()
AccessTokenModel = get_access_token_model()


class BaseTest(TestCase):
    """
    Base class for cases in this module
    """

    factory = RequestFactory()

    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("user", "test@example.com", "123456")
        cls.app = ApplicationModel.objects.create(
            name="app",
            client_type=ApplicationModel.CLIENT_CONFIDENTIAL,
            authorization_grant_type=ApplicationModel.GRANT_CLIENT_CREDENTIALS,
            user=cls.user,
        )
        cls.token = AccessTokenModel.objects.create(
            user=cls.user, token="tokstr", application=cls.app, expires=now() + timedelta(days=365)
        )


class TestOAuth2Backend(BaseTest):
    def test_authenticate(self):
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + "tokstr",
        }
        request = self.factory.get("/a-resource", **auth_headers)

        backend = OAuth2Backend()
        credentials = {"request": request}
        u = backend.authenticate(**credentials)
        self.assertEqual(u, self.user)

    def test_authenticate_raises_error_with_invalid_hex_in_query_params(self):
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + "tokstr",
        }
        request = self.factory.get("/a-resource?auth_token=%%7A", **auth_headers)
        credentials = {"request": request}

        with pytest.raises(SuspiciousOperation):
            OAuth2Backend().authenticate(**credentials)

    @patch("oauth2_provider.backends.OAuthLibCore.verify_request")
    def test_value_errors_are_reraised(self, patched_verify_request):
        patched_verify_request.side_effect = ValueError("Generic error")

        with pytest.raises(ValueError):
            OAuth2Backend().authenticate(request={})

    def test_authenticate_fail(self):
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + "badstring",
        }
        request = self.factory.get("/a-resource", **auth_headers)

        backend = OAuth2Backend()
        credentials = {"request": request}
        self.assertIsNone(backend.authenticate(**credentials))

        credentials = {"username": "u", "password": "p"}
        self.assertIsNone(backend.authenticate(**credentials))

    def test_get_user(self):
        backend = OAuth2Backend()
        self.assertEqual(self.user, backend.get_user(self.user.pk))
        self.assertIsNone(backend.get_user(123456))


@override_settings(
    AUTHENTICATION_BACKENDS=(
        "oauth2_provider.backends.OAuth2Backend",
        "django.contrib.auth.backends.ModelBackend",
    ),
)
@modify_settings(
    MIDDLEWARE={
        "append": "oauth2_provider.middleware.OAuth2TokenMiddleware",
    }
)
class TestOAuth2Middleware(BaseTest):
    def dummy_get_response(self, request):
        return HttpResponse()

    def test_middleware_wrong_headers(self):
        m = OAuth2TokenMiddleware(self.dummy_get_response)
        request = self.factory.get("/a-resource")
        m(request)
        self.assertFalse(hasattr(request, "user"))
        auth_headers = {
            "HTTP_AUTHORIZATION": "Beerer " + "badstring",  # a Beer token for you!
        }
        request = self.factory.get("/a-resource", **auth_headers)
        m(request)
        self.assertFalse(hasattr(request, "user"))

    def test_middleware_user_is_set(self):
        m = OAuth2TokenMiddleware(self.dummy_get_response)
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + "tokstr",
        }
        request = self.factory.get("/a-resource", **auth_headers)
        request.user = self.user
        m(request)
        self.assertIs(request.user, self.user)
        request.user = AnonymousUser()
        m(request)
        self.assertEqual(request.user.pk, self.user.pk)

    def test_middleware_success(self):
        m = OAuth2TokenMiddleware(self.dummy_get_response)
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + "tokstr",
        }
        request = self.factory.get("/a-resource", **auth_headers)
        m(request)
        self.assertEqual(request.user, self.user)

    def test_middleware_response(self):
        m = OAuth2TokenMiddleware(self.dummy_get_response)
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + "tokstr",
        }
        request = self.factory.get("/a-resource", **auth_headers)
        response = m(request)
        self.assertIsInstance(response, HttpResponse)

    def test_middleware_response_header(self):
        m = OAuth2TokenMiddleware(self.dummy_get_response)
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + "tokstr",
        }
        request = self.factory.get("/a-resource", **auth_headers)
        response = m(request)
        self.assertIn("Vary", response)
        self.assertIn("Authorization", response["Vary"])


@override_settings(
    AUTHENTICATION_BACKENDS=(
        "oauth2_provider.backends.OAuth2Backend",
        "django.contrib.auth.backends.ModelBackend",
    ),
)
@modify_settings(
    MIDDLEWARE={
        "append": "oauth2_provider.middleware.OAuth2TokenMiddleware",
    }
)
class TestOAuth2ExtraTokenMiddleware(BaseTest):
    def dummy_get_response(self, request):
        return HttpResponse()

    def test_middleware_wrong_headers(self):
        m = OAuth2ExtraTokenMiddleware(self.dummy_get_response)
        request = self.factory.get("/a-resource")
        m(request)
        self.assertFalse(hasattr(request, "access_token"))
        auth_headers = {
            "HTTP_AUTHORIZATION": "Beerer " + "badstring",  # a Beer token for you!
        }
        request = self.factory.get("/a-resource", **auth_headers)
        m(request)
        self.assertFalse(hasattr(request, "access_token"))

    def test_middleware_token_does_not_exist(self):
        m = OAuth2ExtraTokenMiddleware(self.dummy_get_response)
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + "badtokstr",
        }
        request = self.factory.get("/a-resource", **auth_headers)
        m(request)
        self.assertFalse(hasattr(request, "access_token"))

    def test_middleware_success(self):
        m = OAuth2ExtraTokenMiddleware(self.dummy_get_response)
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + "tokstr",
        }
        request = self.factory.get("/a-resource", **auth_headers)
        m(request)
        self.assertEqual(request.access_token, self.token)

    def test_middleware_response(self):
        m = OAuth2ExtraTokenMiddleware(self.dummy_get_response)
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + "tokstr",
        }
        request = self.factory.get("/a-resource", **auth_headers)
        response = m(request)
        self.assertIsInstance(response, HttpResponse)
