from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.test.utils import override_settings
from django.urls import include, path
from django.utils import timezone
from ninja import NinjaAPI
from ninja.security import django_auth

from oauth2_provider.contrib.ninja import HttpOAuth2
from oauth2_provider.models import get_access_token_model, get_application_model

from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()


class StaffOnlyOAuth2(HttpOAuth2):
    def authenticate(self, request, access_token):
        if access_token.user is None or not access_token.user.is_staff:
            return None
        return access_token


api = NinjaAPI()


@api.get("/private", auth=HttpOAuth2())
def private_endpoint(request):
    return {"message": "This is a private endpoint"}


@api.get("/write", auth=HttpOAuth2(scopes=["write"]))
def scoped_endpoint(request):
    return {"message": "This requires 'write' scope"}


@api.get("/impossible", auth=HttpOAuth2(scopes=["impossible"]))
def scoped_impossible_endpoint(request):
    return {"message": "This requires 'impossible' scope"}


@api.get("/request-attributes", auth=HttpOAuth2())
def request_attributes_endpoint(request):
    return {
        "request_user_username": request.user.username,
        "request_user_is_authenticated": request.user.is_authenticated,
        "request_user_is_anonymous": request.user.is_anonymous,
        "request_auth_token": request.auth.token,
    }


@api.get("/staff-only", auth=StaffOnlyOAuth2())
def staff_only_endpoint(request):
    return {"request_user_username": request.user.username}


@api.get("/staff-only-or-session", auth=[StaffOnlyOAuth2(), django_auth])
def staff_only_or_session_endpoint(request):
    return {"request_user_username": request.user.username}


urlpatterns = [
    path("oauth2/", include("oauth2_provider.urls")),
    path("api/", api.urls),
]


@override_settings(ROOT_URLCONF=__name__)
@pytest.mark.nologinrequiredmiddleware
@pytest.mark.usefixtures("oauth2_settings")
class TestNinja(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.test_user = UserModel.objects.create_user("test_user", "test@example.com", "123456")
        cls.dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")

        cls.application = Application.objects.create(
            name="Test Application",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=cls.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

        cls.access_token = AccessToken.objects.create(
            user=cls.test_user,
            scope="read write",
            expires=timezone.now() + timedelta(seconds=300),
            token="secret-access-token-key",
            application=cls.application,
        )

        cls.staff_user = UserModel.objects.create_user(
            "staff_user", "staff@example.com", "123456", is_staff=True
        )
        cls.staff_access_token = AccessToken.objects.create(
            user=cls.staff_user,
            scope="read write",
            expires=timezone.now() + timedelta(seconds=300),
            token="secret-staff-access-token-key",
            application=cls.application,
        )

        # `client_credentials` tokens have no user
        cls.userless_access_token = AccessToken.objects.create(
            user=None,
            scope="read write",
            expires=timezone.now() + timedelta(seconds=300),
            token="secret-userless-access-token-key",
            application=cls.application,
        )

    def _create_authorization_header(self, token):
        return "Bearer {0}".format(token)

    def test_valid_token(self):
        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/api/private", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    def test_missing_token(self):
        response = self.client.get("/api/private")
        self.assertEqual(response.status_code, 401)

    def test_invalid_token(self):
        auth = self._create_authorization_header("invalid")
        response = self.client.get("/api/private", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 401)

    def test_valid_token_with_scope(self):
        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/api/write", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    def test_valid_token_absent_scope(self):
        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/api/impossible", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 401)

    def test_invalid_hex_string_in_query(self):
        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/api/private?q=73%%20of%20Arkansans", HTTP_AUTHORIZATION=auth)
        # Should respond with a 400 rather than raise a ValueError
        self.assertEqual(response.status_code, 400)

    def test_request_attributes(self):
        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/api/request-attributes", HTTP_AUTHORIZATION=auth)

        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertEqual(response_data["request_user_username"], self.test_user.username)
        self.assertIs(response_data["request_user_is_authenticated"], True)
        self.assertIs(response_data["request_user_is_anonymous"], False)
        self.assertEqual(response_data["request_auth_token"], self.access_token.token)

    def test_request_attributes_userless_token(self):
        auth = self._create_authorization_header(self.userless_access_token.token)
        response = self.client.get("/api/request-attributes", HTTP_AUTHORIZATION=auth)

        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        # `request.user` should be an `AnonymousUser`, not `None`
        self.assertEqual(response_data["request_user_username"], "")
        self.assertIs(response_data["request_user_is_authenticated"], False)
        self.assertIs(response_data["request_user_is_anonymous"], True)
        # The request is still authenticated by Ninja, with the token as `request.auth`
        self.assertEqual(response_data["request_auth_token"], self.userless_access_token.token)

    def test_userless_token_overrides_session_user(self):
        self.client.force_login(self.test_user)
        auth = self._create_authorization_header(self.userless_access_token.token)
        response = self.client.get("/api/request-attributes", HTTP_AUTHORIZATION=auth)

        self.assertEqual(response.status_code, 200)
        self.assertIs(response.json()["request_user_is_authenticated"], False)

    def test_subclass_authenticate_accepted(self):
        auth = self._create_authorization_header(self.staff_access_token.token)
        response = self.client.get("/api/staff-only", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["request_user_username"], self.staff_user.username)

    def test_subclass_authenticate_rejected(self):
        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/api/staff-only", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 401)

    def test_subclass_authenticate_rejected_with_fallback(self):
        # A rejected token must not set `request.user`, or else `django_auth` would accept it
        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/api/staff-only-or-session", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 401)

    def test_subclass_authenticate_rejected_with_fallback_session(self):
        # A rejected token must not overwrite the `request.user` from a valid session
        self.client.force_login(self.dev_user)
        auth = self._create_authorization_header(self.userless_access_token.token)
        response = self.client.get("/api/staff-only-or-session", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["request_user_username"], self.dev_user.username)
