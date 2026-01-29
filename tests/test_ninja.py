from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.test.utils import override_settings
from django.urls import include, path
from django.utils import timezone
from ninja import NinjaAPI

from oauth2_provider.contrib.ninja import HttpOAuth2
from oauth2_provider.models import get_access_token_model, get_application_model

from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()

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
