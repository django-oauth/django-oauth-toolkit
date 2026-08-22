from datetime import timedelta

import pytest
from django.conf.urls import include
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test.utils import override_settings
from django.urls import path
from django.utils import timezone
from ninja import NinjaAPI

from oauth2_provider.contrib.ninja import (
    HttpOAuth2,
    OAuth2ClientRateThrottle,
    OAuth2UserOrClientRateThrottle,
)
from oauth2_provider.models import get_access_token_model, get_application_model

from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()

api = NinjaAPI()


@api.get("/client-throttled", auth=HttpOAuth2(), throttle=[OAuth2ClientRateThrottle("2/min")])
def client_throttled_endpoint(request):
    return {"message": "throttled per client application"}


@api.get(
    "/user-or-client-throttled",
    auth=HttpOAuth2(),
    throttle=[OAuth2UserOrClientRateThrottle("2/min")],
)
def user_or_client_throttled_endpoint(request):
    return {"message": "throttled per user, or per client for client_credentials"}


@api.get("/open-client-throttled", throttle=[OAuth2ClientRateThrottle("2/min")])
def open_client_throttled_endpoint(request):
    return {"message": "not OAuth2 authenticated"}


@api.get("/open-user-or-client-throttled", throttle=[OAuth2UserOrClientRateThrottle("2/min")])
def open_user_or_client_throttled_endpoint(request):
    return {"message": "not OAuth2 authenticated"}


urlpatterns = [
    path("oauth2/", include("oauth2_provider.urls")),
    path("api/", api.urls),
]


@pytest.fixture(autouse=True)
def _clear_throttle_cache():
    """Throttle history lives in Django's cache; isolate it per test."""
    cache.clear()
    yield
    cache.clear()


@override_settings(ROOT_URLCONF=__name__)
@pytest.mark.nologinrequiredmiddleware
@pytest.mark.usefixtures("oauth2_settings")
class TestNinjaThrottling(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")
        cls.test_user = UserModel.objects.create_user("test_user", "test@example.com", "123456")
        cls.other_user = UserModel.objects.create_user("other_user", "other@example.com", "123456")

        cls.application = Application.objects.create(
            name="Machine Client",
            user=cls.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
        )
        cls.other_application = Application.objects.create(
            name="Other Machine Client",
            user=cls.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
        )

        # `client_credentials` tokens have no user: OAuth2Validator._create_access_token
        # sets `request.user = None` for that grant.
        cls.client_token = cls._create_token("client-credentials-token", None, cls.application)
        cls.rotated_client_token = cls._create_token("rotated-token", None, cls.application)
        cls.other_client_token = cls._create_token("other-client-token", None, cls.other_application)
        cls.user_token = cls._create_token("user-token", cls.test_user, cls.application)
        cls.other_user_token = cls._create_token("other-user-token", cls.other_user, cls.application)

    @classmethod
    def _create_token(cls, token, user, application):
        return AccessToken.objects.create(
            user=user,
            scope="read write",
            expires=timezone.now() + timedelta(seconds=300),
            token=token,
            application=application,
        )

    def _get(self, url, token=None, remote_addr="127.0.0.1"):
        extra = {"REMOTE_ADDR": remote_addr}
        if token is not None:
            extra["HTTP_AUTHORIZATION"] = "Bearer {0}".format(token)
        return self.client.get(url, **extra)

    def test_client_credentials_requests_are_throttled(self):
        for _ in range(2):
            response = self._get("/api/client-throttled", self.client_token.token)
            self.assertEqual(response.status_code, 200)

        response = self._get("/api/client-throttled", self.client_token.token)
        self.assertEqual(response.status_code, 429)

    def test_each_client_gets_its_own_bucket_behind_a_shared_address(self):
        for _ in range(2):
            response = self._get("/api/client-throttled", self.client_token.token, "203.0.113.7")
            self.assertEqual(response.status_code, 200)

        response = self._get("/api/client-throttled", self.client_token.token, "203.0.113.7")
        self.assertEqual(response.status_code, 429)

        response = self._get("/api/client-throttled", self.other_client_token.token, "203.0.113.7")
        self.assertEqual(response.status_code, 200)

    def test_rotating_the_token_does_not_reset_the_bucket(self):
        """Unlike Ninja's AuthRateThrottle, which keys on str(request.auth)."""
        for _ in range(2):
            response = self._get("/api/client-throttled", self.client_token.token)
            self.assertEqual(response.status_code, 200)

        response = self._get("/api/client-throttled", self.rotated_client_token.token)
        self.assertEqual(response.status_code, 429)

    def test_client_throttle_ignores_non_oauth2_requests(self):
        for _ in range(3):
            response = self._get("/api/open-client-throttled")
            self.assertEqual(response.status_code, 200)

    def test_user_or_client_throttle_keys_user_tokens_by_user(self):
        for _ in range(2):
            response = self._get("/api/user-or-client-throttled", self.user_token.token)
            self.assertEqual(response.status_code, 200)

        response = self._get("/api/user-or-client-throttled", self.user_token.token)
        self.assertEqual(response.status_code, 429)

        response = self._get("/api/user-or-client-throttled", self.other_user_token.token)
        self.assertEqual(response.status_code, 200)

    def test_user_or_client_throttle_keys_client_credentials_by_client(self):
        for _ in range(2):
            response = self._get("/api/user-or-client-throttled", self.client_token.token)
            self.assertEqual(response.status_code, 200)

        response = self._get("/api/user-or-client-throttled", self.client_token.token)
        self.assertEqual(response.status_code, 429)

        response = self._get("/api/user-or-client-throttled", self.other_client_token.token)
        self.assertEqual(response.status_code, 200)

    def test_user_or_client_throttle_falls_back_to_ip_when_unauthenticated(self):
        for _ in range(2):
            response = self._get("/api/open-user-or-client-throttled", remote_addr="198.51.100.5")
            self.assertEqual(response.status_code, 200)

        response = self._get("/api/open-user-or-client-throttled", remote_addr="198.51.100.5")
        self.assertEqual(response.status_code, 429)

        response = self._get("/api/open-user-or-client-throttled", remote_addr="198.51.100.6")
        self.assertEqual(response.status_code, 200)
