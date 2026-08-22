from datetime import timedelta

import pytest
from django.conf.urls import include
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.http import HttpResponse
from django.test.utils import override_settings
from django.urls import path
from django.utils import timezone
from rest_framework import permissions
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory
from rest_framework.views import APIView

from oauth2_provider.contrib.rest_framework import (
    OAuth2Authentication,
    OAuth2ClientRateThrottle,
    OAuth2UserOrClientRateThrottle,
    TokenHasScope,
)
from oauth2_provider.core.throttling import get_client_ident, get_user_or_client_ident
from oauth2_provider.models import get_access_token_model, get_application_model

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()


class TwoPerMinuteClientThrottle(OAuth2ClientRateThrottle):
    rate = "2/min"


class TwoPerMinuteUserOrClientThrottle(OAuth2UserOrClientRateThrottle):
    rate = "2/min"


class MockView(APIView):
    authentication_classes = [OAuth2Authentication]
    permission_classes = [TokenHasScope]
    required_scopes = ["read"]

    def get(self, request):
        return HttpResponse({"a": 1, "b": 2, "c": 3})


class ClientThrottledView(MockView):
    throttle_classes = [TwoPerMinuteClientThrottle]


class UserOrClientThrottledView(MockView):
    throttle_classes = [TwoPerMinuteUserOrClientThrottle]


class OpenClientThrottledView(ClientThrottledView):
    permission_classes = [permissions.AllowAny]


class OpenUserOrClientThrottledView(UserOrClientThrottledView):
    permission_classes = [permissions.AllowAny]


urlpatterns = [
    path("oauth2/", include("oauth2_provider.urls")),
    path("oauth2-client-throttled/", ClientThrottledView.as_view()),
    path("oauth2-user-or-client-throttled/", UserOrClientThrottledView.as_view()),
    path("open-client-throttled/", OpenClientThrottledView.as_view()),
    path("open-user-or-client-throttled/", OpenUserOrClientThrottledView.as_view()),
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
@pytest.mark.oauth2_settings(presets.REST_FRAMEWORK_SCOPES)
class TestOAuth2Throttling(TestCase):
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

    def _drf_request(self, user=None, auth=None, remote_addr="127.0.0.1"):
        """A DRF request with authentication already resolved, as a throttle sees it."""
        request = Request(APIRequestFactory().get("/", REMOTE_ADDR=remote_addr))
        request.user = user
        request.auth = auth
        return request

    def _get(self, url, token=None, remote_addr="127.0.0.1"):
        extra = {"REMOTE_ADDR": remote_addr}
        if token is not None:
            extra["HTTP_AUTHORIZATION"] = "Bearer {0}".format(token)
        return self.client.get(url, **extra)

    def test_client_credentials_requests_are_throttled(self):
        """A userless token is throttled at all, rather than sliding into the IP bucket."""
        for _ in range(2):
            response = self._get("/oauth2-client-throttled/", self.client_token.token)
            self.assertEqual(response.status_code, 200)

        response = self._get("/oauth2-client-throttled/", self.client_token.token)
        self.assertEqual(response.status_code, 429)

    def test_each_client_gets_its_own_bucket_behind_a_shared_address(self):
        """The point of #984: two machine clients on one egress address do not share a bucket."""
        for _ in range(2):
            response = self._get("/oauth2-client-throttled/", self.client_token.token, "203.0.113.7")
            self.assertEqual(response.status_code, 200)

        response = self._get("/oauth2-client-throttled/", self.client_token.token, "203.0.113.7")
        self.assertEqual(response.status_code, 429)

        response = self._get("/oauth2-client-throttled/", self.other_client_token.token, "203.0.113.7")
        self.assertEqual(response.status_code, 200)

    def test_rotating_the_token_does_not_reset_the_bucket(self):
        """The bucket follows the client, not the token, so re-issuing one buys nothing."""
        for _ in range(2):
            response = self._get("/oauth2-client-throttled/", self.client_token.token)
            self.assertEqual(response.status_code, 200)

        response = self._get("/oauth2-client-throttled/", self.rotated_client_token.token)
        self.assertEqual(response.status_code, 429)

    def test_client_throttle_ignores_non_oauth2_requests(self):
        """Unthrottled here, so the class can be combined with whatever covers the rest."""
        response = self._get("/open-client-throttled/")
        self.assertEqual(response.status_code, 200)

        request = self._drf_request(user=self.test_user)
        self.assertIsNone(TwoPerMinuteClientThrottle().get_cache_key(request, OpenClientThrottledView()))

    def test_user_or_client_throttle_keys_user_tokens_by_user(self):
        """Two users of one application are throttled apart, matching UserRateThrottle."""
        for _ in range(2):
            response = self._get("/oauth2-user-or-client-throttled/", self.user_token.token)
            self.assertEqual(response.status_code, 200)

        response = self._get("/oauth2-user-or-client-throttled/", self.user_token.token)
        self.assertEqual(response.status_code, 429)

        response = self._get("/oauth2-user-or-client-throttled/", self.other_user_token.token)
        self.assertEqual(response.status_code, 200)

    def test_user_or_client_throttle_keys_client_credentials_by_client(self):
        for _ in range(2):
            response = self._get("/oauth2-user-or-client-throttled/", self.client_token.token)
            self.assertEqual(response.status_code, 200)

        response = self._get("/oauth2-user-or-client-throttled/", self.client_token.token)
        self.assertEqual(response.status_code, 429)

        response = self._get("/oauth2-user-or-client-throttled/", self.other_client_token.token)
        self.assertEqual(response.status_code, 200)

    def test_user_and_client_idents_do_not_collide(self):
        """A user and an application that share a primary key must not share a bucket."""
        token_with_user = AccessToken(user_id=5, application_id=9)
        userless_token = AccessToken(user_id=None, application_id=5)

        self.assertEqual(get_user_or_client_ident(token_with_user), "user-5")
        self.assertEqual(get_user_or_client_ident(userless_token), "client-5")
        self.assertEqual(get_client_ident(token_with_user), "client-9")

    def test_idents_are_none_for_non_oauth2_credentials(self):
        """`request.auth` set by some other authentication class is left alone."""
        self.assertIsNone(get_client_ident(None))
        self.assertIsNone(get_user_or_client_ident(None))
        self.assertIsNone(get_client_ident("some-other-tokens-value"))
        self.assertIsNone(get_user_or_client_ident("some-other-tokens-value"))

    def test_user_or_client_throttle_falls_back_to_session_user(self):
        request = self._drf_request(user=self.test_user)

        key = TwoPerMinuteUserOrClientThrottle().get_cache_key(request, OpenUserOrClientThrottledView())
        self.assertEqual(key, "throttle_oauth2_user-{0}".format(self.test_user.pk))

    def test_user_or_client_throttle_falls_back_to_ip_when_unauthenticated(self):
        for _ in range(2):
            response = self._get("/open-user-or-client-throttled/", remote_addr="198.51.100.5")
            self.assertEqual(response.status_code, 200)

        response = self._get("/open-user-or-client-throttled/", remote_addr="198.51.100.5")
        self.assertEqual(response.status_code, 429)

        response = self._get("/open-user-or-client-throttled/", remote_addr="198.51.100.6")
        self.assertEqual(response.status_code, 200)

    def test_token_without_application_is_not_client_throttled(self):
        """AccessToken.application is nullable; such a token has no client to key on."""
        orphan_token = self._create_token("orphan-token", None, None)
        request = self._drf_request(auth=orphan_token)

        self.assertIsNone(TwoPerMinuteClientThrottle().get_cache_key(request, OpenClientThrottledView()))
        self.assertEqual(
            TwoPerMinuteUserOrClientThrottle().get_cache_key(request, OpenUserOrClientThrottledView()),
            "throttle_oauth2_127.0.0.1",
        )
