"""End-to-end coverage for a dynamic ``ACCESS_TOKEN_EXPIRE_SECONDS``.

The setting may be a number of seconds, a ``timedelta``, or a callable taking the
oauthlib request, which is how a deployment varies the access token lifetime per
client, grant type, scope or session (issue #483). What is asserted here is that the
resolved lifetime reaches *both* the ``expires_in`` the client is told and the
``AccessToken.expires`` that is stored, and that the two agree.
"""

import json
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from oauthlib.common import Request

from oauth2_provider.models import get_access_token_model, get_application_model
from oauth2_provider.oauth2_validators import OAuth2Validator

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"

PASSWORD_EXPIRES_IN = 111
CLIENT_CREDENTIALS_EXPIRES_IN = 222
DEFAULT_EXPIRES_IN = 333


def expires_in_by_grant_type(request):
    """Sample per-grant-type lifetime, wired in as ACCESS_TOKEN_EXPIRE_SECONDS below."""
    return {
        "password": PASSWORD_EXPIRES_IN,
        "client_credentials": CLIENT_CREDENTIALS_EXPIRES_IN,
    }.get(request.grant_type, DEFAULT_EXPIRES_IN)


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.DEFAULT_SCOPES_RW)
class BaseTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.test_user = UserModel.objects.create_user("test_user", "test@example.com", "123456")
        cls.dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")

        cls.password_app = Application.objects.create(
            name="test_password_app",
            user=cls.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
            client_secret=CLEARTEXT_SECRET,
        )
        cls.client_credentials_app = Application.objects.create(
            name="test_client_credentials_app",
            user=cls.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            client_secret=CLEARTEXT_SECRET,
        )

    def post_token(self, application, **data):
        auth_headers = get_basic_auth_header(application.client_id, CLEARTEXT_SECRET)
        response = self.client.post(reverse("oauth2_provider:token"), data=data, **auth_headers)
        self.assertEqual(response.status_code, 200, response.content)
        return json.loads(response.content.decode("utf-8"))

    def assertStoredExpiryMatches(self, content):
        """The persisted expiry must agree with the ``expires_in`` handed to the client."""
        access_token = AccessToken.objects.get(token=content["access_token"])
        remaining = (access_token.expires - timezone.now()).total_seconds()
        # A second of slack for the time between issuing the token and this assertion.
        self.assertAlmostEqual(remaining, content["expires_in"], delta=1)


class TestCallableAccessTokenExpiry(BaseTest):
    def setUp(self):
        super().setUp()
        self.oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS = expires_in_by_grant_type

    def test_password_grant_uses_the_callable(self):
        content = self.post_token(
            self.password_app, grant_type="password", username="test_user", password="123456"
        )
        self.assertEqual(content["expires_in"], PASSWORD_EXPIRES_IN)
        self.assertStoredExpiryMatches(content)

    def test_client_credentials_grant_uses_the_callable(self):
        content = self.post_token(self.client_credentials_app, grant_type="client_credentials")
        self.assertEqual(content["expires_in"], CLIENT_CREDENTIALS_EXPIRES_IN)
        self.assertStoredExpiryMatches(content)

    def test_one_setting_serves_both_grant_types(self):
        """The point of a callable: two grant types, two lifetimes, one setting."""
        password = self.post_token(
            self.password_app, grant_type="password", username="test_user", password="123456"
        )
        client_credentials = self.post_token(self.client_credentials_app, grant_type="client_credentials")
        self.assertNotEqual(password["expires_in"], client_credentials["expires_in"])

    def test_refresh_re_evaluates_the_callable(self):
        """A refreshed access token gets the lifetime of the refresh request, not the original."""
        content = self.post_token(
            self.password_app, grant_type="password", username="test_user", password="123456"
        )
        self.assertEqual(content["expires_in"], PASSWORD_EXPIRES_IN)

        refreshed = self.post_token(
            self.password_app, grant_type="refresh_token", refresh_token=content["refresh_token"]
        )
        self.assertEqual(refreshed["expires_in"], DEFAULT_EXPIRES_IN)
        self.assertStoredExpiryMatches(refreshed)


class TestTimedeltaAccessTokenExpiry(BaseTest):
    def test_timedelta_setting_is_reported_in_seconds(self):
        self.oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS = timedelta(minutes=7)
        content = self.post_token(self.client_credentials_app, grant_type="client_credentials")
        self.assertEqual(content["expires_in"], 420)
        self.assertStoredExpiryMatches(content)


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.DEFAULT_SCOPES_RW)
class TestSaveBearerTokenFallback(TestCase):
    """``_save_bearer_token`` must resolve the setting when the token dict omits ``expires_in``.

    oauthlib's own token handlers always populate ``expires_in``, but a custom server or
    token class need not, and before #483 that path fed the raw setting straight to
    ``timedelta(seconds=...)`` -- which raises ``TypeError`` for a callable.
    """

    @classmethod
    def setUpTestData(cls):
        cls.dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")
        cls.application = Application.objects.create(
            name="test_app",
            user=cls.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            client_secret=CLEARTEXT_SECRET,
        )

    def _save(self, token):
        request = Request("/o/token/")
        request.grant_type = "client_credentials"
        request.client = self.application
        request.user = None
        OAuth2Validator().save_bearer_token(token, request)
        return AccessToken.objects.get(token=token["access_token"])

    def test_callable_setting_is_resolved_when_token_omits_expires_in(self):
        self.oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS = expires_in_by_grant_type
        access_token = self._save({"access_token": "no-expires-in", "scope": "read write"})
        remaining = (access_token.expires - timezone.now()).total_seconds()
        self.assertAlmostEqual(remaining, CLIENT_CREDENTIALS_EXPIRES_IN, delta=1)

    def test_token_expires_in_still_wins_over_the_setting(self):
        self.oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS = expires_in_by_grant_type
        access_token = self._save(
            {"access_token": "explicit-expires-in", "scope": "read write", "expires_in": 60}
        )
        remaining = (access_token.expires - timezone.now()).total_seconds()
        self.assertAlmostEqual(remaining, 60, delta=1)
