import hashlib
from copy import deepcopy
from http.cookies import SimpleCookie

import pytest
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django.test.utils import modify_settings

from oauth2_provider.utils import session_management_state_key

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase


PRESET_OIDC_MIDDLEWARE = deepcopy(presets.OIDC_SETTINGS_SESSION_MANAGEMENT)
PRESET_OIDC_MIDDLEWARE["OIDC_SESSION_MANAGEMENT_COOKIE_NAME"] = "oidc-session-test"

User = get_user_model()


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(PRESET_OIDC_MIDDLEWARE)
@modify_settings(MIDDLEWARE={"append": "oauth2_provider.middleware.OIDCSessionManagementMiddleware"})
class TestOIDCSessionManagementMiddleware(TestCase):
    def setUp(self):
        User.objects.create_user("test_user", "test@example.com", "123456")

    def test_response_is_intact_if_session_management_is_disabled(self):
        self.oauth2_settings.OIDC_SESSION_MANAGEMENT_ENABLED = False
        response = self.client.get("/a-resource")
        self.assertFalse("oidc-session-test" in response.cookies.keys())

    def test_session_cookie_is_set_for_logged_users(self):
        self.client.login(username="test_user", password="123456")
        response = self.client.get("/a-resource")
        self.assertTrue(isinstance(response.cookies, SimpleCookie))
        self.assertTrue("oidc-session-test" in response.cookies.keys())
        self.assertNotEqual(response.cookies["oidc-session-test"].value, "")

    def test_session_cookie_is_cleared_for_anonymous_users(self):
        response = self.client.get("/a-resource")
        self.assertTrue(isinstance(response.cookies, SimpleCookie))
        self.assertTrue("oidc-session-test" in response.cookies.keys())
        self.assertEqual(response.cookies["oidc-session-test"].value, "")

    def test_session_cookie_is_not_set_after_logging_out(self):
        self.client.login(username="test_user", password="123456")
        self.client.get("/a-resource")
        self.client.logout()

        response = self.client.get("/another-resource")
        self.assertTrue(isinstance(response.cookies, SimpleCookie))
        self.assertTrue("oidc-session-test" in response.cookies.keys())
        self.assertEqual(response.cookies["oidc-session-test"].value, "")


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(PRESET_OIDC_MIDDLEWARE)
class TestSessionManagementStateKey(TestCase):
    def test_session_management_state_key_uses_session_key_when_no_cookie(self):
        session_key = "test-session"
        session_hash = hashlib.sha256(session_key.encode("utf-8")).hexdigest()

        request = RequestFactory().get("/")
        request.COOKIES = {}
        request.session = type("Session", (), {"session_key": session_key})()

        result = session_management_state_key(request)
        self.assertEqual(result, session_hash)

    def test_session_management_state_key_uses_default_when_no_session(self):
        request = RequestFactory().get("/")
        request.COOKIES = {}
        request.session = None

        default_key = PRESET_OIDC_MIDDLEWARE["OIDC_SESSION_MANAGEMENT_DEFAULT_KEY"]

        result = session_management_state_key(request)
        default_key_hash = hashlib.sha256(default_key.encode("utf-8")).hexdigest()
        self.assertEqual(result, default_key_hash)
