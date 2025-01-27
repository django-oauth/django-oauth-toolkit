from copy import deepcopy
from http.cookies import SimpleCookie

import pytest
from django.contrib.auth import get_user_model
from django.test.utils import modify_settings

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
