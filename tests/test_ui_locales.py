from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from oauth2_provider.models import get_application_model


UserModel = get_user_model()
Application = get_application_model()


@override_settings(
    OAUTH2_PROVIDER={
        "OIDC_ENABLED": True,
        "PKCE_REQUIRED": False,
        "SCOPES": {
            "openid": "OpenID connect",
        },
    }
)
class TestUILocalesParam(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.application = Application.objects.create(
            name="Test Application",
            client_id="test",
            redirect_uris="https://www.example.com/",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        cls.trusted_application = Application.objects.create(
            name="Trusted Application",
            client_id="trusted",
            redirect_uris="https://www.example.com/",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            skip_authorization=True,
        )
        cls.user = UserModel.objects.create_user("test_user")
        cls.url = reverse("oauth2_provider:authorize")

    def setUp(self):
        self.client.force_login(self.user)

    def test_application_ui_locales_param(self):
        response = self.client.get(
            f"{self.url}?response_type=code&client_id=test&scope=openid&ui_locales=de",
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "oauth2_provider/authorize.html")

    def test_trusted_application_ui_locales_param(self):
        response = self.client.get(
            f"{self.url}?response_type=code&client_id=trusted&scope=openid&ui_locales=de",
        )
        self.assertEqual(response.status_code, 302)
        self.assertRegex(response.url, r"https://www\.example\.com/\?code=[a-zA-Z0-9]+")
