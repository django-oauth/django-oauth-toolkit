"""
#1904: the consent page shows the client's registered logo and links
(RFC 7591 section 2, OpenID Connect Dynamic Client Registration 1.0 section 2).
"""

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse

from oauth2_provider.models import get_application_model

from .common_testing import OAuth2ProviderTestCase as TestCase


UserModel = get_user_model()
Application = get_application_model()


@override_settings(OAUTH2_PROVIDER={"PKCE_REQUIRED": False})
class TestConsentPageClientBranding(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("branding_user")
        cls.url = reverse("oauth2_provider:authorize")

    def setUp(self):
        self.client.force_login(self.user)

    def _application(self, **kwargs):
        fields = {
            "name": "Branded App",
            "redirect_uris": "https://client.example.com/cb",
            "client_type": Application.CLIENT_PUBLIC,
            "authorization_grant_type": Application.GRANT_AUTHORIZATION_CODE,
            **kwargs,
        }
        return Application.objects.create(**fields)

    def _consent_page(self, application):
        response = self.client.get(
            self.url,
            {"response_type": "code", "client_id": application.client_id, "scope": "read"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "oauth2_provider/authorize.html")
        self.assertTemplateUsed(response, "oauth2_provider/client_branding.html")
        return response

    def test_shows_logo_and_links(self):
        application = self._application(
            client_uri="https://client.example.com/",
            logo_uri="https://client.example.com/logo.png",
            policy_uri="https://client.example.com/policy",
            tos_uri="https://client.example.com/tos",
        )
        response = self._consent_page(application)
        self.assertContains(
            response,
            '<img class="client-logo" src="https://client.example.com/logo.png" alt="Branded App logo" '
            'referrerpolicy="no-referrer">',
            html=True,
        )
        for href, label in (
            ("https://client.example.com/", "Home page"),
            ("https://client.example.com/policy", "Privacy policy"),
            ("https://client.example.com/tos", "Terms of service"),
        ):
            self.assertContains(
                response,
                f'<a href="{href}" rel="noopener noreferrer nofollow" target="_blank">{label}</a>',
                html=True,
            )

    def test_logo_alt_falls_back_to_client_id(self):
        application = self._application(name="", logo_uri="https://client.example.com/logo.png")
        response = self._consent_page(application)
        self.assertContains(response, f'alt="{application.client_id} logo"')
        self.assertNotContains(response, 'class="client-links"')

    def test_only_registered_links_are_shown(self):
        application = self._application(policy_uri="https://client.example.com/policy")
        response = self._consent_page(application)
        self.assertContains(response, "Privacy policy")
        self.assertNotContains(response, "Terms of service")
        self.assertNotContains(response, "Home page")
        self.assertNotContains(response, 'class="client-logo"')

    def test_nothing_shown_without_display_metadata(self):
        response = self._consent_page(self._application())
        self.assertNotContains(response, "client-branding")
