import datetime

from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone

from oauth2_provider.models import get_access_token_model, get_application_model, get_refresh_token_model

from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()
AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"


class BaseTest(TestCase):
    factory = RequestFactory()

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
            client_secret=CLEARTEXT_SECRET,
        )


class TestRevocationView(BaseTest):
    def test_revoke_access_token(self):
        tok = AccessToken.objects.create(
            user=self.test_user,
            token="1234567890",
            application=self.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write",
        )

        data = {
            "client_id": self.application.client_id,
            "client_secret": CLEARTEXT_SECRET,
            "token": tok.token,
        }
        url = reverse("oauth2_provider:revoke-token")
        response = self.client.post(url, data=data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"")
        self.assertFalse(AccessToken.objects.filter(pk=tok.pk).exists())

    def test_revoke_access_token_public(self):
        public_app = Application(
            name="Test Application",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=self.dev_user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        public_app.save()

        tok = AccessToken.objects.create(
            user=self.test_user,
            token="1234567890",
            application=public_app,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write",
        )

        data = {
            "client_id": public_app.client_id,
            "token": tok.token,
        }

        url = reverse("oauth2_provider:revoke-token")
        response = self.client.post(url, data=data)
        self.assertEqual(response.status_code, 200)

    def test_revoke_access_token_with_hint(self):
        tok = AccessToken.objects.create(
            user=self.test_user,
            token="1234567890",
            application=self.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write",
        )

        data = {
            "client_id": self.application.client_id,
            "client_secret": CLEARTEXT_SECRET,
            "token": tok.token,
            "token_type_hint": "access_token",
        }

        url = reverse("oauth2_provider:revoke-token")
        response = self.client.post(url, data=data)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(AccessToken.objects.filter(pk=tok.pk).exists())

    def test_revoke_access_token_with_invalid_hint(self):
        tok = AccessToken.objects.create(
            user=self.test_user,
            token="1234567890",
            application=self.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write",
        )
        # invalid hint should have no effect

        data = {
            "client_id": self.application.client_id,
            "client_secret": CLEARTEXT_SECRET,
            "token": tok.token,
            "token_type_hint": "bad_hint",
        }

        url = reverse("oauth2_provider:revoke-token")
        response = self.client.post(url, data=data)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(AccessToken.objects.filter(pk=tok.pk).exists())

    def test_revoke_refresh_token(self):
        tok = AccessToken.objects.create(
            user=self.test_user,
            token="1234567890",
            application=self.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write",
        )
        rtok = RefreshToken.objects.create(
            user=self.test_user, token="999999999", application=self.application, access_token=tok
        )

        data = {
            "client_id": self.application.client_id,
            "client_secret": CLEARTEXT_SECRET,
            "token": rtok.token,
        }

        url = reverse("oauth2_provider:revoke-token")
        response = self.client.post(url, data=data)
        self.assertEqual(response.status_code, 200)
        refresh_token = RefreshToken.objects.filter(pk=rtok.pk).first()
        self.assertIsNotNone(refresh_token.revoked)
        self.assertFalse(AccessToken.objects.filter(pk=rtok.access_token.pk).exists())

    def test_revoke_refresh_token_with_revoked_access_token(self):
        tok = AccessToken.objects.create(
            user=self.test_user,
            token="1234567890",
            application=self.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write",
        )
        rtok = RefreshToken.objects.create(
            user=self.test_user, token="999999999", application=self.application, access_token=tok
        )
        for token in (tok.token, rtok.token):
            data = {
                "client_id": self.application.client_id,
                "client_secret": CLEARTEXT_SECRET,
                "token": token,
            }

            url = reverse("oauth2_provider:revoke-token")
            response = self.client.post(url, data=data)
            self.assertEqual(response.status_code, 200)

        self.assertFalse(AccessToken.objects.filter(pk=tok.pk).exists())
        refresh_token = RefreshToken.objects.filter(pk=rtok.pk).first()
        self.assertIsNotNone(refresh_token.revoked)

    def test_revoke_token_with_wrong_hint(self):
        """
        From the revocation rfc, `Section 4.1.2`_ :

        If the server is unable to locate the token using the given hint,
        it MUST extend its search across all of its supported token types
        .. _`Section 4.1.2`: http://tools.ietf.org/html/draft-ietf-oauth-revocation-11#section-4.1.2
        """
        tok = AccessToken.objects.create(
            user=self.test_user,
            token="1234567890",
            application=self.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write",
        )

        data = {
            "client_id": self.application.client_id,
            "client_secret": CLEARTEXT_SECRET,
            "token": tok.token,
            "token_type_hint": "refresh_token",
        }

        url = reverse("oauth2_provider:revoke-token")
        response = self.client.post(url, data=data)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(AccessToken.objects.filter(pk=tok.pk).exists())
