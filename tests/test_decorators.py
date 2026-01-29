from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django.utils import timezone

from oauth2_provider.decorators import protected_resource, rw_protected_resource
from oauth2_provider.models import get_access_token_model, get_application_model

from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()


class TestProtectedResourceDecorator(TestCase):
    request_factory = RequestFactory()

    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("test_user", "test@example.com", "123456")
        cls.application = Application.objects.create(
            name="test_client_credentials_app",
            user=cls.user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
        )

        cls.access_token = AccessToken.objects.create(
            user=cls.user,
            scope="read write",
            expires=timezone.now() + timedelta(seconds=300),
            token="secret-access-token-key",
            application=cls.application,
        )

    def test_access_denied(self):
        @protected_resource()
        def view(request, *args, **kwargs):
            return "protected contents"

        request = self.request_factory.get("/fake-resource")
        response = view(request)
        self.assertEqual(response.status_code, 403)

    def test_access_allowed(self):
        @protected_resource()
        def view(request, *args, **kwargs):
            return "protected contents"

        @protected_resource(scopes=["can_touch_this"])
        def scoped_view(request, *args, **kwargs):
            return "moar protected contents"

        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.access_token.token,
        }
        request = self.request_factory.get("/fake-resource", **auth_headers)
        response = view(request)
        self.assertEqual(response, "protected contents")

        # now with scopes
        self.access_token.scope = "can_touch_this"
        self.access_token.save()
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.access_token.token,
        }
        request = self.request_factory.get("/fake-resource", **auth_headers)
        response = scoped_view(request)
        self.assertEqual(response, "moar protected contents")

    def test_rw_protected(self):
        self.access_token.scope = "exotic_scope write"
        self.access_token.save()
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.access_token.token,
        }

        @rw_protected_resource(scopes=["exotic_scope"])
        def scoped_view(request, *args, **kwargs):
            return "other protected contents"

        request = self.request_factory.post("/fake-resource", **auth_headers)
        response = scoped_view(request)
        self.assertEqual(response, "other protected contents")

        request = self.request_factory.get("/fake-resource", **auth_headers)
        response = scoped_view(request)
        self.assertEqual(response.status_code, 403)
