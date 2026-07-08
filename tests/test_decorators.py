from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django.utils import timezone

from oauth2_provider.decorators import (
    protected_resource,
    protected_resource_metadata,
    rw_protected_resource,
    rw_protected_resource_metadata,
)
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
        assert "WWW-Authenticate" not in response

    def test_access_denied_metadata_decorator_advertises_metadata(self):
        """RFC 9728: the metadata decorator returns a 401 with a resource_metadata challenge."""

        @protected_resource_metadata()
        def view(request, *args, **kwargs):
            return "protected contents"

        request = self.request_factory.get("/fake-resource")
        response = view(request)
        self.assertEqual(response.status_code, 401)
        challenge = response["WWW-Authenticate"]
        assert challenge.startswith("Bearer")
        assert 'resource_metadata="http://testserver/o/.well-known/oauth-protected-resource"' in challenge

    def test_access_denied_rw_metadata_decorator_advertises_metadata(self):
        @rw_protected_resource_metadata()
        def view(request, *args, **kwargs):
            return "protected contents"

        request = self.request_factory.get("/fake-resource")
        response = view(request)
        self.assertEqual(response.status_code, 401)
        assert (
            'resource_metadata="http://testserver/o/.well-known/oauth-protected-resource"'
            in response["WWW-Authenticate"]
        )

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

    def test_rw_protected_scopes_not_polluted_across_requests(self):
        """
        Regression test: the read/write scope must not accumulate on a shared list
        across requests. A prior write (POST) request must not cause a later read
        (GET) request made with a read-only token to be rejected.
        """
        self.access_token.scope = "exotic_scope read"
        self.access_token.save()
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.access_token.token,
        }

        @rw_protected_resource(scopes=["exotic_scope"])
        def scoped_view(request, *args, **kwargs):
            return "protected contents"

        # POST requires the write scope, which this token does not have -> denied.
        request = self.request_factory.post("/fake-resource", **auth_headers)
        response = scoped_view(request)
        self.assertEqual(response.status_code, 403)

        # A subsequent GET requires only the read scope, which this token has.
        # With the scope-list-mutation bug, the "write" scope appended by the POST
        # above would still be required here and this would wrongly return 403.
        request = self.request_factory.get("/fake-resource", **auth_headers)
        response = scoped_view(request)
        self.assertEqual(response, "protected contents")

    def test_rw_protected_does_not_mutate_scopes_argument(self):
        """The caller-supplied ``scopes`` list must never be mutated by a request."""
        scopes_arg = ["exotic_scope"]

        @rw_protected_resource(scopes=scopes_arg)
        def scoped_view(request, *args, **kwargs):
            return "protected contents"

        self.access_token.scope = "exotic_scope read"
        self.access_token.save()
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.access_token.token,
        }
        request = self.request_factory.get("/fake-resource", **auth_headers)
        scoped_view(request)

        self.assertEqual(scopes_arg, ["exotic_scope"])
