from datetime import timedelta

import pytest
from django.conf.urls import include
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.test.utils import override_settings
from django.urls import path, re_path
from django.utils import timezone
from rest_framework import permissions
from rest_framework.authentication import BaseAuthentication
from rest_framework.test import APIRequestFactory, force_authenticate
from rest_framework.views import APIView

from oauth2_provider.contrib.rest_framework import (
    IsAuthenticatedOrTokenHasScope,
    OAuth2Authentication,
    TokenHasReadWriteScope,
    TokenHasResourceScope,
    TokenHasScope,
    TokenMatchesOASRequirements,
)
from oauth2_provider.models import get_access_token_model, get_application_model

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()


class MockView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        return HttpResponse({"a": 1, "b": 2, "c": 3})

    def post(self, request):
        return HttpResponse({"a": 1, "b": 2, "c": 3})

    def put(self, request):
        return HttpResponse({"a": 1, "b": 2, "c": 3})


class OAuth2View(MockView):
    authentication_classes = [OAuth2Authentication]


class ScopedView(OAuth2View):
    permission_classes = [permissions.IsAuthenticated, TokenHasScope]
    required_scopes = ["scope1", "another"]


class AuthenticatedOrScopedView(OAuth2View):
    permission_classes = [IsAuthenticatedOrTokenHasScope]
    required_scopes = ["scope1"]


class ReadWriteScopedView(OAuth2View):
    permission_classes = [permissions.IsAuthenticated, TokenHasReadWriteScope]


class ResourceScopedView(OAuth2View):
    permission_classes = [permissions.IsAuthenticated, TokenHasResourceScope]
    required_scopes = ["resource1"]


class MethodScopeAltView(OAuth2View):
    permission_classes = [TokenMatchesOASRequirements]
    required_alternate_scopes = {
        "GET": [["read"]],
        "POST": [["create"]],
        "PUT": [["update", "put"], ["update", "edit"]],
        "DELETE": [["delete"], ["deleter", "write"]],
    }


class MethodScopeAltViewBad(OAuth2View):
    permission_classes = [TokenMatchesOASRequirements]


class MissingAuthentication(BaseAuthentication):
    def authenticate(self, request):
        return (
            "junk",
            "junk",
        )


class BrokenOAuth2View(MockView):
    authentication_classes = [MissingAuthentication]


class TokenHasScopeViewWrongAuth(BrokenOAuth2View):
    permission_classes = [TokenHasScope]


class MethodScopeAltViewWrongAuth(BrokenOAuth2View):
    permission_classes = [TokenMatchesOASRequirements]


class AuthenticationNone(OAuth2Authentication):
    def authenticate(self, request):
        return None


class AuthenticationNoneOAuth2View(MockView):
    authentication_classes = [AuthenticationNone]


urlpatterns = [
    path("oauth2/", include("oauth2_provider.urls")),
    path("oauth2-test/", OAuth2View.as_view()),
    path("oauth2-scoped-test/", ScopedView.as_view()),
    path("oauth2-scoped-missing-auth/", TokenHasScopeViewWrongAuth.as_view()),
    path("oauth2-read-write-test/", ReadWriteScopedView.as_view()),
    path("oauth2-resource-scoped-test/", ResourceScopedView.as_view()),
    path("oauth2-authenticated-or-scoped-test/", AuthenticatedOrScopedView.as_view()),
    re_path(r"oauth2-method-scope-test/.*$", MethodScopeAltView.as_view()),
    path("oauth2-method-scope-fail/", MethodScopeAltViewBad.as_view()),
    path("oauth2-method-scope-missing-auth/", MethodScopeAltViewWrongAuth.as_view()),
    path("oauth2-authentication-none/", AuthenticationNoneOAuth2View.as_view()),
]


@override_settings(ROOT_URLCONF=__name__)
@pytest.mark.nologinrequiredmiddleware
@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.REST_FRAMEWORK_SCOPES)
class TestOAuth2Authentication(TestCase):
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
        )

        cls.access_token = AccessToken.objects.create(
            user=cls.test_user,
            scope="read write",
            expires=timezone.now() + timedelta(seconds=300),
            token="secret-access-token-key",
            application=cls.application,
        )

    def _create_authorization_header(self, token):
        return "Bearer {0}".format(token)

    def test_authentication_allow(self):
        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    def test_authentication_denied(self):
        response = self.client.get("/oauth2-test/")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response["WWW-Authenticate"],
            'Bearer realm="api"',
        )

    def test_authentication_denied_because_of_invalid_token(self):
        auth = self._create_authorization_header("fake-token")
        response = self.client.get("/oauth2-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response["WWW-Authenticate"],
            'Bearer realm="api",error="invalid_token",error_description="The access token is invalid."',
        )

    def test_authentication_or_scope_denied(self):
        # user is not authenticated
        # not a correct token
        auth = self._create_authorization_header("fake-token")
        response = self.client.get("/oauth2-authenticated-or-scoped-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 401)
        # token doesn"t have correct scope
        auth = self._create_authorization_header(self.access_token.token)

        factory = APIRequestFactory()
        request = factory.get("/oauth2-authenticated-or-scoped-test/")
        request.auth = auth
        force_authenticate(request, token=self.access_token)
        response = AuthenticatedOrScopedView.as_view()(request)
        # authenticated but wrong scope, this is 403, not 401
        self.assertEqual(response.status_code, 403)

    def test_scoped_permission_allow(self):
        self.access_token.scope = "scope1 another"
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-scoped-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    def test_scope_missing_scope_attr(self):
        auth = self._create_authorization_header("fake-token")
        with self.assertRaises(AssertionError) as e:
            self.client.get("/oauth2-scoped-missing-auth/", HTTP_AUTHORIZATION=auth)
        self.assertTrue("`oauth2_provider.rest_framework.OAuth2Authentication`" in str(e.exception))

    def test_authenticated_or_scoped_permission_allow(self):
        self.access_token.scope = "scope1"
        self.access_token.save()
        # correct token and correct scope
        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-authenticated-or-scoped-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

        auth = self._create_authorization_header("fake-token")
        # incorrect token  but authenticated
        factory = APIRequestFactory()
        request = factory.get("/oauth2-authenticated-or-scoped-test/")
        request.auth = auth
        force_authenticate(request, self.test_user)
        response = AuthenticatedOrScopedView.as_view()(request)
        self.assertEqual(response.status_code, 200)

        # correct token  but not authenticated
        request = factory.get("/oauth2-authenticated-or-scoped-test/")
        request.auth = auth
        self.access_token.scope = "scope1"
        self.access_token.save()
        force_authenticate(request, token=self.access_token)
        response = AuthenticatedOrScopedView.as_view()(request)
        self.assertEqual(response.status_code, 200)

    def test_scoped_permission_deny(self):
        self.access_token.scope = "scope2"
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-scoped-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 403)

    def test_read_write_permission_get_allow(self):
        self.access_token.scope = "read"
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-read-write-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    def test_read_write_permission_post_allow(self):
        self.access_token.scope = "write"
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.post("/oauth2-read-write-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    def test_read_write_permission_get_deny(self):
        self.access_token.scope = "write"
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-read-write-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 403)

    def test_read_write_permission_post_deny(self):
        self.access_token.scope = "read"
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.post("/oauth2-read-write-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 403)

    def test_resource_scoped_permission_get_allow(self):
        self.access_token.scope = "resource1:read"
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-resource-scoped-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    def test_resource_scoped_permission_post_allow(self):
        self.access_token.scope = "resource1:write"
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.post("/oauth2-resource-scoped-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    def test_resource_scoped_permission_get_denied(self):
        self.access_token.scope = "resource1:write"
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-resource-scoped-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 403)

    def test_resource_scoped_permission_post_denied(self):
        self.access_token.scope = "resource1:read"
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.post("/oauth2-resource-scoped-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 403)

    def test_required_scope_in_response(self):
        self.oauth2_settings.ERROR_RESPONSE_WITH_SCOPES = True
        self.access_token.scope = "scope2"
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-scoped-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data["required_scopes"], ["scope1", "another"])

    def test_required_scope_not_in_response_by_default(self):
        self.access_token.scope = "scope2"
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-scoped-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("required_scopes", response.data)

    def test_method_scope_alt_permission_get_allow(self):
        self.access_token.scope = "read"
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-method-scope-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    def test_method_scope_alt_permission_post_allow(self):
        self.access_token.scope = "create"
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.post("/oauth2-method-scope-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    def test_method_scope_alt_permission_put_allow(self):
        self.access_token.scope = "edit update"
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.put("/oauth2-method-scope-test/123", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 200)

    def test_method_scope_alt_permission_put_fail(self):
        self.access_token.scope = "edit"
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.put("/oauth2-method-scope-test/123", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 403)

    def test_method_scope_alt_permission_get_deny(self):
        self.access_token.scope = "write"
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-method-scope-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 403)

    def test_method_scope_alt_permission_post_deny(self):
        self.access_token.scope = "read"
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.post("/oauth2-method-scope-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 403)

    def test_method_scope_alt_no_token(self):
        self.access_token.scope = ""
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        self.access_token = None
        response = self.client.post("/oauth2-method-scope-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 403)

    def test_method_scope_alt_missing_attr(self):
        self.access_token.scope = "read"
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        with self.assertRaises(ImproperlyConfigured):
            self.client.post("/oauth2-method-scope-fail/", HTTP_AUTHORIZATION=auth)

    def test_method_scope_alt_missing_patch_method(self):
        self.access_token.scope = "update"
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.patch("/oauth2-method-scope-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 403)

    def test_method_scope_alt_empty_scope(self):
        self.access_token.scope = ""
        self.access_token.save()

        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.patch("/oauth2-method-scope-test/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 403)

    def test_method_scope_alt_missing_scope_attr(self):
        auth = self._create_authorization_header("fake-token")
        with self.assertRaises(AssertionError) as e:
            self.client.get("/oauth2-method-scope-missing-auth/", HTTP_AUTHORIZATION=auth)
        self.assertTrue("`oauth2_provider.rest_framework.OAuth2Authentication`" in str(e.exception))

    def test_authentication_none(self):
        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-authentication-none/", HTTP_AUTHORIZATION=auth)
        self.assertEqual(response.status_code, 401)

    def test_invalid_hex_string_in_query(self):
        auth = self._create_authorization_header(self.access_token.token)
        response = self.client.get("/oauth2-test/?q=73%%20of%20Arkansans", HTTP_AUTHORIZATION=auth)
        # Should respond with a 400 rather than raise a ValueError
        self.assertEqual(response.status_code, 400)
