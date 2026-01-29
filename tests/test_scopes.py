import json
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory
from django.urls import reverse

from oauth2_provider.models import get_access_token_model, get_application_model, get_grant_model
from oauth2_provider.views import ReadWriteScopedResourceView, ScopedProtectedResourceView

from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header


Application = get_application_model()
AccessToken = get_access_token_model()
Grant = get_grant_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"


# mocking a protected resource view
class ScopeResourceView(ScopedProtectedResourceView):
    required_scopes = ["scope1"]

    def get(self, request, *args, **kwargs):
        return "This is a protected resource"


class MultiScopeResourceView(ScopedProtectedResourceView):
    required_scopes = ["scope1", "scope2"]

    def get(self, request, *args, **kwargs):
        return "This is a protected resource"


class ReadWriteResourceView(ReadWriteScopedResourceView):
    def get(self, request, *args, **kwargs):
        return "This is a read protected resource"

    def post(self, request, *args, **kwargs):
        return "This is a write protected resource"


SCOPE_SETTINGS = {
    "SCOPES": {
        "read": "Read scope",
        "write": "Write scope",
        "scope1": "Custom scope 1",
        "scope2": "Custom scope 2",
        "scope3": "Custom scope 3",
    },
}


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(SCOPE_SETTINGS)
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


class TestScopesSave(BaseTest):
    def test_scopes_saved_in_grant(self):
        """
        Test scopes are properly saved in grant
        """
        self.oauth2_settings.PKCE_REQUIRED = False
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "scope1 scope2",
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": True,
        }
        response = self.client.post(reverse("oauth2_provider:authorize"), data=authcode_data)
        query_dict = parse_qs(urlparse(response["Location"]).query)
        authorization_code = query_dict["code"].pop()

        grant = Grant.objects.get(code=authorization_code)
        self.assertEqual(grant.scope, "scope1 scope2")

    def test_scopes_save_in_access_token(self):
        """
        Test scopes are properly saved in access token
        """
        self.oauth2_settings.PKCE_REQUIRED = False
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "scope1 scope2",
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": True,
        }
        response = self.client.post(reverse("oauth2_provider:authorize"), data=authcode_data)
        query_dict = parse_qs(urlparse(response["Location"]).query)
        authorization_code = query_dict["code"].pop()

        # exchange authorization code for a valid access token
        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "http://example.org",
        }
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        content = json.loads(response.content.decode("utf-8"))
        access_token = content["access_token"]

        at = AccessToken.objects.get(token=access_token)
        self.assertEqual(at.scope, "scope1 scope2")


class TestScopesProtection(BaseTest):
    def test_scopes_protection_valid(self):
        """
        Test access to a scope protected resource with correct scopes provided
        """
        self.oauth2_settings.PKCE_REQUIRED = False
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "scope1 scope2",
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": True,
        }
        response = self.client.post(reverse("oauth2_provider:authorize"), data=authcode_data)
        query_dict = parse_qs(urlparse(response["Location"]).query)
        authorization_code = query_dict["code"].pop()

        # exchange authorization code for a valid access token
        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "http://example.org",
        }
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        content = json.loads(response.content.decode("utf-8"))
        access_token = content["access_token"]

        # use token to access the resource
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + access_token,
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ScopeResourceView.as_view()
        response = view(request)
        self.assertEqual(response, "This is a protected resource")

    def test_scopes_protection_fail(self):
        """
        Test access to a scope protected resource with wrong scopes provided
        """
        self.oauth2_settings.PKCE_REQUIRED = False
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "scope2",
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": True,
        }
        response = self.client.post(reverse("oauth2_provider:authorize"), data=authcode_data)
        query_dict = parse_qs(urlparse(response["Location"]).query)
        authorization_code = query_dict["code"].pop()

        # exchange authorization code for a valid access token
        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "http://example.org",
        }
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        content = json.loads(response.content.decode("utf-8"))
        access_token = content["access_token"]

        # use token to access the resource
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + access_token,
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ScopeResourceView.as_view()
        response = view(request)
        self.assertEqual(response.status_code, 403)

    def test_multi_scope_fail(self):
        """
        Test access to a multi-scope protected resource with wrong scopes provided
        """
        self.oauth2_settings.PKCE_REQUIRED = False
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "scope1 scope3",
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": True,
        }
        response = self.client.post(reverse("oauth2_provider:authorize"), data=authcode_data)
        query_dict = parse_qs(urlparse(response["Location"]).query)
        authorization_code = query_dict["code"].pop()

        # exchange authorization code for a valid access token
        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "http://example.org",
        }
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        content = json.loads(response.content.decode("utf-8"))
        access_token = content["access_token"]

        # use token to access the resource
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + access_token,
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = MultiScopeResourceView.as_view()
        response = view(request)
        self.assertEqual(response.status_code, 403)

    def test_multi_scope_valid(self):
        """
        Test access to a multi-scope protected resource with correct scopes provided
        """
        self.oauth2_settings.PKCE_REQUIRED = False
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "scope1 scope2",
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": True,
        }
        response = self.client.post(reverse("oauth2_provider:authorize"), data=authcode_data)
        query_dict = parse_qs(urlparse(response["Location"]).query)
        authorization_code = query_dict["code"].pop()

        # exchange authorization code for a valid access token
        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "http://example.org",
        }
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        content = json.loads(response.content.decode("utf-8"))
        access_token = content["access_token"]

        # use token to access the resource
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + access_token,
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = MultiScopeResourceView.as_view()
        response = view(request)
        self.assertEqual(response, "This is a protected resource")


class TestReadWriteScope(BaseTest):
    def get_access_token(self, scopes):
        self.oauth2_settings.PKCE_REQUIRED = False
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": scopes,
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": True,
        }
        response = self.client.post(reverse("oauth2_provider:authorize"), data=authcode_data)
        query_dict = parse_qs(urlparse(response["Location"]).query)
        authorization_code = query_dict["code"].pop()

        # exchange authorization code for a valid access token
        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "http://example.org",
        }
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        content = json.loads(response.content.decode("utf-8"))
        return content["access_token"]

    def test_improperly_configured(self):
        self.oauth2_settings.SCOPES = {"scope1": "Scope 1"}

        request = self.factory.get("/fake")
        view = ReadWriteResourceView.as_view()
        self.assertRaises(ImproperlyConfigured, view, request)

        self.oauth2_settings.SCOPES = {"read": "Read Scope", "write": "Write Scope"}
        self.oauth2_settings.READ_SCOPE = "ciccia"

        view = ReadWriteResourceView.as_view()
        self.assertRaises(ImproperlyConfigured, view, request)

    def test_properly_configured(self):
        self.oauth2_settings.SCOPES = {"scope1": "Scope 1"}

        request = self.factory.get("/fake")
        view = ReadWriteResourceView.as_view()
        self.assertRaises(ImproperlyConfigured, view, request)

        self.oauth2_settings.SCOPES = {"read": "Read Scope", "write": "Write Scope"}
        self.oauth2_settings.READ_SCOPE = "ciccia"

        view = ReadWriteResourceView.as_view()
        self.assertRaises(ImproperlyConfigured, view, request)

    def test_has_read_scope(self):
        access_token = self.get_access_token("read")

        # use token to access the resource
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + access_token,
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ReadWriteResourceView.as_view()
        response = view(request)
        self.assertEqual(response, "This is a read protected resource")

    def test_no_read_scope(self):
        access_token = self.get_access_token("scope1")

        # use token to access the resource
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + access_token,
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ReadWriteResourceView.as_view()
        response = view(request)
        self.assertEqual(response.status_code, 403)

    def test_has_write_scope(self):
        access_token = self.get_access_token("write")

        # use token to access the resource
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + access_token,
        }
        request = self.factory.post("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ReadWriteResourceView.as_view()
        response = view(request)
        self.assertEqual(response, "This is a write protected resource")

    def test_no_write_scope(self):
        access_token = self.get_access_token("scope1")

        # use token to access the resource
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + access_token,
        }
        request = self.factory.post("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ReadWriteResourceView.as_view()
        response = view(request)
        self.assertEqual(response.status_code, 403)
