import json
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django.urls import reverse
from jwcrypto import jwt

from oauth2_provider.models import get_application_model
from oauth2_provider.views import ProtectedResourceView

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()
UserModel = get_user_model()


# mocking a protected resource view
class ResourceView(ProtectedResourceView):
    def get(self, request, *args, **kwargs):
        return "This is a protected resource"


@pytest.mark.usefixtures("oauth2_settings")
class BaseTest(TestCase):
    factory = RequestFactory()

    @classmethod
    def setUpTestData(cls):
        cls.test_user = UserModel.objects.create_user("test_user", "test@example.com", "123456")
        cls.dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")

        cls.application = Application.objects.create(
            name="Test Implicit Application",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=cls.dev_user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_IMPLICIT,
        )


@pytest.mark.oauth2_settings(presets.DEFAULT_SCOPES_RO)
class TestImplicitAuthorizationCodeView(BaseTest):
    def test_pre_auth_valid_client_default_scopes(self):
        """
        Test response for a valid client_id with response_type: token and default_scopes
        """
        self.client.login(username="test_user", password="123456")
        query_data = {
            "client_id": self.application.client_id,
            "response_type": "token",
            "state": "random_state_string",
            "redirect_uri": "http://example.org",
        }

        response = self.client.get(reverse("oauth2_provider:authorize"), data=query_data)
        self.assertEqual(response.status_code, 200)

        self.assertIn("form", response.context)
        form = response.context["form"]
        self.assertEqual(form["scope"].value(), "read")

    def test_pre_auth_valid_client(self):
        """
        Test response for a valid client_id with response_type: token
        """
        self.client.login(username="test_user", password="123456")

        query_data = {
            "client_id": self.application.client_id,
            "response_type": "token",
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "http://example.org",
        }

        response = self.client.get(reverse("oauth2_provider:authorize"), data=query_data)
        self.assertEqual(response.status_code, 200)

        # check form is in context and form params are valid
        self.assertIn("form", response.context)

        form = response.context["form"]
        self.assertEqual(form["redirect_uri"].value(), "http://example.org")
        self.assertEqual(form["state"].value(), "random_state_string")
        self.assertEqual(form["scope"].value(), "read write")
        self.assertEqual(form["client_id"].value(), self.application.client_id)

    def test_pre_auth_invalid_client(self):
        """
        Test error for an invalid client_id with response_type: token
        """
        self.client.login(username="test_user", password="123456")

        query_data = {
            "client_id": "fakeclientid",
            "response_type": "token",
        }

        response = self.client.get(reverse("oauth2_provider:authorize"), data=query_data)
        self.assertEqual(response.status_code, 400)

    def test_pre_auth_default_redirect(self):
        """
        Test for default redirect uri if omitted from query string with response_type: token
        """
        self.client.login(username="test_user", password="123456")
        self.application.redirect_uris = "http://localhost"
        self.application.save()

        query_data = {
            "client_id": self.application.client_id,
            "response_type": "token",
        }

        response = self.client.get(reverse("oauth2_provider:authorize"), data=query_data)
        self.assertEqual(response.status_code, 200)

        form = response.context["form"]
        self.assertEqual(form["redirect_uri"].value(), "http://localhost")

    def test_pre_auth_forbibben_redirect(self):
        """
        Test error when passing a forbidden redirect_uri in query string with response_type: token
        """
        self.client.login(username="test_user", password="123456")

        query_data = {
            "client_id": self.application.client_id,
            "response_type": "token",
            "redirect_uri": "http://forbidden.it",
        }

        response = self.client.get(reverse("oauth2_provider:authorize"), data=query_data)
        self.assertEqual(response.status_code, 400)

    def test_post_auth_allow(self):
        """
        Test authorization code is given for an allowed request with response_type: token
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "http://example.org",
            "response_type": "token",
            "allow": True,
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("http://example.org#", response["Location"])
        self.assertIn("access_token=", response["Location"])
        self.assertIn("state=random_state_string", response["Location"])

    def test_skip_authorization_completely(self):
        """
        If application.skip_authorization = True, should skip the authorization page.
        """
        self.client.login(username="test_user", password="123456")
        self.application.skip_authorization = True
        self.application.save()

        query_data = {
            "client_id": self.application.client_id,
            "response_type": "token",
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "http://example.org",
        }

        response = self.client.get(reverse("oauth2_provider:authorize"), data=query_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("http://example.org#", response["Location"])
        self.assertIn("access_token=", response["Location"])
        self.assertIn("state=random_state_string", response["Location"])

    def test_token_post_auth_deny(self):
        """
        Test error when resource owner deny access
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "http://example.org",
            "response_type": "token",
            "allow": False,
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=access_denied", response["Location"])

    def test_implicit_redirection_uri_with_querystring(self):
        """
        Tests that a redirection uri with query string is allowed
        and query string is retained on redirection.
        See https://rfc-editor.org/rfc/rfc6749.html#section-3.1.2
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "http://example.com?foo=bar",
            "response_type": "token",
            "allow": True,
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("http://example.com?foo=bar", response["Location"])
        self.assertIn("access_token=", response["Location"])

    def test_implicit_fails_when_redirect_uri_path_is_invalid(self):
        """
        Tests that a redirection uri is matched using scheme + netloc + path
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "http://example.com/a?foo=bar",
            "response_type": "code",
            "allow": True,
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 400)


@pytest.mark.oauth2_settings(presets.DEFAULT_SCOPES_RO)
class TestImplicitTokenView(BaseTest):
    def test_resource_access_allowed(self):
        self.client.login(username="test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "http://example.org",
            "response_type": "token",
            "allow": True,
        }
        response = self.client.post(reverse("oauth2_provider:authorize"), data=authcode_data)
        # within implicit grant, access token is in the url fragment
        frag_dict = parse_qs(urlparse(response["Location"]).fragment)
        access_token = frag_dict["access_token"].pop()

        # use token to access the resource
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + access_token,
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.test_user

        view = ResourceView.as_view()
        response = view(request)
        self.assertEqual(response, "This is a protected resource")


@pytest.mark.usefixtures("oidc_key")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestOpenIDConnectImplicitFlow(BaseTest):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.application.algorithm = Application.RS256_ALGORITHM
        cls.application.save()

    def test_id_token_post_auth_allow(self):
        """
        Test authorization code is given for an allowed request with response_type: id_token
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "nonce": "random_nonce_string",
            "scope": "openid",
            "redirect_uri": "http://example.org",
            "response_type": "id_token",
            "allow": True,
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("http://example.org#", response["Location"])
        self.assertNotIn("access_token=", response["Location"])
        self.assertIn("id_token=", response["Location"])
        self.assertIn("state=random_state_string", response["Location"])

        uri_query = urlparse(response["Location"]).fragment
        uri_query_params = dict(parse_qs(uri_query, keep_blank_values=True, strict_parsing=True))
        id_token = uri_query_params["id_token"][0]
        jwt_token = jwt.JWT(key=self.key, jwt=id_token)
        claims = json.loads(jwt_token.claims)
        self.assertIn("nonce", claims)
        self.assertNotIn("at_hash", claims)

    def test_id_token_skip_authorization_completely(self):
        """
        If application.skip_authorization = True, should skip the authorization page.
        """
        self.client.login(username="test_user", password="123456")
        self.application.skip_authorization = True
        self.application.save()

        query_data = {
            "client_id": self.application.client_id,
            "response_type": "id_token",
            "state": "random_state_string",
            "nonce": "random_nonce_string",
            "scope": "openid",
            "redirect_uri": "http://example.org",
        }

        response = self.client.get(reverse("oauth2_provider:authorize"), data=query_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("http://example.org#", response["Location"])
        self.assertNotIn("access_token=", response["Location"])
        self.assertIn("id_token=", response["Location"])
        self.assertIn("state=random_state_string", response["Location"])

        uri_query = urlparse(response["Location"]).fragment
        uri_query_params = dict(parse_qs(uri_query, keep_blank_values=True, strict_parsing=True))
        id_token = uri_query_params["id_token"][0]
        jwt_token = jwt.JWT(key=self.key, jwt=id_token)
        claims = json.loads(jwt_token.claims)
        self.assertIn("nonce", claims)
        self.assertNotIn("at_hash", claims)

    def test_id_token_skip_authorization_completely_missing_nonce(self):
        """
        If application.skip_authorization = True, should skip the authorization page.
        """
        self.client.login(username="test_user", password="123456")
        self.application.skip_authorization = True
        self.application.save()

        query_data = {
            "client_id": self.application.client_id,
            "response_type": "id_token",
            "state": "random_state_string",
            "scope": "openid",
            "redirect_uri": "http://example.org",
        }

        response = self.client.get(reverse("oauth2_provider:authorize"), data=query_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=invalid_request", response["Location"])
        self.assertIn("error_description=Request+is+missing+mandatory+nonce+parameter", response["Location"])

    def test_id_token_post_auth_deny(self):
        """
        Test error when resource owner deny access
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "nonce": "random_nonce_string",
            "scope": "openid",
            "redirect_uri": "http://example.org",
            "response_type": "id_token",
            "allow": False,
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=access_denied", response["Location"])

    def test_access_token_and_id_token_post_auth_allow(self):
        """
        Test authorization code is given for an allowed request with response_type: token
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "nonce": "random_nonce_string",
            "scope": "openid",
            "redirect_uri": "http://example.org",
            "response_type": "id_token token",
            "allow": True,
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("http://example.org#", response["Location"])
        self.assertIn("access_token=", response["Location"])
        self.assertIn("id_token=", response["Location"])
        self.assertIn("state=random_state_string", response["Location"])

        uri_query = urlparse(response["Location"]).fragment
        uri_query_params = dict(parse_qs(uri_query, keep_blank_values=True, strict_parsing=True))
        id_token = uri_query_params["id_token"][0]
        jwt_token = jwt.JWT(key=self.key, jwt=id_token)
        claims = json.loads(jwt_token.claims)
        self.assertIn("nonce", claims)
        self.assertIn("at_hash", claims)

    def test_access_token_and_id_token_skip_authorization_completely(self):
        """
        If application.skip_authorization = True, should skip the authorization page.
        """
        self.client.login(username="test_user", password="123456")
        self.application.skip_authorization = True
        self.application.save()

        query_data = {
            "client_id": self.application.client_id,
            "response_type": "id_token token",
            "state": "random_state_string",
            "nonce": "random_nonce_string",
            "scope": "openid",
            "redirect_uri": "http://example.org",
        }

        response = self.client.get(reverse("oauth2_provider:authorize"), data=query_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("http://example.org#", response["Location"])
        self.assertIn("access_token=", response["Location"])
        self.assertIn("id_token=", response["Location"])
        self.assertIn("state=random_state_string", response["Location"])

        uri_query = urlparse(response["Location"]).fragment
        uri_query_params = dict(parse_qs(uri_query, keep_blank_values=True, strict_parsing=True))
        id_token = uri_query_params["id_token"][0]
        jwt_token = jwt.JWT(key=self.key, jwt=id_token)
        claims = json.loads(jwt_token.claims)
        self.assertIn("nonce", claims)
        self.assertIn("at_hash", claims)

    def test_access_token_and_id_token_post_auth_deny(self):
        """
        Test error when resource owner deny access
        """
        self.client.login(username="test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "openid",
            "redirect_uri": "http://example.org",
            "response_type": "id_token token",
            "allow": False,
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=access_denied", response["Location"])
