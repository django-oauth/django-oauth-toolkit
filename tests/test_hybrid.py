import base64
import datetime
import json
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone
from jwcrypto import jwt
from oauthlib.oauth2.rfc6749 import errors as oauthlib_errors

from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_grant_model,
    get_refresh_token_model,
)
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauth2_provider.views import ProtectedResourceView, ScopedProtectedResourceView

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .common_testing import retrieve_current_databases
from .utils import get_basic_auth_header, spy_on


Application = get_application_model()
AccessToken = get_access_token_model()
Grant = get_grant_model()
RefreshToken = get_refresh_token_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"


# mocking a protected resource view
class ResourceView(ProtectedResourceView):
    def get(self, request, *args, **kwargs):
        return "This is a protected resource"


class ScopedResourceView(ScopedProtectedResourceView):
    required_scopes = ["read"]

    def get(self, request, *args, **kwargs):
        return "This is a protected resource"


@pytest.mark.usefixtures("oauth2_settings")
class BaseTest(TestCase):
    factory = RequestFactory()

    @classmethod
    def setUpTestData(cls):
        cls.hy_test_user = UserModel.objects.create_user("hy_test_user", "test_hy@example.com", "123456")
        cls.hy_dev_user = UserModel.objects.create_user("hy_dev_user", "dev_hy@example.com", "123456")

        cls.application = Application(
            name="Hybrid Test Application",
            redirect_uris=(
                "http://localhost http://example.com http://example.org custom-scheme://example.com"
            ),
            user=cls.hy_dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_OPENID_HYBRID,
            algorithm=Application.RS256_ALGORITHM,
            client_secret=CLEARTEXT_SECRET,
        )
        cls.application.save()

    def setUp(self):
        self.oauth2_settings.PKCE_REQUIRED = False
        self.oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES = ["http", "custom-scheme"]


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestRegressionIssue315Hybrid(BaseTest):
    """
    Test to avoid regression for the issue 315: request object
    was being reassigned when getting AuthorizationView
    """

    def test_request_is_not_overwritten_code_token(self):
        self.client.login(username="hy_test_user", password="123456")
        query_string = urlencode(
            {
                "client_id": self.application.client_id,
                "response_type": "code token",
                "state": "random_state_string",
                "scope": "openid read write",
                "redirect_uri": "http://example.org",
            }
        )
        url = "{url}?{qs}".format(url=reverse("oauth2_provider:authorize"), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        assert "request" not in response.context_data

    def test_request_is_not_overwritten_code_id_token(self):
        self.client.login(username="hy_test_user", password="123456")
        query_string = urlencode(
            {
                "client_id": self.application.client_id,
                "response_type": "code id_token",
                "state": "random_state_string",
                "scope": "openid read write",
                "redirect_uri": "http://example.org",
                "nonce": "nonce",
            }
        )
        url = "{url}?{qs}".format(url=reverse("oauth2_provider:authorize"), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        assert "request" not in response.context_data

    def test_request_is_not_overwritten_code_id_token_token(self):
        self.client.login(username="hy_test_user", password="123456")
        query_string = urlencode(
            {
                "client_id": self.application.client_id,
                "response_type": "code id_token token",
                "state": "random_state_string",
                "scope": "openid read write",
                "redirect_uri": "http://example.org",
                "nonce": "nonce",
            }
        )
        url = "{url}?{qs}".format(url=reverse("oauth2_provider:authorize"), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        assert "request" not in response.context_data


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestHybridView(BaseTest):
    def test_skip_authorization_completely(self):
        """
        If application.skip_authorization = True, should skip the authorization page.
        """
        self.client.login(username="hy_test_user", password="123456")
        self.application.skip_authorization = True
        self.application.save()

        query_string = urlencode(
            {
                "client_id": self.application.client_id,
                "response_type": "code",
                "state": "random_state_string",
                "scope": "read write",
                "redirect_uri": "http://example.org",
            }
        )
        url = "{url}?{qs}".format(url=reverse("oauth2_provider:authorize"), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)

    def test_id_token_skip_authorization_completely(self):
        """
        If application.skip_authorization = True, should skip the authorization page.
        """
        self.client.login(username="hy_test_user", password="123456")
        self.application.skip_authorization = True
        self.application.save()

        query_string = urlencode(
            {
                "client_id": self.application.client_id,
                "response_type": "code",
                "state": "random_state_string",
                "scope": "openid",
                "redirect_uri": "http://example.org",
            }
        )
        url = "{url}?{qs}".format(url=reverse("oauth2_provider:authorize"), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)

    def test_pre_auth_invalid_client(self):
        """
        Test error for an invalid client_id with response_type: code
        """
        self.client.login(username="hy_test_user", password="123456")

        query_string = urlencode(
            {
                "client_id": "fakeclientid",
                "response_type": "code",
            }
        )
        url = "{url}?{qs}".format(url=reverse("oauth2_provider:authorize"), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.context_data["url"],
            "?error=invalid_request&error_description=Invalid+client_id+parameter+value.",
        )

    def test_pre_auth_valid_client(self):
        """
        Test response for a valid client_id with response_type: code
        """
        self.client.login(username="hy_test_user", password="123456")

        query_string = urlencode(
            {
                "client_id": self.application.client_id,
                "response_type": "code id_token",
                "state": "random_state_string",
                "scope": "read write",
                "redirect_uri": "http://example.org",
            }
        )
        url = "{url}?{qs}".format(url=reverse("oauth2_provider:authorize"), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        # check form is in context and form params are valid
        self.assertIn("form", response.context)

        form = response.context["form"]
        self.assertEqual(form["redirect_uri"].value(), "http://example.org")
        self.assertEqual(form["state"].value(), "random_state_string")
        self.assertEqual(form["scope"].value(), "read write")
        self.assertEqual(form["client_id"].value(), self.application.client_id)

    def test_id_token_pre_auth_valid_client(self):
        """
        Test response for a valid client_id with response_type: code
        """
        self.client.login(username="hy_test_user", password="123456")

        query_string = urlencode(
            {
                "client_id": self.application.client_id,
                "response_type": "code id_token",
                "state": "random_state_string",
                "scope": "openid",
                "redirect_uri": "http://example.org",
                "nonce": "nonce",
            }
        )
        url = "{url}?{qs}".format(url=reverse("oauth2_provider:authorize"), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        # check form is in context and form params are valid
        self.assertIn("form", response.context)

        form = response.context["form"]
        self.assertEqual(form["redirect_uri"].value(), "http://example.org")
        self.assertEqual(form["state"].value(), "random_state_string")
        self.assertEqual(form["scope"].value(), "openid")
        self.assertEqual(form["client_id"].value(), self.application.client_id)

    def test_pre_auth_valid_client_custom_redirect_uri_scheme(self):
        """
        Test response for a valid client_id with response_type: code
        using a non-standard, but allowed, redirect_uri scheme.
        """
        self.client.login(username="hy_test_user", password="123456")

        query_string = urlencode(
            {
                "client_id": self.application.client_id,
                "response_type": "code id_token",
                "state": "random_state_string",
                "scope": "read write",
                "redirect_uri": "custom-scheme://example.com",
            }
        )
        url = "{url}?{qs}".format(url=reverse("oauth2_provider:authorize"), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        # check form is in context and form params are valid
        self.assertIn("form", response.context)

        form = response.context["form"]
        self.assertEqual(form["redirect_uri"].value(), "custom-scheme://example.com")
        self.assertEqual(form["state"].value(), "random_state_string")
        self.assertEqual(form["scope"].value(), "read write")
        self.assertEqual(form["client_id"].value(), self.application.client_id)

    def test_pre_auth_approval_prompt(self):
        tok = AccessToken.objects.create(
            user=self.hy_test_user,
            token="1234567890",
            application=self.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write",
        )
        self.client.login(username="hy_test_user", password="123456")
        query_string = urlencode(
            {
                "client_id": self.application.client_id,
                "response_type": "code id_token",
                "state": "random_state_string",
                "scope": "read write",
                "redirect_uri": "http://example.org",
                "approval_prompt": "auto",
            }
        )
        url = "{url}?{qs}".format(url=reverse("oauth2_provider:authorize"), qs=query_string)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        # user already authorized the application, but with different scopes: prompt them.
        tok.scope = "read"
        tok.save()
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_pre_auth_approval_prompt_default(self):
        self.oauth2_settings.REQUEST_APPROVAL_PROMPT = "force"
        self.assertEqual(self.oauth2_settings.REQUEST_APPROVAL_PROMPT, "force")

        AccessToken.objects.create(
            user=self.hy_test_user,
            token="1234567890",
            application=self.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write",
        )
        self.client.login(username="hy_test_user", password="123456")
        query_string = urlencode(
            {
                "client_id": self.application.client_id,
                "response_type": "code id_token",
                "state": "random_state_string",
                "scope": "read write",
                "redirect_uri": "http://example.org",
            }
        )
        url = "{url}?{qs}".format(url=reverse("oauth2_provider:authorize"), qs=query_string)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_pre_auth_approval_prompt_default_override(self):
        self.oauth2_settings.REQUEST_APPROVAL_PROMPT = "auto"

        AccessToken.objects.create(
            user=self.hy_test_user,
            token="1234567890",
            application=self.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write",
        )
        self.client.login(username="hy_test_user", password="123456")
        query_string = urlencode(
            {
                "client_id": self.application.client_id,
                "response_type": "code",
                "state": "random_state_string",
                "scope": "read write",
                "redirect_uri": "http://example.org",
            }
        )
        url = "{url}?{qs}".format(url=reverse("oauth2_provider:authorize"), qs=query_string)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)

    def test_pre_auth_default_redirect(self):
        """
        Test for default redirect uri if omitted from query string with response_type: code
        """
        self.client.login(username="hy_test_user", password="123456")
        self.application.redirect_uris = "http://localhost"
        self.application.save()

        query_string = urlencode(
            {
                "client_id": self.application.client_id,
                "response_type": "code id_token",
            }
        )
        url = "{url}?{qs}".format(url=reverse("oauth2_provider:authorize"), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        form = response.context["form"]
        self.assertEqual(form["redirect_uri"].value(), "http://localhost")

    def test_pre_auth_forbibben_redirect(self):
        """
        Test error when passing a forbidden redirect_uri in query string with response_type: code
        """
        self.client.login(username="hy_test_user", password="123456")

        query_string = urlencode(
            {
                "client_id": self.application.client_id,
                "response_type": "code",
                "redirect_uri": "http://forbidden.it",
            }
        )
        url = "{url}?{qs}".format(url=reverse("oauth2_provider:authorize"), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 400)

    def test_pre_auth_wrong_response_type(self):
        """
        Test error when passing a wrong response_type in query string
        """
        self.client.login(username="hy_test_user", password="123456")

        query_string = urlencode(
            {
                "client_id": self.application.client_id,
                "response_type": "WRONG",
                "redirect_uri": "http://example.org",
            }
        )
        url = "{url}?{qs}".format(url=reverse("oauth2_provider:authorize"), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=unsupported_response_type", response["Location"])

    def test_code_post_auth_allow_code_token(self):
        """
        Test authorization code is given for an allowed request with response_type: code
        """
        self.client.login(username="hy_test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "openid read write",
            "redirect_uri": "http://example.org",
            "response_type": "code token",
            "allow": True,
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("http://example.org", response["Location"])
        self.assertIn("state=random_state_string", response["Location"])
        self.assertIn("code=", response["Location"])
        self.assertIn("access_token=", response["Location"])

    def test_code_post_auth_allow_code_id_token(self):
        """
        Test authorization code is given for an allowed request with response_type: code
        """
        self.client.login(username="hy_test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "openid read write",
            "redirect_uri": "http://example.org",
            "response_type": "code id_token",
            "allow": True,
            "nonce": "nonce",
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("http://example.org", response["Location"])
        self.assertIn("state=random_state_string", response["Location"])
        self.assertIn("code=", response["Location"])
        self.assertIn("id_token=", response["Location"])

    def test_code_post_auth_allow_code_id_token_token(self):
        """
        Test authorization code is given for an allowed request with response_type: code
        """
        self.client.login(username="hy_test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "openid read write",
            "redirect_uri": "http://example.org",
            "response_type": "code id_token token",
            "allow": True,
            "nonce": "nonce",
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("http://example.org", response["Location"])
        self.assertIn("state=random_state_string", response["Location"])
        self.assertIn("code=", response["Location"])
        self.assertIn("id_token=", response["Location"])
        self.assertIn("access_token=", response["Location"])

    def test_id_token_code_post_auth_allow(self):
        """
        Test authorization code is given for an allowed request with response_type: code
        """
        self.client.login(username="hy_test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "openid",
            "redirect_uri": "http://example.org",
            "response_type": "code id_token",
            "allow": True,
            "nonce": "nonce",
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("http://example.org", response["Location"])
        self.assertIn("state=random_state_string", response["Location"])
        self.assertIn("code=", response["Location"])
        self.assertIn("id_token=", response["Location"])

    def test_code_post_auth_deny(self):
        """
        Test error when resource owner deny access
        """
        self.client.login(username="hy_test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": False,
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=access_denied", response["Location"])

    def test_code_post_auth_bad_responsetype(self):
        """
        Test authorization code is given for an allowed request with a response_type not supported
        """
        self.client.login(username="hy_test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "http://example.org",
            "response_type": "UNKNOWN",
            "allow": True,
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("http://example.org?error", response["Location"])

    def test_code_post_auth_forbidden_redirect_uri(self):
        """
        Test authorization code is given for an allowed request with a forbidden redirect_uri
        """
        self.client.login(username="hy_test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "http://forbidden.it",
            "response_type": "code",
            "allow": True,
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 400)

    def test_code_post_auth_malicious_redirect_uri(self):
        """
        Test validation of a malicious redirect_uri
        """
        self.client.login(username="hy_test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "/../",
            "response_type": "code",
            "allow": True,
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 400)

    def test_code_post_auth_allow_custom_redirect_uri_scheme_code_token(self):
        """
        Test authorization code is given for an allowed request with response_type: code
        using a non-standard, but allowed, redirect_uri scheme.
        """
        self.client.login(username="hy_test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "openid read write",
            "redirect_uri": "custom-scheme://example.com",
            "response_type": "code token",
            "allow": True,
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("custom-scheme://example.com", response["Location"])
        self.assertIn("state=random_state_string", response["Location"])
        self.assertIn("code=", response["Location"])
        self.assertIn("access_token=", response["Location"])

    def test_code_post_auth_allow_custom_redirect_uri_scheme_code_id_token(self):
        """
        Test authorization code is given for an allowed request with response_type: code
        using a non-standard, but allowed, redirect_uri scheme.
        """
        self.client.login(username="hy_test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "openid read write",
            "redirect_uri": "custom-scheme://example.com",
            "response_type": "code id_token",
            "allow": True,
            "nonce": "nonce",
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("custom-scheme://example.com", response["Location"])
        self.assertIn("state=random_state_string", response["Location"])
        self.assertIn("code=", response["Location"])
        self.assertIn("id_token=", response["Location"])

    def test_code_post_auth_allow_custom_redirect_uri_scheme_code_id_token_token(self):
        """
        Test authorization code is given for an allowed request with response_type: code
        using a non-standard, but allowed, redirect_uri scheme.
        """
        self.client.login(username="hy_test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "openid read write",
            "redirect_uri": "custom-scheme://example.com",
            "response_type": "code id_token token",
            "allow": True,
            "nonce": "nonce",
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("custom-scheme://example.com", response["Location"])
        self.assertIn("state=random_state_string", response["Location"])
        self.assertIn("code=", response["Location"])
        self.assertIn("id_token=", response["Location"])
        self.assertIn("access_token=", response["Location"])

    def test_code_post_auth_deny_custom_redirect_uri_scheme(self):
        """
        Test error when resource owner deny access
        using a non-standard, but allowed, redirect_uri scheme.
        """
        self.client.login(username="hy_test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "custom-scheme://example.com",
            "response_type": "code",
            "allow": False,
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("custom-scheme://example.com?", response["Location"])
        self.assertIn("error=access_denied", response["Location"])

    def test_code_post_auth_redirection_uri_with_querystring_code_token(self):
        """
        Tests that a redirection uri with query string is allowed
        and query string is retained on redirection.
        See https://rfc-editor.org/rfc/rfc6749.html#section-3.1.2
        """
        self.client.login(username="hy_test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "openid read write",
            "redirect_uri": "http://example.com?foo=bar",
            "response_type": "code token",
            "allow": True,
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("http://example.com?foo=bar", response["Location"])
        self.assertIn("code=", response["Location"])
        self.assertIn("access_token=", response["Location"])

    def test_code_post_auth_redirection_uri_with_querystring_code_id_token(self):
        """
        Tests that a redirection uri with query string is allowed
        and query string is retained on redirection.
        See https://rfc-editor.org/rfc/rfc6749.html#section-3.1.2
        """
        self.client.login(username="hy_test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "openid read write",
            "redirect_uri": "http://example.com?foo=bar",
            "response_type": "code id_token",
            "allow": True,
            "nonce": "nonce",
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("http://example.com?foo=bar", response["Location"])
        self.assertIn("code=", response["Location"])
        self.assertIn("id_token=", response["Location"])

    def test_code_post_auth_redirection_uri_with_querystring_code_id_token_token(self):
        """
        Tests that a redirection uri with query string is allowed
        and query string is retained on redirection.
        See https://rfc-editor.org/rfc/rfc6749.html#section-3.1.2
        """
        self.client.login(username="hy_test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "openid read write",
            "redirect_uri": "http://example.com?foo=bar",
            "response_type": "code id_token token",
            "allow": True,
            "nonce": "nonce",
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertIn("http://example.com?foo=bar", response["Location"])
        self.assertIn("code=", response["Location"])
        self.assertIn("id_token=", response["Location"])
        self.assertIn("access_token=", response["Location"])

    def test_code_post_auth_failing_redirection_uri_with_querystring(self):
        """
        Test that in case of error the querystring of the redirection uri is preserved

        See https://github.com/evonove/django-oauth-toolkit/issues/238
        """
        self.client.login(username="hy_test_user", password="123456")

        form_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "http://example.com?foo=bar",
            "response_type": "code",
            "allow": False,
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=form_data)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            "http://example.com?foo=bar&error=access_denied&state=random_state_string", response["Location"]
        )

    def test_code_post_auth_fails_when_redirect_uri_path_is_invalid(self):
        """
        Tests that a redirection uri is matched using scheme + netloc + path
        """
        self.client.login(username="hy_test_user", password="123456")

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


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestHybridTokenView(BaseTest):
    def get_auth(self, scope="read write"):
        """
        Helper method to retrieve a valid authorization code
        """
        authcode_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": scope,
            "redirect_uri": "http://example.org",
            "response_type": "code id_token",
            "allow": True,
            "nonce": "nonce",
        }

        response = self.client.post(reverse("oauth2_provider:authorize"), data=authcode_data)
        fragment_dict = parse_qs(urlparse(response["Location"]).fragment)
        return fragment_dict["code"].pop()

    def test_basic_auth(self):
        """
        Request an access token using basic authentication for client authentication
        """
        self.client.login(username="hy_test_user", password="123456")
        authorization_code = self.get_auth()

        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "http://example.org",
        }
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        self.assertEqual(content["token_type"], "Bearer")
        self.assertEqual(content["scope"], "read write")
        self.assertEqual(content["expires_in"], self.oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)

    def test_basic_auth_bad_authcode(self):
        """
        Request an access token using a bad authorization code
        """
        self.client.login(username="hy_test_user", password="123456")

        token_request_data = {
            "grant_type": "authorization_code",
            "code": "BLAH",
            "redirect_uri": "http://example.org",
        }
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 400)

    def test_basic_auth_bad_granttype(self):
        """
        Request an access token using a bad grant_type string
        """
        self.client.login(username="hy_test_user", password="123456")

        token_request_data = {"grant_type": "UNKNOWN", "code": "BLAH", "redirect_uri": "http://example.org"}
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 400)

    def test_basic_auth_grant_expired(self):
        """
        Request an access token using an expired grant token
        """
        self.client.login(username="hy_test_user", password="123456")
        g = Grant(
            application=self.application,
            user=self.hy_test_user,
            code="BLAH",
            expires=timezone.now(),
            redirect_uri="",
            scope="",
        )
        g.save()

        token_request_data = {
            "grant_type": "authorization_code",
            "code": "BLAH",
            "redirect_uri": "http://example.org",
        }
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 400)

    def test_basic_auth_bad_secret(self):
        """
        Request an access token using basic authentication for client authentication
        """
        self.client.login(username="hy_test_user", password="123456")
        authorization_code = self.get_auth()

        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "http://example.org",
        }
        auth_headers = get_basic_auth_header(self.application.client_id, "BOOM!")

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 401)

    def test_basic_auth_wrong_auth_type(self):
        """
        Request an access token using basic authentication for client authentication
        """
        self.client.login(username="hy_test_user", password="123456")
        authorization_code = self.get_auth()

        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "http://example.org",
        }

        user_pass = "{0}:{1}".format(self.application.client_id, CLEARTEXT_SECRET)
        auth_string = base64.b64encode(user_pass.encode("utf-8"))
        auth_headers = {
            "HTTP_AUTHORIZATION": "Wrong " + auth_string.decode("utf-8"),
        }

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 401)

    def test_request_body_params(self):
        """
        Request an access token using client_type: public
        """
        self.client.login(username="hy_test_user", password="123456")
        authorization_code = self.get_auth()

        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "http://example.org",
            "client_id": self.application.client_id,
            "client_secret": CLEARTEXT_SECRET,
        }

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        self.assertEqual(content["token_type"], "Bearer")
        self.assertEqual(content["scope"], "read write")
        self.assertEqual(content["expires_in"], self.oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)

    def test_public(self):
        """
        Request an access token using client_type: public
        """
        self.client.login(username="hy_test_user", password="123456")

        self.application.client_type = Application.CLIENT_PUBLIC
        self.application.save()
        authorization_code = self.get_auth()

        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "http://example.org",
            "client_id": self.application.client_id,
        }

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        self.assertEqual(content["token_type"], "Bearer")
        self.assertEqual(content["scope"], "read write")
        self.assertEqual(content["expires_in"], self.oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)

    def test_id_token_public(self):
        """
        Request an access token using client_type: public
        """
        self.client.login(username="hy_test_user", password="123456")

        self.application.client_type = Application.CLIENT_PUBLIC
        self.application.save()
        authorization_code = self.get_auth(scope="openid")

        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "http://example.org",
            "client_id": self.application.client_id,
            "scope": "openid",
        }

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        self.assertEqual(content["token_type"], "Bearer")
        self.assertEqual(content["scope"], "openid")
        self.assertIn("access_token", content)
        self.assertIn("id_token", content)
        self.assertEqual(content["expires_in"], self.oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)

    def test_malicious_redirect_uri(self):
        """
        Request an access token using client_type: public and ensure redirect_uri is
        properly validated.
        """
        self.client.login(username="hy_test_user", password="123456")

        self.application.client_type = Application.CLIENT_PUBLIC
        self.application.save()
        authorization_code = self.get_auth()

        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "/../",
            "client_id": self.application.client_id,
        }

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data)
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data["error"], "invalid_request")
        self.assertEqual(data["error_description"], oauthlib_errors.MismatchingRedirectURIError.description)

    def test_code_exchange_succeed_when_redirect_uri_match(self):
        """
        Tests code exchange succeed when redirect uri matches the one used for code request
        """
        self.client.login(username="hy_test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "openid read write",
            "redirect_uri": "http://example.org?foo=bar",
            "response_type": "code token",
            "allow": True,
        }
        response = self.client.post(reverse("oauth2_provider:authorize"), data=authcode_data)
        fragment_dict = parse_qs(urlparse(response["Location"]).fragment)
        authorization_code = fragment_dict["code"].pop()

        # exchange authorization code for a valid access token
        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "http://example.org?foo=bar",
        }
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        self.assertEqual(content["token_type"], "Bearer")
        self.assertEqual(content["scope"], "openid read write")
        self.assertEqual(content["expires_in"], self.oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)

    def test_code_exchange_fails_when_redirect_uri_does_not_match(self):
        """
        Tests code exchange fails when redirect uri does not match the one used for code request
        """
        self.client.login(username="hy_test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "openid read write",
            "redirect_uri": "http://example.org?foo=bar",
            "response_type": "code token",
            "allow": True,
        }
        response = self.client.post(reverse("oauth2_provider:authorize"), data=authcode_data)
        query_dict = parse_qs(urlparse(response["Location"]).fragment)
        authorization_code = query_dict["code"].pop()

        # exchange authorization code for a valid access token
        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "http://example.org?foo=baraa",
        }
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data["error"], "invalid_request")
        self.assertEqual(data["error_description"], oauthlib_errors.MismatchingRedirectURIError.description)

    def test_code_exchange_succeed_when_redirect_uri_match_with_multiple_query_params(self):
        """
        Tests code exchange succeed when redirect uri matches the one used for code request
        """
        self.client.login(username="hy_test_user", password="123456")
        self.application.redirect_uris = "http://localhost http://example.com?foo=bar"
        self.application.save()

        # retrieve a valid authorization code
        authcode_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "openid read write",
            "redirect_uri": "http://example.com?bar=baz&foo=bar",
            "response_type": "code token",
            "allow": True,
        }
        response = self.client.post(reverse("oauth2_provider:authorize"), data=authcode_data)
        fragment_dict = parse_qs(urlparse(response["Location"]).fragment)
        authorization_code = fragment_dict["code"].pop()

        # exchange authorization code for a valid access token
        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "http://example.com?bar=baz&foo=bar",
        }
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        self.assertEqual(content["token_type"], "Bearer")
        self.assertEqual(content["scope"], "openid read write")
        self.assertEqual(content["expires_in"], self.oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)

    def test_id_token_code_exchange_succeed_when_redirect_uri_match_with_multiple_query_params(self):
        """
        Tests code exchange succeed when redirect uri matches the one used for code request
        """
        self.client.login(username="hy_test_user", password="123456")
        self.application.redirect_uris = "http://localhost http://example.com?foo=bar"
        self.application.save()

        # retrieve a valid authorization code
        authcode_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "openid",
            "redirect_uri": "http://example.com?bar=baz&foo=bar",
            "response_type": "code token",
            "allow": True,
        }
        response = self.client.post(reverse("oauth2_provider:authorize"), data=authcode_data)
        fragment_dict = parse_qs(urlparse(response["Location"]).fragment)
        authorization_code = fragment_dict["code"].pop()

        # exchange authorization code for a valid access token
        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "http://example.com?bar=baz&foo=bar",
        }
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)

        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        self.assertEqual(content["token_type"], "Bearer")
        self.assertEqual(content["scope"], "openid")
        self.assertIn("access_token", content)
        self.assertIn("id_token", content)
        self.assertEqual(content["expires_in"], self.oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestHybridProtectedResource(BaseTest):
    def test_resource_access_allowed(self):
        self.client.login(username="hy_test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "openid read write",
            "redirect_uri": "http://example.org",
            "response_type": "code token",
            "allow": True,
        }
        response = self.client.post(reverse("oauth2_provider:authorize"), data=authcode_data)
        fragment_dict = parse_qs(urlparse(response["Location"]).fragment)
        authorization_code = fragment_dict["code"].pop()

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
        request.user = self.hy_test_user

        view = ResourceView.as_view()
        response = view(request)
        self.assertEqual(response, "This is a protected resource")

    def test_id_token_resource_access_allowed(self):
        self.client.login(username="hy_test_user", password="123456")

        # retrieve a valid authorization code
        authcode_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "openid",
            "redirect_uri": "http://example.org",
            "response_type": "code token",
            "allow": True,
        }
        response = self.client.post(reverse("oauth2_provider:authorize"), data=authcode_data)
        fragment_dict = parse_qs(urlparse(response["Location"]).fragment)
        authorization_code = fragment_dict["code"].pop()

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
        id_token = content["id_token"]

        # use token to access the resource
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + access_token,
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.hy_test_user

        view = ResourceView.as_view()
        response = view(request)
        self.assertEqual(response, "This is a protected resource")

        # use id_token to access the resource
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + id_token,
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.hy_test_user

        view = ResourceView.as_view()
        response = view(request)
        self.assertEqual(response, "This is a protected resource")

        # If the resource requires more scopes than we requested, we should get an error
        view = ScopedResourceView.as_view()
        response = view(request)
        self.assertEqual(response.status_code, 403)

    def test_resource_access_deny(self):
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + "faketoken",
        }
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.hy_test_user

        view = ResourceView.as_view()
        response = view(request)
        self.assertEqual(response.status_code, 403)


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RO)
class TestDefaultScopesHybrid(BaseTest):
    def test_pre_auth_default_scopes(self):
        """
        Test response for a valid client_id with response_type: code using default scopes
        """
        self.client.login(username="hy_test_user", password="123456")

        query_string = urlencode(
            {
                "client_id": self.application.client_id,
                "response_type": "code token",
                "state": "random_state_string",
                "redirect_uri": "http://example.org",
            }
        )
        url = "{url}?{qs}".format(url=reverse("oauth2_provider:authorize"), qs=query_string)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        # check form is in context and form params are valid
        self.assertIn("form", response.context)

        form = response.context["form"]
        self.assertEqual(form["redirect_uri"].value(), "http://example.org")
        self.assertEqual(form["state"].value(), "random_state_string")
        self.assertEqual(form["scope"].value(), "read")
        self.assertEqual(form["client_id"].value(), self.application.client_id)


@pytest.mark.django_db(databases=retrieve_current_databases())
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_id_token_nonce_in_token_response(oauth2_settings, test_user, hybrid_application, client, oidc_key):
    client.force_login(test_user)
    auth_rsp = client.post(
        reverse("oauth2_provider:authorize"),
        data={
            "client_id": hybrid_application.client_id,
            "state": "random_state_string",
            "scope": "openid",
            "redirect_uri": "http://example.org",
            "response_type": "code id_token",
            "nonce": "random_nonce_string",
            "allow": True,
        },
    )
    assert auth_rsp.status_code == 302
    auth_data = parse_qs(urlparse(auth_rsp["Location"]).fragment)
    assert "code" in auth_data
    assert "id_token" in auth_data
    # Decode the id token - is the nonce correct
    jwt_token = jwt.JWT(key=oidc_key, jwt=auth_data["id_token"][0])
    claims = json.loads(jwt_token.claims)
    assert "nonce" in claims
    assert claims["nonce"] == "random_nonce_string"
    code = auth_data["code"][0]
    client.logout()
    # Get the token response using the code
    token_rsp = client.post(
        reverse("oauth2_provider:token"),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://example.org",
            "client_id": hybrid_application.client_id,
            "client_secret": CLEARTEXT_SECRET,
            "scope": "openid",
        },
    )
    assert token_rsp.status_code == 200
    token_data = token_rsp.json()
    assert "id_token" in token_data
    # The nonce should be present in this id token also
    jwt_token = jwt.JWT(key=oidc_key, jwt=token_data["id_token"])
    claims = json.loads(jwt_token.claims)
    assert "nonce" in claims
    assert claims["nonce"] == "random_nonce_string"


@pytest.mark.django_db(databases=retrieve_current_databases())
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_claims_passed_to_code_generation(
    oauth2_settings, test_user, hybrid_application, client, mocker, oidc_key
):
    # Add a spy on to OAuth2Validator.finalize_id_token
    mocker.patch.object(
        OAuth2Validator,
        "finalize_id_token",
        spy_on(OAuth2Validator.finalize_id_token),
    )
    claims = {"id_token": {"email": {"essential": True}}}
    client.force_login(test_user)
    auth_form_rsp = client.get(
        reverse("oauth2_provider:authorize"),
        data={
            "client_id": hybrid_application.client_id,
            "state": "random_state_string",
            "scope": "openid",
            "redirect_uri": "http://example.org",
            "response_type": "code id_token",
            "nonce": "random_nonce_string",
            "claims": json.dumps(claims),
        },
    )
    # Check that claims has made it in to the form to be submitted
    assert auth_form_rsp.status_code == 200
    form_initial_data = auth_form_rsp.context_data["form"].initial
    assert "claims" in form_initial_data
    assert json.loads(form_initial_data["claims"]) == claims
    # Filter out not specified values
    form_data = {key: value for key, value in form_initial_data.items() if value is not None}
    # Now submitting the form (with allow=True) should persist requested claims
    auth_rsp = client.post(
        reverse("oauth2_provider:authorize"),
        data={"allow": True, **form_data},
    )
    assert auth_rsp.status_code == 302
    auth_data = parse_qs(urlparse(auth_rsp["Location"]).fragment)
    assert "code" in auth_data
    assert "id_token" in auth_data
    assert OAuth2Validator.finalize_id_token.spy.call_count == 1
    oauthlib_request = OAuth2Validator.finalize_id_token.spy.call_args[0][4]
    assert oauthlib_request.claims == claims
    assert Grant.objects.get().claims == json.dumps(claims)
    OAuth2Validator.finalize_id_token.spy.reset_mock()

    # Get the token response using the code
    client.logout()
    code = auth_data["code"][0]
    token_rsp = client.post(
        reverse("oauth2_provider:token"),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://example.org",
            "client_id": hybrid_application.client_id,
            "client_secret": CLEARTEXT_SECRET,
            "scope": "openid",
        },
    )
    assert token_rsp.status_code == 200
    token_data = token_rsp.json()
    assert "id_token" in token_data
    assert OAuth2Validator.finalize_id_token.spy.call_count == 1
    oauthlib_request = OAuth2Validator.finalize_id_token.spy.call_args[0][4]
    assert oauthlib_request.claims == claims
