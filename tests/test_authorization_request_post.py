"""Authorization requests sent by HTTP POST (OpenID Connect Core 1.0 section 3.1.2.1).

The authorization endpoint must accept the request by POST, with its parameters
form-serialized in the body, as well as by GET. The consent form also posts to the
endpoint; it is told apart by its ``allow`` field or CSRF token, and stays
CSRF-protected, while an authorization request sent by POST carries no CSRF token.
"""

import base64
import json
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse

from oauth2_provider.models import get_application_model

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header, post_form


Application = get_application_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"
REDIRECT_URI = "http://example.org"


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestAuthorizationRequestByPost(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.test_user = UserModel.objects.create_user("test_user", "test@example.com", "123456")
        dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")
        cls.application = Application.objects.create(
            name="Code Application",
            redirect_uris=REDIRECT_URI,
            user=dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            algorithm=Application.RS256_ALGORITHM,
            client_secret=CLEARTEXT_SECRET,
        )

    def setUp(self):
        # The authorization request comes from the client's site, without a CSRF
        # token, so the tests enforce CSRF checks the way a browser session would.
        self.client = Client(enforce_csrf_checks=True)
        self.client.login(username="test_user", password="123456")

    @property
    def authorize_url(self):
        return reverse("oauth2_provider:authorize")

    def request_parameters(self, **params):
        parameters = {
            "client_id": self.application.client_id,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": "random_state_string",
            "nonce": "random_nonce_string",
        }
        parameters.update(params)
        return {key: value for key, value in parameters.items() if value is not None}

    def post_authorization_request(self, url=None, **params):
        return post_form(self.client, url or self.authorize_url, self.request_parameters(**params))

    def submit_consent(self, consent, allow=True, csrf_token=True):
        """Post the rendered consent form back to the URL it was loaded from."""
        data = {key: value for key, value in consent.context_data["form"].initial.items() if value}
        if allow:
            data["allow"] = "Authorize"
        if csrf_token:
            data["csrfmiddlewaretoken"] = consent.context["csrf_token"]
        # The browser's address after a POST carries no query string.
        return post_form(self.client, self.authorize_url, data)

    def assertRedirectParameters(self, response):
        self.assertEqual(response.status_code, 302)
        location = urlparse(response["Location"])
        self.assertEqual(f"{location.scheme}://{location.netloc}", REDIRECT_URI)
        return parse_qs(location.query)

    def test_post_shows_consent_like_get(self):
        response = self.post_authorization_request()

        self.assertEqual(response.status_code, 200)
        get_response = self.client.get(self.authorize_url, self.request_parameters())
        self.assertEqual(response.context_data["form"].initial, get_response.context_data["form"].initial)
        # The consent form is shown, not submitted: it is unbound, without errors.
        self.assertFalse(response.context_data["form"].is_bound)
        self.assertEqual(response.context_data["application"], self.application)
        self.assertEqual(response.context_data["scopes"], ["openid"])

    def test_post_then_consent_issues_code_and_id_token(self):
        consent = self.post_authorization_request()
        response = self.submit_consent(consent)

        params = self.assertRedirectParameters(response)
        self.assertEqual(params["state"], ["random_state_string"])
        token_response = post_form(
            self.client,
            reverse("oauth2_provider:token"),
            {"grant_type": "authorization_code", "code": params["code"][0], "redirect_uri": REDIRECT_URI},
            **get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET),
        )
        self.assertEqual(token_response.status_code, 200)
        id_token = json.loads(token_response.content)["id_token"]
        payload = json.loads(_b64decode(id_token.split(".")[1]))
        self.assertEqual(payload["nonce"], "random_nonce_string")
        self.assertEqual(payload["aud"], self.application.client_id)

    def test_post_then_denial_returns_access_denied(self):
        # The default template's Cancel button submits no allow field, only the
        # CSRF token.
        consent = self.post_authorization_request()
        response = self.submit_consent(consent, allow=False)

        params = self.assertRedirectParameters(response)
        self.assertEqual(params["error"], ["access_denied"])
        self.assertEqual(params["state"], ["random_state_string"])

    def test_post_with_skip_authorization_issues_code(self):
        self.application.skip_authorization = True
        self.application.save()

        response = self.post_authorization_request()

        params = self.assertRedirectParameters(response)
        self.assertIn("code", params)
        self.assertEqual(params["state"], ["random_state_string"])

    def test_post_invalid_request_is_rejected_like_get(self):
        response = self.post_authorization_request(redirect_uri="http://attacker.example")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.context_data["error"].error, "invalid_request")

    def test_parameter_in_both_query_and_body_is_rejected(self):
        # The body joins the query string, so a parameter sent in both is a
        # repeated parameter, as it would be in a GET; it is never resolved in
        # favour of either copy.
        url = f"{self.authorize_url}?{urlencode({'client_id': 'other-client'})}"
        response = self.post_authorization_request(url=url)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.context_data["error"].error, "invalid_request")

    def test_logged_out_post_redirects_to_get_form(self):
        self.client.logout()

        response = self.post_authorization_request()

        self.assertEqual(response.status_code, 303)
        location = urlparse(response["Location"])
        self.assertEqual(location.path, self.authorize_url)
        self.assertEqual(
            {key: values[0] for key, values in parse_qs(location.query).items()}, self.request_parameters()
        )

        # The GET form sends the user to log in, then back to the same request.
        response = self.client.get(response["Location"])
        self.assertEqual(response.status_code, 302)
        login = urlparse(response["Location"])
        next_url = urlparse(parse_qs(login.query)["next"][0])
        self.assertEqual(next_url.path, self.authorize_url)
        self.assertEqual(
            {key: values[0] for key, values in parse_qs(next_url.query).items()}, self.request_parameters()
        )

    def test_logged_out_post_with_prompt_none_returns_login_required(self):
        self.client.logout()

        response = self.post_authorization_request(prompt="none", scope="read", nonce=None)
        self.assertEqual(response.status_code, 303)
        response = self.client.get(response["Location"])

        params = self.assertRedirectParameters(response)
        self.assertEqual(params["error"], ["login_required"])
        self.assertEqual(params["state"], ["random_state_string"])

    def test_post_with_prompt_login_redirects_to_login(self):
        response = self.post_authorization_request(prompt="login")

        self.assertEqual(response.status_code, 302)
        login = urlparse(response["Location"])
        next_url = urlparse(parse_qs(login.query)["next"][0])
        self.assertEqual(next_url.path, self.authorize_url)
        next_parameters = parse_qs(next_url.query)
        # The prompt is consumed; the rest of the request comes from the body.
        self.assertNotIn("prompt", next_parameters)
        self.assertEqual(next_parameters["client_id"], [self.application.client_id])
        self.assertEqual(next_parameters["nonce"], ["random_nonce_string"])

    def test_post_with_approval_prompt_auto_reuses_prior_authorization(self):
        consent = self.post_authorization_request()
        code = self.assertRedirectParameters(self.submit_consent(consent))["code"][0]
        post_form(
            self.client,
            reverse("oauth2_provider:token"),
            {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI},
            **get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET),
        )

        response = self.post_authorization_request(approval_prompt="auto")

        self.assertIn("code", self.assertRedirectParameters(response))

    def test_post_with_resources(self):
        resources = ["https://api.example.com", "https://other.example.com"]

        response = self.post_authorization_request(resource=resources)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context_data["form"].initial["resource"], " ".join(resources))

    def test_post_with_invalid_resource_returns_invalid_target(self):
        response = self.post_authorization_request(resource="not-a-uri")

        params = self.assertRedirectParameters(response)
        self.assertEqual(params["error"], ["invalid_target"])
        self.assertEqual(params["state"], ["random_state_string"])

    def test_post_with_request_object_is_rejected(self):
        response = self.post_authorization_request(request="eyJhbGciOiJub25lIn0.e30.")

        params = self.assertRedirectParameters(response)
        self.assertEqual(params["error"], ["request_not_supported"])

    def test_post_with_request_uri_is_rejected(self):
        response = self.post_authorization_request(request_uri="https://client.example/request.jwt")

        params = self.assertRedirectParameters(response)
        self.assertEqual(params["error"], ["request_uri_not_supported"])

    def test_post_with_pushed_request_uri(self):
        push = post_form(
            self.client,
            reverse("oauth2_provider:pushed-authorization-request"),
            self.request_parameters(scope="openid read"),
            **get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET),
        )
        self.assertEqual(push.status_code, 201)
        request_uri = json.loads(push.content)["request_uri"]

        consent = post_form(
            self.client,
            self.authorize_url,
            {"client_id": self.application.client_id, "request_uri": request_uri},
        )

        self.assertEqual(consent.status_code, 200)
        # The pushed request is authoritative and drives the consent screen.
        self.assertEqual(consent.context_data["scopes"], ["openid", "read"])
        params = self.assertRedirectParameters(self.submit_consent(consent))
        self.assertIn("code", params)
        self.assertEqual(params["state"], ["random_state_string"])

    def test_consent_without_csrf_token_is_rejected(self):
        consent = self.post_authorization_request()

        response = self.submit_consent(consent, csrf_token=False)

        self.assertEqual(response.status_code, 403)

    def test_consent_with_wrong_csrf_token_is_rejected(self):
        consent = self.post_authorization_request()
        data = {key: value for key, value in consent.context_data["form"].initial.items() if value}
        data["csrfmiddlewaretoken"] = "x" * 64

        response = post_form(self.client, self.authorize_url, data)

        self.assertEqual(response.status_code, 403)

    def test_consent_with_csrf_header_is_csrf_protected(self):
        consent = self.post_authorization_request()
        data = {key: value for key, value in consent.context_data["form"].initial.items() if value}

        response = post_form(self.client, self.authorize_url, data, HTTP_X_CSRFTOKEN="x" * 64)

        self.assertEqual(response.status_code, 403)

    def test_authorization_request_carrying_allow_is_csrf_protected(self):
        # A cross-site POST cannot pass as consent by including the allow field.
        response = self.post_authorization_request(allow="Authorize")

        self.assertEqual(response.status_code, 403)

    def test_logged_out_consent_without_csrf_token_is_rejected(self):
        self.client.logout()

        response = post_form(self.client, self.authorize_url, self.request_parameters(allow="Authorize"))

        self.assertEqual(response.status_code, 403)

    def test_put_is_csrf_protected(self):
        # Django's FormView handles PUT like a form submission.
        data = urlencode(self.request_parameters(allow="Authorize"))

        response = self.client.put(self.authorize_url, data, content_type="application/x-www-form-urlencoded")

        self.assertEqual(response.status_code, 403)


def _b64decode(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
