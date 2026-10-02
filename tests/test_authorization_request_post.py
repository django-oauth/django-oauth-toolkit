"""Authorization requests sent by HTTP POST (OpenID Connect Core 1.0 section 3.1.2.1).

The authorization endpoint must accept the request by POST, with its parameters
form-serialized in the body, as well as by GET. It answers such a request with a
redirect to the same request sent by GET. The consent form also posts to the
endpoint; it is told apart by its ``allow`` field or CSRF token, and stays
CSRF-protected, while an authorization request sent by POST carries no CSRF token.
"""

import base64
import json
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.middleware.csrf import CsrfViewMiddleware
from django.test import Client, RequestFactory
from django.urls import reverse

from oauth2_provider.authorization_server.views.base import AuthorizationView
from oauth2_provider.models import get_application_model

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header, post_form


Application = get_application_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"
REDIRECT_URI = "http://example.org"


def _b64decode(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


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

    def authorize_by_post(self, url=None, **params):
        """POST the request and follow the redirect to its GET form, as a browser does."""
        response = self.post_authorization_request(url=url, **params)
        self.assertEqual(response.status_code, 303)
        return self.client.get(response["Location"])

    def submit_consent(self, consent, allow=True, csrf_token=True):
        """Post the rendered consent form back to the URL it was loaded from."""
        data = {key: value for key, value in consent.context_data["form"].initial.items() if value}
        if allow:
            data["allow"] = "Authorize"
        if csrf_token:
            data["csrfmiddlewaretoken"] = consent.context["csrf_token"]
        return post_form(self.client, consent.wsgi_request.get_full_path(), data)

    def assertRedirectParameters(self, response, fragment=False):
        self.assertEqual(response.status_code, 302)
        location = urlparse(response["Location"])
        self.assertEqual(f"{location.scheme}://{location.netloc}", REDIRECT_URI)
        return parse_qs(location.fragment if fragment else location.query)

    def assertGetForm(self, response, parameters):
        self.assertEqual(response.status_code, 303)
        location = urlparse(response["Location"])
        self.assertEqual(location.path, self.authorize_url)
        self.assertEqual(parse_qs(location.query), parameters)

    def test_post_redirects_to_get_form(self):
        response = self.post_authorization_request()

        self.assertGetForm(response, {key: [value] for key, value in self.request_parameters().items()})

    def test_post_keeps_query_string_parameters(self):
        url = f"{self.authorize_url}?{urlencode({'ui_locales': 'fr'})}"

        response = self.post_authorization_request(url=url)

        expected = {key: [value] for key, value in self.request_parameters(ui_locales="fr").items()}
        self.assertGetForm(response, expected)

    def test_multipart_post_redirects_to_get_form(self):
        response = self.client.post(self.authorize_url, self.request_parameters())

        self.assertGetForm(response, {key: [value] for key, value in self.request_parameters().items()})

    def test_post_shows_consent_like_get(self):
        response = self.authorize_by_post()

        self.assertEqual(response.status_code, 200)
        get_response = self.client.get(self.authorize_url, self.request_parameters())
        self.assertEqual(response.context_data["form"].initial, get_response.context_data["form"].initial)
        self.assertEqual(response.context_data["application"], self.application)
        self.assertEqual(response.context_data["scopes"], ["openid"])

    def test_post_then_consent_issues_code_and_id_token(self):
        consent = self.authorize_by_post()
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

    def test_post_with_response_mode_is_honoured_through_consent(self):
        consent = self.authorize_by_post(response_mode="fragment")
        response = self.submit_consent(consent)

        params = self.assertRedirectParameters(response, fragment=True)
        self.assertIn("code", params)
        self.assertEqual(params["state"], ["random_state_string"])

    def test_post_then_denial_returns_access_denied(self):
        # The default template's Cancel button submits no allow field, only the
        # CSRF token.
        consent = self.authorize_by_post()
        response = self.submit_consent(consent, allow=False)

        params = self.assertRedirectParameters(response)
        self.assertEqual(params["error"], ["access_denied"])
        self.assertEqual(params["state"], ["random_state_string"])

    def test_post_with_skip_authorization_issues_code(self):
        self.application.skip_authorization = True
        self.application.save()

        response = self.authorize_by_post()

        params = self.assertRedirectParameters(response)
        self.assertIn("code", params)
        self.assertEqual(params["state"], ["random_state_string"])

    def test_post_invalid_request_is_rejected_like_get(self):
        response = self.authorize_by_post(redirect_uri="http://attacker.example")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.context_data["error"].error, "invalid_request")

    def test_parameter_in_both_query_and_body_is_rejected(self):
        # The body joins the query string, so a parameter sent in both is a
        # repeated parameter, as it would be in a GET; it is never resolved in
        # favour of either copy.
        url = f"{self.authorize_url}?{urlencode({'client_id': 'other-client'})}"
        response = self.authorize_by_post(url=url)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.context_data["error"].error, "invalid_request")

    def test_logged_out_post_redirects_to_login_through_get_form(self):
        self.client.logout()

        response = self.authorize_by_post()

        self.assertEqual(response.status_code, 302)
        login = urlparse(response["Location"])
        next_url = urlparse(parse_qs(login.query)["next"][0])
        self.assertEqual(next_url.path, self.authorize_url)
        self.assertEqual(
            {key: values[0] for key, values in parse_qs(next_url.query).items()}, self.request_parameters()
        )

    def test_logged_out_post_with_prompt_none_returns_login_required(self):
        self.client.logout()

        response = self.authorize_by_post(prompt="none", scope="read", nonce=None)

        params = self.assertRedirectParameters(response)
        self.assertEqual(params["error"], ["login_required"])
        self.assertEqual(params["state"], ["random_state_string"])

    def test_post_with_prompt_login_redirects_to_login(self):
        response = self.authorize_by_post(prompt="login")

        self.assertEqual(response.status_code, 302)
        login = urlparse(response["Location"])
        next_url = urlparse(parse_qs(login.query)["next"][0])
        self.assertEqual(next_url.path, self.authorize_url)
        next_parameters = parse_qs(next_url.query)
        # The prompt is kept until the login has been verified; the rest of the
        # request comes from the body.
        self.assertEqual(next_parameters["prompt"], ["login"])
        self.assertEqual(next_parameters["client_id"], [self.application.client_id])
        self.assertEqual(next_parameters["nonce"], ["random_nonce_string"])

    def test_post_with_approval_prompt_auto_reuses_prior_authorization(self):
        consent = self.authorize_by_post()
        code = self.assertRedirectParameters(self.submit_consent(consent))["code"][0]
        post_form(
            self.client,
            reverse("oauth2_provider:token"),
            {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI},
            **get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET),
        )

        response = self.authorize_by_post(approval_prompt="auto")

        self.assertIn("code", self.assertRedirectParameters(response))

    def test_post_with_resources(self):
        resources = ["https://api.example.com", "https://other.example.com"]

        response = self.authorize_by_post(resource=resources)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context_data["form"].initial["resource"], " ".join(resources))

    def test_post_with_invalid_resource_returns_invalid_target(self):
        response = self.authorize_by_post(resource="not-a-uri")

        params = self.assertRedirectParameters(response)
        self.assertEqual(params["error"], ["invalid_target"])
        self.assertEqual(params["state"], ["random_state_string"])

    def test_post_with_request_object_is_rejected(self):
        response = self.authorize_by_post(request="eyJhbGciOiJub25lIn0.e30.")

        params = self.assertRedirectParameters(response)
        self.assertEqual(params["error"], ["request_not_supported"])

    def test_post_with_request_uri_is_rejected(self):
        response = self.authorize_by_post(request_uri="https://client.example/request.jwt")

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

        response = post_form(
            self.client,
            self.authorize_url,
            {"client_id": self.application.client_id, "request_uri": request_uri},
        )
        self.assertEqual(response.status_code, 303)
        consent = self.client.get(response["Location"])

        self.assertEqual(consent.status_code, 200)
        # The pushed request is authoritative and drives the consent screen.
        self.assertEqual(consent.context_data["scopes"], ["openid", "read"])
        params = self.assertRedirectParameters(self.submit_consent(consent))
        self.assertIn("code", params)
        self.assertEqual(params["state"], ["random_state_string"])

    def test_consent_without_csrf_token_is_rejected(self):
        consent = self.authorize_by_post()

        response = self.submit_consent(consent, csrf_token=False)

        self.assertEqual(response.status_code, 403)

    def test_consent_with_wrong_csrf_token_is_rejected(self):
        consent = self.authorize_by_post()
        data = {key: value for key, value in consent.context_data["form"].initial.items() if value}
        data["csrfmiddlewaretoken"] = "x" * 64

        response = post_form(self.client, self.authorize_url, data)

        self.assertEqual(response.status_code, 403)

    def test_consent_with_csrf_header_is_csrf_protected(self):
        consent = self.authorize_by_post()
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

    def test_options_is_unchanged(self):
        response = self.client.options(self.authorize_url)

        self.assertEqual(response.status_code, 200)
        self.assertIn("POST", response["Allow"])

    def test_consent_without_csrf_middleware(self):
        # The view is CSRF-exempt and protects the consent submission itself, so
        # it must also set the cookie the consent form's token is checked against.
        middleware = [m for m in settings.MIDDLEWARE if m != "django.middleware.csrf.CsrfViewMiddleware"]
        with self.settings(MIDDLEWARE=middleware):
            consent = self.authorize_by_post()
            self.assertEqual(self.submit_consent(consent, csrf_token=False).status_code, 403)
            response = self.submit_consent(consent)

        self.assertIn("code", self.assertRedirectParameters(response))

    def test_csrf_cookie_is_set_only_with_the_consent_form(self):
        middleware = [m for m in settings.MIDDLEWARE if m != "django.middleware.csrf.CsrfViewMiddleware"]
        with self.settings(MIDDLEWARE=middleware):
            consent = self.authorize_by_post()
            self.assertIn(settings.CSRF_COOKIE_NAME, consent.cookies)

            self.client.cookies.clear()
            self.application.skip_authorization = True
            self.application.save()
            self.client.login(username="test_user", password="123456")
            response = self.authorize_by_post()

        self.assertIn("code", self.assertRedirectParameters(response))
        self.assertNotIn(settings.CSRF_COOKIE_NAME, response.cookies)


class TestAuthorizationViewSubclass(TestCase):
    def test_csrf_exemption_survives_dispatch_override(self):
        class CustomAuthorizationView(AuthorizationView):
            def dispatch(self, request, *args, **kwargs):
                return super().dispatch(request, *args, **kwargs)

        view = CustomAuthorizationView.as_view()
        request = RequestFactory().post("/o/authorize/", {"client_id": "client"})

        # The CSRF middleware lets the authorization request reach the view.
        self.assertIsNone(CsrfViewMiddleware(lambda request: None).process_view(request, view, (), {}))
        self.assertEqual(view(request).status_code, 303)
