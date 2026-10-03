import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.urls import reverse, reverse_lazy

from oauth2_provider.authorization_server.sessions import AUTH_EVENT_SESSION_KEY, AUTH_TIME_SESSION_KEY
from oauth2_provider.authorization_server.stored_requests import REQUEST_URI_PREFIX
from oauth2_provider.models import (
    create_stored_authorization_request,
    get_application_model,
    get_grant_model,
    get_stored_authorization_request_model,
)

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header, post_form


Application = get_application_model()
Grant = get_grant_model()
StoredAuthorizationRequest = get_stored_authorization_request_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"


def _pkce_pair():
    verifier = "a" * 64
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.DEFAULT_SCOPES_RW)
class PARBaseTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.test_user = UserModel.objects.create_user("test_user", "test@example.com", "123456")
        cls.dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")

        cls.application = Application.objects.create(
            name="Test Application",
            redirect_uris="http://example.org http://example.com",
            user=cls.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
        )
        cls.public_application = Application.objects.create(
            name="Public Application",
            redirect_uris="http://example.org",
            user=cls.dev_user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

    def setUp(self):
        self.oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES = ["http", "https"]
        self.oauth2_settings.PKCE_REQUIRED = False

    @property
    def par_url(self):
        return reverse("oauth2_provider:pushed-authorization-request")

    @property
    def authorize_url(self):
        return reverse("oauth2_provider:authorize")

    def push(self, extra=None, auth=True, **kwargs):
        data = {
            "client_id": self.application.client_id,
            "response_type": "code",
            "redirect_uri": "http://example.org",
            "scope": "read write",
            "state": "some_state",
        }
        if extra:
            data.update(extra)
        headers = {}
        if auth:
            headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        return post_form(self.client, self.par_url, data=data, **headers, **kwargs)


class TestPAREndpoint(PARBaseTestCase):
    def test_successful_push_returns_request_uri(self):
        response = self.push()
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response["Cache-Control"], "no-cache, no-store")
        body = json.loads(response.content)
        self.assertTrue(body["request_uri"].startswith(REQUEST_URI_PREFIX))
        self.assertEqual(body["expires_in"], self.oauth2_settings.PAR_REQUEST_URI_LIFETIME_SECONDS)

        par = StoredAuthorizationRequest.objects.get(request_uri=body["request_uri"])
        self.assertEqual(par.client_id, self.application.client_id)
        self.assertEqual(par.parameters["scope"], "read write")
        # Client-authentication parameters are never stored on the pushed request.
        self.assertNotIn("client_secret", par.parameters)

    def test_get_method_not_allowed(self):
        response = self.client.get(self.par_url)
        self.assertEqual(response.status_code, 405)

    def test_reject_request_uri_parameter(self):
        response = self.push(extra={"request_uri": f"{REQUEST_URI_PREFIX}abc"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_request")

    def test_reject_request_object(self):
        response = self.push(extra={"request": "eyJ.abc.def"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_request")

    def test_reject_request_uri_in_query_string(self):
        # The guard must also catch request_uri supplied via the query string, which
        # oauthlib would otherwise merge into the request (RFC 9126 §2.1).
        headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        response = post_form(
            self.client,
            self.par_url + f"?request_uri={REQUEST_URI_PREFIX}abc",
            data={
                "client_id": self.application.client_id,
                "response_type": "code",
                "redirect_uri": "http://example.org",
                "scope": "read write",
            },
            **headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_request")

    def test_reject_request_object_in_query_string(self):
        headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        response = post_form(
            self.client,
            self.par_url + "?request=eyJ.abc.def",
            data={
                "client_id": self.application.client_id,
                "response_type": "code",
                "redirect_uri": "http://example.org",
                "scope": "read write",
            },
            **headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_request")

    def test_client_authentication_required(self):
        response = self.push(auth=False)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(json.loads(response.content)["error"], "invalid_client")
        # RFC 6749 §5.2: a 401 client-authentication failure carries a WWW-Authenticate header.
        self.assertIn('error="invalid_client"', response["WWW-Authenticate"])

    def test_wrong_client_secret_rejected(self):
        headers = get_basic_auth_header(self.application.client_id, "wrong-secret")
        response = post_form(
            self.client,
            self.par_url,
            data={
                "client_id": self.application.client_id,
                "response_type": "code",
                "redirect_uri": "http://example.org",
                "scope": "read write",
            },
            **headers,
        )
        self.assertEqual(response.status_code, 401)

    def test_public_client_with_pkce(self):
        _, challenge = _pkce_pair()
        response = post_form(
            self.client,
            self.par_url,
            data={
                "client_id": self.public_application.client_id,
                "response_type": "code",
                "redirect_uri": "http://example.org",
                "scope": "read write",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        self.assertEqual(response.status_code, 201)
        body = json.loads(response.content)
        par = StoredAuthorizationRequest.objects.get(request_uri=body["request_uri"])
        self.assertEqual(par.client_id, self.public_application.client_id)

    def test_invalid_redirect_uri_rejected(self):
        response = self.push(extra={"redirect_uri": "http://not-registered.example"})
        self.assertEqual(response.status_code, 400)

    def test_client_id_mismatch_rejected(self):
        # Authenticate as the confidential client but claim a different client_id.
        response = self.push(extra={"client_id": self.public_application.client_id})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_request")

    def test_disabled_par_endpoint(self):
        # A disabled endpoint behaves as absent (404), like DCR when DCR_ENABLED is off.
        self.oauth2_settings.PAR_ENABLED = False
        response = self.push()
        self.assertEqual(response.status_code, 404)

    def test_disabled_par_endpoint_is_absent_for_all_methods(self):
        # The gate lives in dispatch(), so a disabled endpoint is 404 for every method
        # (not 405 for non-POST via http_method_names).
        self.oauth2_settings.PAR_ENABLED = False
        self.assertEqual(self.client.get(self.par_url).status_code, 404)

    def test_query_string_client_id_binding_enforced(self):
        # oauthlib validates the merged query string + body, so a client_id supplied
        # via the query string must not bypass the binding check.
        headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        response = post_form(
            self.client,
            self.par_url + f"?client_id={self.public_application.client_id}",
            data={
                "response_type": "code",
                "redirect_uri": "http://example.org",
                "scope": "read write",
            },
            **headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_request")

    def test_query_string_parameters_are_stored(self):
        # A parameter supplied via the query string is validated by oauthlib, so it
        # must also be stored (merged with the body) — otherwise the request_uri would
        # resolve to different parameters than were validated.
        headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        response = post_form(
            self.client,
            self.par_url + "?scope=read+write",
            data={
                "client_id": self.application.client_id,
                "response_type": "code",
                "redirect_uri": "http://example.org",
            },
            **headers,
        )
        self.assertEqual(response.status_code, 201)
        par = StoredAuthorizationRequest.objects.get(request_uri=json.loads(response.content)["request_uri"])
        self.assertEqual(par.parameters["scope"], "read write")

    def test_client_secret_post_excluded_from_stored_parameters(self):
        # Authenticate via client_secret_post (credentials in the body). The
        # client-authentication parameters must not be stored on the pushed request.
        response = post_form(
            self.client,
            self.par_url,
            data={
                "client_id": self.application.client_id,
                "client_secret": CLEARTEXT_SECRET,
                "response_type": "code",
                "redirect_uri": "http://example.org",
                "scope": "read write",
            },
        )
        self.assertEqual(response.status_code, 201)
        par = StoredAuthorizationRequest.objects.get(request_uri=json.loads(response.content)["request_uri"])
        self.assertNotIn("client_secret", par.parameters)
        self.assertEqual(par.parameters["client_id"], self.application.client_id)

    def test_resource_parameters_are_stored_as_list(self):
        # RFC 8707 resource indicators may be repeated; every value must be
        # preserved (as a list) so the resolved authorization request sees them all.
        response = self.push(
            extra={"resource": ["https://api.example.org", "https://files.example.org"]},
        )
        self.assertEqual(response.status_code, 201)
        par = StoredAuthorizationRequest.objects.get(request_uri=json.loads(response.content)["request_uri"])
        self.assertEqual(
            par.parameters["resource"],
            ["https://api.example.org", "https://files.example.org"],
        )


class TestPARResponseMode(PARBaseTestCase):
    def test_query_response_mode_rejected_for_token_response_type(self):
        """
        response_mode=query is invalid for a response type that returns tokens in
        the front channel (OAuth 2.0 Multiple Response Type Encoding Practices),
        including when it arrives in the PAR request body.
        """
        implicit_application = Application.objects.create(
            name="Implicit Application",
            redirect_uris="http://example.org",
            user=self.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_IMPLICIT,
            client_secret=CLEARTEXT_SECRET,
        )
        data = {
            "client_id": implicit_application.client_id,
            "response_type": "token",
            "response_mode": "query",
            "redirect_uri": "http://example.org",
            "scope": "read write",
            "state": "some_state",
        }
        headers = get_basic_auth_header(implicit_application.client_id, CLEARTEXT_SECRET)

        response = post_form(self.client, self.par_url, data=data, **headers)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_request")


@pytest.mark.usefixtures("oauth2_settings", "oidc_key")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestPARReorderedResponseType(TestCase):
    """
    The order of a multi-valued response_type does not matter (RFC 6749 §3.1.1), so a
    pushed request is served in any ordering, like one sent to the authorization endpoint.
    """

    par_url = reverse_lazy("oauth2_provider:pushed-authorization-request")
    authorize_url = reverse_lazy("oauth2_provider:authorize")

    @classmethod
    def setUpTestData(cls):
        cls.test_user = UserModel.objects.create_user("test_user", "test@example.com", "123456")
        cls.dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")
        cls.hybrid_application = Application.objects.create(
            name="Hybrid Application",
            redirect_uris="http://example.org",
            user=cls.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_OPENID_HYBRID,
            algorithm=Application.RS256_ALGORITHM,
            client_secret=CLEARTEXT_SECRET,
        )

    def push_hybrid(self, **extra):
        data = {
            "client_id": self.hybrid_application.client_id,
            "response_type": "id_token code",
            "redirect_uri": "http://example.org",
            "scope": "openid read",
            "state": "some_state",
            "nonce": "some_nonce",
            **extra,
        }
        headers = get_basic_auth_header(self.hybrid_application.client_id, CLEARTEXT_SECRET)
        return post_form(self.client, self.par_url, data=data, **headers)

    def test_push_then_authorize(self):
        push = self.push_hybrid()
        self.assertEqual(push.status_code, 201)
        request_uri = json.loads(push.content)["request_uri"]

        self.client.login(username="test_user", password="123456")
        query = {"client_id": self.hybrid_application.client_id, "request_uri": request_uri}
        consent = self.client.get(self.authorize_url, query)
        self.assertEqual(consent.status_code, 200)
        form_data = {k: v for k, v in consent.context_data["form"].initial.items() if v is not None}
        self.assertEqual(form_data["response_type"], "code id_token")
        form_data["allow"] = True
        response = self.client.post(f"{self.authorize_url}?{urlencode(query)}", data=form_data)

        self.assertEqual(response.status_code, 302)
        location = urlparse(response["Location"])
        self.assertEqual(location.query, "")
        params = parse_qs(location.fragment)
        self.assertIn("code", params)
        self.assertIn("id_token", params)
        self.assertEqual(params["state"], ["some_state"])

    def test_query_response_mode_still_rejected(self):
        response = self.push_hybrid(response_mode="query")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_request")


class TestAuthorizeWithRequestURI(PARBaseTestCase):
    def _make_par(self, client_id=None, expires_in=60, parameters=None):
        request_uri = f"{REQUEST_URI_PREFIX}test-reference-value"
        params = parameters or {
            "client_id": client_id or self.application.client_id,
            "response_type": "code",
            "redirect_uri": "http://example.org",
            "scope": "read write",
            "state": "some_state",
        }
        return create_stored_authorization_request(
            request_uri=request_uri,
            client_id=client_id or self.application.client_id,
            parameters=params,
            expires_in=expires_in,
        )

    def test_end_to_end_push_then_authorize(self):
        push = self.push()
        request_uri = json.loads(push.content)["request_uri"]

        self.client.login(username="test_user", password="123456")
        response = self.client.get(
            self.authorize_url,
            {"client_id": self.application.client_id, "request_uri": request_uri},
        )
        self.assertEqual(response.status_code, 200)
        # The pushed scopes drive the consent screen.
        self.assertIn("read", response.context_data["scopes"])
        self.assertIn("write", response.context_data["scopes"])

    def _consent_after_push(self, allow):
        """Push with response_mode=fragment, open consent, then post the form back."""
        push = self.push(extra={"response_mode": "fragment"})
        request_uri = json.loads(push.content)["request_uri"]
        self.client.login(username="test_user", password="123456")
        query = {"client_id": self.application.client_id, "request_uri": request_uri}
        consent = self.client.get(self.authorize_url, query)
        self.assertEqual(consent.status_code, 200)
        form_data = {k: v for k, v in consent.context_data["form"].initial.items() if v is not None}
        form_data["allow"] = allow
        # The browser posts back to the URL it loaded, which carries only request_uri.
        return self.client.post(f"{self.authorize_url}?{urlencode(query)}", data=form_data)

    def test_pushed_response_mode_kept_on_denial(self):
        response = self._consent_after_push(allow=False)

        self.assertEqual(response.status_code, 302)
        location = urlparse(response["Location"])
        self.assertEqual(location.query, "")
        self.assertEqual(parse_qs(location.fragment)["error"], ["access_denied"])

    def test_pushed_response_mode_kept_on_approval(self):
        response = self._consent_after_push(allow=True)

        self.assertEqual(response.status_code, 302)
        location = urlparse(response["Location"])
        self.assertEqual(location.query, "")
        self.assertIn("code", parse_qs(location.fragment))

    def test_skip_authorization_issues_code(self):
        self.application.skip_authorization = True
        self.application.save()
        par = self._make_par()

        self.client.login(username="test_user", password="123456")
        response = self.client.get(
            self.authorize_url,
            {"client_id": self.application.client_id, "request_uri": par.request_uri},
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Grant.objects.filter(application=self.application).exists())

    def test_request_uri_is_single_use(self):
        par = self._make_par()
        self.client.login(username="test_user", password="123456")
        first = self.client.get(
            self.authorize_url,
            {"client_id": self.application.client_id, "request_uri": par.request_uri},
        )
        self.assertEqual(first.status_code, 200)
        # The record is consumed on first use.
        self.assertFalse(StoredAuthorizationRequest.objects.filter(pk=par.pk).exists())
        second = self.client.get(
            self.authorize_url,
            {"client_id": self.application.client_id, "request_uri": par.request_uri},
        )
        self.assertEqual(second.status_code, 400)

    def test_expired_request_uri_rejected(self):
        par = self._make_par(expires_in=-10)
        self.client.login(username="test_user", password="123456")
        response = self.client.get(
            self.authorize_url,
            {"client_id": self.application.client_id, "request_uri": par.request_uri},
        )
        self.assertEqual(response.status_code, 400)

    def test_unknown_request_uri_rejected(self):
        self.client.login(username="test_user", password="123456")
        response = self.client.get(
            self.authorize_url,
            {
                "client_id": self.application.client_id,
                "request_uri": f"{REQUEST_URI_PREFIX}does-not-exist",
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_request_uri_bound_to_client(self):
        par = self._make_par(client_id=self.application.client_id)
        self.client.login(username="test_user", password="123456")
        response = self.client.get(
            self.authorize_url,
            {"client_id": self.public_application.client_id, "request_uri": par.request_uri},
        )
        self.assertEqual(response.status_code, 400)
        # A non-bound client must NOT be able to consume/invalidate the request_uri
        # (RFC 9126 §2.2): the record survives, so the bound client can still use it.
        self.assertTrue(StoredAuthorizationRequest.objects.filter(pk=par.pk).exists())
        legit = self.client.get(
            self.authorize_url,
            {"client_id": self.application.client_id, "request_uri": par.request_uri},
        )
        self.assertEqual(legit.status_code, 200)

    def test_inline_parameters_are_ignored(self):
        # Regression guard: the pushed request is authoritative, so authorization
        # parameters supplied alongside request_uri must be ignored (never honored),
        # which prevents parameter injection (RFC 9126).
        par = self._make_par(
            parameters={
                "client_id": self.application.client_id,
                "response_type": "code",
                "redirect_uri": "http://example.org",
                "scope": "read write",
                "state": "pushed_state",
            }
        )
        self.client.login(username="test_user", password="123456")
        response = self.client.get(
            self.authorize_url,
            {
                "client_id": self.application.client_id,
                "request_uri": par.request_uri,
                # Inline overrides that must be ignored (both redirect URIs are
                # registered, so example.com is dropped for being inline, not invalid):
                "scope": "read",
                "redirect_uri": "http://example.com",
                "state": "injected_state",
            },
        )
        self.assertEqual(response.status_code, 200)
        # Pushed "read write" wins over inline "read".
        self.assertIn("write", response.context_data["scopes"])
        form_initial = response.context_data["form"].initial
        self.assertEqual(form_initial["scope"], "read write")
        self.assertEqual(form_initial["redirect_uri"], "http://example.org")
        self.assertEqual(form_initial["state"], "pushed_state")

    def test_request_uri_requires_client_id(self):
        par = self._make_par(client_id=self.application.client_id)
        self.client.login(username="test_user", password="123456")
        response = self.client.get(self.authorize_url, {"request_uri": par.request_uri})
        self.assertEqual(response.status_code, 400)
        # Omitting client_id must not consume the record either.
        self.assertTrue(StoredAuthorizationRequest.objects.filter(pk=par.pk).exists())


class TestPAREnforcement(PARBaseTestCase):
    def test_global_enforcement_blocks_plain_request(self):
        self.oauth2_settings.REQUIRE_PUSHED_AUTHORIZATION_REQUESTS = True
        self.client.login(username="test_user", password="123456")
        response = self.client.get(
            self.authorize_url,
            {
                "client_id": self.application.client_id,
                "response_type": "code",
                "redirect_uri": "http://example.org",
                "scope": "read write",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("this authorization server requires", response.content.decode().lower())

    def test_global_enforcement_allows_pushed_request(self):
        self.oauth2_settings.REQUIRE_PUSHED_AUTHORIZATION_REQUESTS = True
        push = self.push()
        request_uri = json.loads(push.content)["request_uri"]
        self.client.login(username="test_user", password="123456")
        response = self.client.get(
            self.authorize_url,
            {"client_id": self.application.client_id, "request_uri": request_uri},
        )
        self.assertEqual(response.status_code, 200)

    def test_not_required_without_client_id(self):
        # With enforcement off and no client_id, PAR is not required; the request
        # falls through to normal authorization validation (which then errors).
        self.client.login(username="test_user", password="123456")
        response = self.client.get(self.authorize_url, {"response_type": "code"})
        self.assertEqual(response.status_code, 400)

    def test_per_application_enforcement(self):
        self.application.require_pushed_authorization_requests = True
        self.application.save()
        self.client.login(username="test_user", password="123456")
        response = self.client.get(
            self.authorize_url,
            {
                "client_id": self.application.client_id,
                "response_type": "code",
                "redirect_uri": "http://example.org",
                "scope": "read write",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("required for this client", response.content.decode().lower())


class TestPARReauthentication(PARBaseTestCase):
    """A pushed request that needs the user to log in again survives the login."""

    def setUp(self):
        super().setUp()
        # The login redirect must work for a client that may only use PAR.
        self.application.require_pushed_authorization_requests = True
        self.application.save()

    def _authorize(self, request_uri):
        return self.client.get(
            self.authorize_url, {"client_id": self.application.client_id, "request_uri": request_uri}
        )

    def _next_url(self, response):
        self.assertEqual(response.status_code, 302)
        location = urlparse(response["Location"])
        self.assertEqual(location.path, settings.LOGIN_URL)
        return parse_qs(location.query)["next"][0]

    def test_prompt_login_pushes_the_request_again(self):
        push = self.push(
            extra={"prompt": "login", "resource": ["https://api.example.com", "https://other.example.com"]}
        )
        request_uri = json.loads(push.content)["request_uri"]
        self.client.login(username="test_user", password="123456")

        next_url = urlparse(self._next_url(self._authorize(request_uri)))

        # The return URL carries only a new request_uri for the same client; the
        # one the client sent has been used.
        self.assertEqual(next_url.path, self.authorize_url)
        next_query = parse_qs(next_url.query)
        self.assertEqual(set(next_query), {"client_id", "request_uri"})
        self.assertEqual(next_query["client_id"], [self.application.client_id])
        new_request_uri = next_query["request_uri"][0]
        self.assertTrue(new_request_uri.startswith(REQUEST_URI_PREFIX))
        self.assertNotEqual(new_request_uri, request_uri)
        pushed = StoredAuthorizationRequest.objects.get(request_uri=new_request_uri)
        self.assertEqual(pushed.client_id, self.application.client_id)
        # The prompt stays on the server until the login has been verified.
        self.assertEqual(pushed.parameters["prompt"], "login")
        self.assertEqual(pushed.parameters["state"], "some_state")
        self.assertEqual(
            pushed.parameters["resource"], ["https://api.example.com", "https://other.example.com"]
        )

        self.client.login(username="test_user", password="123456")
        response = self.client.get(f"{next_url.path}?{next_url.query}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context_data["state"], "some_state")

    def test_expired_max_age_pushes_the_request_again(self):
        self.oauth2_settings.update(presets.OIDC_SETTINGS_RW)
        push = self.push(extra={"scope": "openid read", "max_age": "60"})
        request_uri = json.loads(push.content)["request_uri"]
        self.client.login(username="test_user", password="123456")
        session = self.client.session
        session[AUTH_TIME_SESSION_KEY] = time.time() - 3600
        session.save()

        # max_age is read from the pushed request, not from the query.
        next_url = urlparse(self._next_url(self._authorize(request_uri)))

        next_query = parse_qs(next_url.query)
        self.assertEqual(set(next_query), {"client_id", "request_uri"})
        pushed = StoredAuthorizationRequest.objects.get(request_uri=next_query["request_uri"][0])
        self.assertEqual(pushed.parameters["max_age"], "60")

        self.client.login(username="test_user", password="123456")
        response = self.client.get(f"{next_url.path}?{next_url.query}")
        self.assertEqual(response.status_code, 200)

    def test_anonymous_prompt_login_logs_in_once(self):
        # The pushed prompt is not in the query, so the login that LoginRequiredMixin
        # asks for is the one that satisfies it.
        push = self.push(extra={"prompt": "login"})
        request_uri = json.loads(push.content)["request_uri"]

        next_url = self._next_url(self._authorize(request_uri))
        self.assertIn(urlencode({"request_uri": request_uri}), next_url)

        self.client.login(username="test_user", password="123456")
        response = self.client.get(next_url)
        self.assertEqual(response.status_code, 200)

    def test_malformed_max_age_is_rejected_when_pushed(self):
        # The pushed request is validated as at the authorization endpoint.
        self.oauth2_settings.update(presets.OIDC_SETTINGS_RW)
        response = self.push(extra={"scope": "openid read", "max_age": "abc"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_request")

        response = self.push(extra={"scope": "openid read", "max_age": "60"})
        self.assertEqual(response.status_code, 201)

    def test_query_max_age_beside_a_pushed_request_is_ignored(self):
        # The pushed request is authoritative: a stray max_age in the query does
        # not change how an anonymous user is handled.
        self.oauth2_settings.update(presets.OIDC_SETTINGS_RW)
        request_uri = json.loads(self.push(extra={"scope": "openid read"}).content)["request_uri"]

        response = self.client.get(
            self.authorize_url,
            {"client_id": self.application.client_id, "request_uri": request_uri, "max_age": "abc"},
        )
        self._next_url(response)

    def test_anonymous_pushed_request_authenticated_without_a_recorded_login(self):
        # A login that does not go through Django's login() records no login
        # identifier; a pushed request that asks for no new login still works.
        request_uri = json.loads(self.push().content)["request_uri"]
        next_url = self._next_url(self._authorize(request_uri))
        self.client.login(username="test_user", password="123456")
        session = self.client.session
        session.pop(AUTH_EVENT_SESSION_KEY)
        session.save()

        response = self.client.get(next_url)
        self.assertEqual(response.status_code, 200)

    def test_repeated_parameters_are_rejected_when_pushed(self):
        self.oauth2_settings.update(presets.OIDC_SETTINGS_RW)
        # Split between the query string and the body.
        response = self.push(extra={"scope": "openid read", "max_age": "0"}, QUERY_STRING="max_age=999999")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_request")

        response = self.push(extra={"prompt": ["login", "none"]})
        self.assertEqual(response.status_code, 400)

    def test_following_the_return_url_without_logging_in_is_login_required(self):
        self.client.login(username="test_user", password="123456")
        request_uri = json.loads(self.push(extra={"prompt": "login"}).content)["request_uri"]
        next_url = self._next_url(self._authorize(request_uri))

        # The pushed request keeps its prompt=login, so a session that skips the
        # login page does not reach consent; the client gets the error.
        response = self.client.get(next_url)
        self.assertEqual(response.status_code, 302)
        location = urlparse(response["Location"])
        self.assertEqual(f"{location.scheme}://{location.netloc}", "http://example.org")
        query = parse_qs(location.query)
        self.assertEqual(query["error"], ["login_required"])
        self.assertEqual(query["state"], ["some_state"])

    def test_prompt_login_without_logging_in_is_sent_to_login_again(self):
        self.client.login(username="test_user", password="123456")
        first = json.loads(self.push(extra={"prompt": "login"}).content)["request_uri"]
        self._next_url(self._authorize(first))

        # Being sent to log in is not logging in: a stale session that skips the
        # login page is asked again.
        second = json.loads(self.push(extra={"prompt": "login"}).content)["request_uri"]
        self._next_url(self._authorize(second))


@pytest.mark.usefixtures("oauth2_settings")
class TestPARMetadata(TestCase):
    def _metadata(self):
        response = self.client.get(reverse("oauth2_provider:oauth-server-metadata"))
        return json.loads(response.content)

    def test_advertises_par_endpoint(self):
        data = self._metadata()
        self.assertIn("pushed_authorization_request_endpoint", data)
        self.assertNotIn("require_pushed_authorization_requests", data)

    def test_advertises_require_par(self):
        self.oauth2_settings.REQUIRE_PUSHED_AUTHORIZATION_REQUESTS = True
        data = self._metadata()
        self.assertTrue(data["require_pushed_authorization_requests"])

    def test_hidden_when_disabled(self):
        self.oauth2_settings.PAR_ENABLED = False
        data = self._metadata()
        self.assertNotIn("pushed_authorization_request_endpoint", data)


class TestPARModel(PARBaseTestCase):
    def test_is_expired(self):
        active = self._create(expires_in=60)
        expired = self._create(expires_in=-10, reference="expired")
        self.assertFalse(active.is_expired())
        self.assertTrue(expired.is_expired())

    def test_is_expired_without_expiry(self):
        par = StoredAuthorizationRequest(request_uri=f"{REQUEST_URI_PREFIX}x", client_id="c", expires=None)
        self.assertTrue(par.is_expired())

    def test_str_does_not_leak_request_uri(self):
        par = self._create(expires_in=60)
        rendered = str(par)
        self.assertNotIn(par.request_uri, rendered)
        self.assertIn(str(par.pk), rendered)

    def _create(self, expires_in, reference="active"):
        return create_stored_authorization_request(
            request_uri=f"{REQUEST_URI_PREFIX}{reference}",
            client_id=self.application.client_id,
            parameters={"client_id": self.application.client_id},
            expires_in=expires_in,
        )
