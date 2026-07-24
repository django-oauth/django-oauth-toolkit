import base64
import hashlib
import json

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse

from oauth2_provider.models import (
    create_pushed_authorization_request,
    get_application_model,
    get_grant_model,
    get_par_request_model,
)
from oauth2_provider.views.par import REQUEST_URI_PREFIX

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header


Application = get_application_model()
Grant = get_grant_model()
PushedAuthorizationRequest = get_par_request_model()
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
        return self.client.post(self.par_url, data=data, **headers, **kwargs)


class TestPAREndpoint(PARBaseTestCase):
    def test_successful_push_returns_request_uri(self):
        response = self.push()
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response["Cache-Control"], "no-cache, no-store")
        body = json.loads(response.content)
        self.assertTrue(body["request_uri"].startswith(REQUEST_URI_PREFIX))
        self.assertEqual(body["expires_in"], self.oauth2_settings.PAR_REQUEST_URI_LIFETIME_SECONDS)

        par = PushedAuthorizationRequest.objects.get(request_uri=body["request_uri"])
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

    def test_client_authentication_required(self):
        response = self.push(auth=False)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(json.loads(response.content)["error"], "invalid_client")

    def test_wrong_client_secret_rejected(self):
        headers = get_basic_auth_header(self.application.client_id, "wrong-secret")
        response = self.client.post(
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
        response = self.client.post(
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
        par = PushedAuthorizationRequest.objects.get(request_uri=body["request_uri"])
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
        self.oauth2_settings.PAR_ENABLED = False
        response = self.push()
        self.assertEqual(response.status_code, 400)


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
        return create_pushed_authorization_request(
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
        self.assertFalse(PushedAuthorizationRequest.objects.filter(pk=par.pk).exists())
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

    def _create(self, expires_in, reference="active"):
        return create_pushed_authorization_request(
            request_uri=f"{REQUEST_URI_PREFIX}{reference}",
            client_id=self.application.client_id,
            parameters={"client_id": self.application.client_id},
            expires_in=expires_in,
        )
