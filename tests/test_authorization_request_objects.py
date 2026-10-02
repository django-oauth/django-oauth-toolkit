"""Request objects (OpenID Connect Core 1.0 section 6) are not supported.

The authorization endpoint answers the ``request`` parameter and any ``request_uri``
that is not a PAR request URI with the section 3.1.2.6 ``request_not_supported`` and
``request_uri_not_supported`` errors, redirected once the client and redirect URI
have been validated.
"""

from unittest import mock
from urllib.parse import parse_qs, urlparse

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from oauthlib.oauth2.rfc6749.errors import InvalidRequestError

from oauth2_provider.authorization_server.par import REQUEST_URI_PREFIX
from oauth2_provider.authorization_server.views.base import AuthorizationView
from oauth2_provider.core.exceptions import OAuthToolkitError
from oauth2_provider.models import create_pushed_authorization_request, get_application_model
from oauth2_provider.oauth2_validators import OAuth2Validator

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()
UserModel = get_user_model()

# An unsigned request object ({"alg": "none"}) carrying its own state and nonce.
REQUEST_OBJECT = "eyJhbGciOiJub25lIn0.eyJzdGF0ZSI6ImlubmVyX3N0YXRlIiwibm9uY2UiOiJpbm5lcl9ub25jZSJ9."


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestUnsupportedRequestObjects(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.test_user = UserModel.objects.create_user("test_user", "test@example.com", "123456")
        dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")
        cls.application = Application.objects.create(
            name="Code Application",
            redirect_uris="http://example.org",
            user=dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            algorithm=Application.RS256_ALGORITHM,
        )
        cls.implicit_application = Application.objects.create(
            name="Implicit Application",
            redirect_uris="http://example.org",
            user=dev_user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_IMPLICIT,
            algorithm=Application.RS256_ALGORITHM,
        )

    def setUp(self):
        self.client.login(username="test_user", password="123456")

    def authorize(self, method="get", **params):
        query = {
            "client_id": self.application.client_id,
            "response_type": "code",
            "redirect_uri": "http://example.org",
            "scope": "openid",
            "state": "outer_state",
        }
        query.update(params)
        send = getattr(self.client, method)
        return send(reverse("oauth2_provider:authorize"), {k: v for k, v in query.items() if v})

    def assertErrorRedirect(self, response, error, state="outer_state"):
        self.assertEqual(response.status_code, 302)
        location = urlparse(response["Location"])
        self.assertEqual(f"{location.scheme}://{location.netloc}", "http://example.org")
        params = parse_qs(location.query)
        self.assertEqual(params["error"], [error])
        if state is None:
            self.assertNotIn("state", params)
        else:
            self.assertEqual(params["state"], [state])
        return params

    def test_request_parameter_is_rejected(self):
        response = self.authorize(request=REQUEST_OBJECT)
        self.assertErrorRedirect(response, "request_not_supported")

    def test_request_parameter_without_outer_state(self):
        # The state inside the request object is not read, so none is echoed.
        response = self.authorize(request=REQUEST_OBJECT, state=None)
        self.assertErrorRedirect(response, "request_not_supported", state=None)

    def test_request_parameter_rejected_when_outer_parameters_are_incomplete(self):
        # The nonce an implicit request needs may be inside the request object, so the
        # unsupported parameter is reported rather than the missing nonce.
        response = self.authorize(
            client_id=self.implicit_application.client_id,
            response_type="id_token",
            request=REQUEST_OBJECT,
        )
        self.assertErrorRedirect(response, "request_not_supported")

    def test_request_uri_is_rejected(self):
        response = self.authorize(request_uri="https://client.example/req.jwt")
        self.assertErrorRedirect(response, "request_uri_not_supported")

    # Django's View answers HEAD with get(); with skip_authorization a request
    # that slipped past the check would be issued a code.
    def test_head_request_parameter_is_rejected(self):
        self.application.skip_authorization = True
        self.application.save()
        response = self.authorize(method="head", request=REQUEST_OBJECT)
        self.assertErrorRedirect(response, "request_not_supported")

    def test_head_request_uri_is_rejected(self):
        self.application.skip_authorization = True
        self.application.save()
        response = self.authorize(method="head", request_uri="https://client.example/req.jwt")
        self.assertErrorRedirect(response, "request_uri_not_supported")

    def test_request_takes_precedence_over_request_uri(self):
        response = self.authorize(request=REQUEST_OBJECT, request_uri="https://client.example/req.jwt")
        self.assertErrorRedirect(response, "request_not_supported")

    def test_error_redirect_carries_iss(self):
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS = True
        response = self.authorize(request=REQUEST_OBJECT)
        params = self.assertErrorRedirect(response, "request_not_supported")
        self.assertIn("iss", params)

    def test_unknown_client_is_not_redirected(self):
        response = self.authorize(client_id="unknown", request=REQUEST_OBJECT)
        self.assertEqual(response.status_code, 400)

    def test_unregistered_redirect_uri_is_not_redirected(self):
        response = self.authorize(redirect_uri="http://attacker.example", request_uri="https://x.example/r")
        self.assertEqual(response.status_code, 400)

    def test_error_without_redirect_uri_is_not_redirected(self):
        error = OAuthToolkitError(error=InvalidRequestError())
        with mock.patch.object(AuthorizationView, "validate_authorization_request", side_effect=error):
            response = self.authorize(request=REQUEST_OBJECT)
        self.assertEqual(response.status_code, 400)

    def test_par_required_client_gets_par_error(self):
        self.application.require_pushed_authorization_requests = True
        self.application.save()
        response = self.authorize(request_uri="https://client.example/req.jwt")
        self.assertEqual(response.status_code, 400)
        self.assertIn("required for this client", response.content.decode().lower())

    def make_par(self):
        return create_pushed_authorization_request(
            request_uri=f"{REQUEST_URI_PREFIX}test-reference-value",
            client_id=self.application.client_id,
            parameters={
                "client_id": self.application.client_id,
                "response_type": "code",
                "redirect_uri": "http://example.org",
                "scope": "openid",
                "state": "pushed_state",
            },
            expires_in=60,
        )

    def test_par_request_uri_is_still_resolved(self):
        par = self.make_par()
        response = self.client.get(
            reverse("oauth2_provider:authorize"),
            {"client_id": self.application.client_id, "request_uri": par.request_uri},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context_data["state"], "pushed_state")

    def test_request_alongside_par_request_uri_is_ignored(self):
        # The pushed request is authoritative (RFC 9126), so a request parameter
        # sent next to a PAR request_uri is ignored like any other.
        par = self.make_par()
        response = self.client.get(
            reverse("oauth2_provider:authorize"),
            {
                "client_id": self.application.client_id,
                "request_uri": par.request_uri,
                "request": REQUEST_OBJECT,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context_data["state"], "pushed_state")


class TestUnsupportedRequestObjectsAnonymous(TestUnsupportedRequestObjects):
    """The same requests from an end-user who is not logged in.

    The request is validated before the end-user is authenticated, so the
    unsupported-parameter error comes back without a detour through login.
    """

    def setUp(self):
        pass

    def assertLoginRedirect(self, response):
        self.assertEqual(response.status_code, 302)
        self.assertEqual(urlparse(response["Location"]).path, settings.LOGIN_URL)

    # oauthlib asks the validator about silent login for prompt=none; deny it, as
    # for an end-user who is not logged in, which would give login_required.
    @mock.patch.object(OAuth2Validator, "validate_silent_login", return_value=False)
    def test_request_parameter_with_prompt_none(self, _validate_silent_login):
        response = self.authorize(request=REQUEST_OBJECT, prompt="none")
        self.assertErrorRedirect(response, "request_not_supported")

    @mock.patch.object(OAuth2Validator, "validate_silent_login", return_value=False)
    def test_request_uri_with_prompt_none(self, _validate_silent_login):
        response = self.authorize(request_uri="https://client.example/req.jwt", prompt="none")
        self.assertErrorRedirect(response, "request_uri_not_supported")

    def test_par_required_client_gets_par_error(self):
        # PAR enforcement keeps precedence and, as before, runs after login.
        self.application.require_pushed_authorization_requests = True
        self.application.save()
        response = self.authorize(request_uri="https://client.example/req.jwt")
        self.assertLoginRedirect(response)

    def test_par_request_uri_is_still_resolved(self):
        # A PAR request_uri is single use, so it is not consumed before login.
        par = self.make_par()
        response = self.client.get(
            reverse("oauth2_provider:authorize"),
            {"client_id": self.application.client_id, "request_uri": par.request_uri},
        )
        self.assertLoginRedirect(response)
        par.refresh_from_db()  # still there: consuming deletes it

    def test_request_alongside_par_request_uri_is_ignored(self):
        par = self.make_par()
        response = self.client.get(
            reverse("oauth2_provider:authorize"),
            {
                "client_id": self.application.client_id,
                "request_uri": par.request_uri,
                "request": REQUEST_OBJECT,
            },
        )
        self.assertLoginRedirect(response)
        par.refresh_from_db()
