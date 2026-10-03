import base64
import json

import pytest
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django.utils.timezone import now, timedelta

from oauth2_provider.core.backends_oauthlib import (
    _AUTHENTICATED_CLIENT_ATTRIBUTE,
    JSONOAuthLibCore,
    OAuthLibCore,
)
from oauth2_provider.models import get_access_token_model, get_application_model, redirect_to_uri_allowed
from oauth2_provider.resource_server.backends import get_oauthlib_core
from tests.common_testing import OAuth2ProviderTestCase as TestCase
from tests.utils import post_form


try:
    from unittest import mock
except ImportError:
    import mock


@pytest.mark.usefixtures("oauth2_settings")
class TestOAuthLibCoreBackend(TestCase):
    factory = RequestFactory()

    @classmethod
    def setUpTestData(cls):
        cls.oauthlib_core = OAuthLibCore()

    def test_swappable_server_class(self):
        self.oauth2_settings.OAUTH2_SERVER_CLASS = mock.MagicMock
        oauthlib_core = OAuthLibCore()
        self.assertTrue(isinstance(oauthlib_core.server, mock.MagicMock))

    def test_form_urlencoded_extract_params(self):
        payload = "grant_type=password&username=john&password=123456"
        request = self.factory.post("/o/token/", payload, content_type="application/x-www-form-urlencoded")

        uri, http_method, body, headers = self.oauthlib_core._extract_params(request)
        self.assertIn("grant_type=password", body)
        self.assertIn("username=john", body)
        self.assertIn("password=123456", body)

    def test_application_json_extract_params(self):
        payload = json.dumps(
            {
                "grant_type": "password",
                "username": "john",
                "password": "123456",
            }
        )
        request = self.factory.post("/o/token/", payload, content_type="application/json")

        uri, http_method, body, headers = self.oauthlib_core._extract_params(request)
        self.assertNotIn("grant_type=password", body)
        self.assertNotIn("username=john", body)
        self.assertNotIn("password=123456", body)


UserModel = get_user_model()
ApplicationModel = get_application_model()
AccessTokenModel = get_access_token_model()


@pytest.mark.usefixtures("oauth2_settings")
class TestOAuthLibCoreBackendErrorHandling(TestCase):
    factory = RequestFactory()

    @classmethod
    def setUpTestData(cls):
        cls.oauthlib_core = OAuthLibCore()
        cls.user = UserModel.objects.create_user("john", "test@example.com", "123456")
        cls.app = ApplicationModel.objects.create(
            name="app",
            client_id="app_id",
            client_secret="app_secret",
            client_type=ApplicationModel.CLIENT_CONFIDENTIAL,
            authorization_grant_type=ApplicationModel.GRANT_PASSWORD,
            user=cls.user,
        )

    def test_create_token_response_valid(self):
        payload = (
            "grant_type=password&username=john&password=123456&client_id=app_id&client_secret=app_secret"
        )
        request = self.factory.post(
            "/o/token/",
            payload,
            content_type="application/x-www-form-urlencoded",
            HTTP_AUTHORIZATION="Basic %s" % base64.b64encode(b"john:123456").decode(),
        )

        uri, headers, body, status = self.oauthlib_core.create_token_response(request)
        self.assertEqual(status, 200)

    def test_create_token_response_query_params(self):
        payload = (
            "grant_type=password&username=john&password=123456&client_id=app_id&client_secret=app_secret"
        )
        request = self.factory.post(
            "/o/token/?test=foo",
            payload,
            content_type="application/x-www-form-urlencoded",
            HTTP_AUTHORIZATION="Basic %s" % base64.b64encode(b"john:123456").decode(),
        )
        uri, headers, body, status = self.oauthlib_core.create_token_response(request)

        self.assertEqual(status, 400)
        self.assertDictEqual(
            json.loads(body),
            {"error": "invalid_request", "error_description": "URL query parameters are not allowed"},
        )

    def test_create_revocation_response_valid(self):
        AccessTokenModel.objects.create(
            user=self.user, token="tokstr", application=self.app, expires=now() + timedelta(days=365)
        )
        payload = "client_id=app_id&client_secret=app_secret&token=tokstr"
        request = self.factory.post(
            "/o/revoke_token/",
            payload,
            content_type="application/x-www-form-urlencoded",
            HTTP_AUTHORIZATION="Basic %s" % base64.b64encode(b"john:123456").decode(),
        )
        uri, headers, body, status = self.oauthlib_core.create_revocation_response(request)
        self.assertEqual(status, 200)

    def test_create_revocation_response_query_params(self):
        token = AccessTokenModel.objects.create(
            user=self.user, token="tokstr", application=self.app, expires=now() + timedelta(days=365)
        )
        payload = "client_id=app_id&client_secret=app_secret&token=tokstr"
        request = self.factory.post(
            "/o/revoke_token/?test=foo",
            payload,
            content_type="application/x-www-form-urlencoded",
            HTTP_AUTHORIZATION="Basic %s" % base64.b64encode(b"john:123456").decode(),
        )
        uri, headers, body, status = self.oauthlib_core.create_revocation_response(request)
        self.assertEqual(status, 400)
        self.assertDictEqual(
            json.loads(body),
            {"error": "invalid_request", "error_description": "URL query parameters are not allowed"},
        )
        token.delete()


class TestCustomOAuthLibCoreBackend(TestCase):
    """
    Tests that the public API behaves as expected when we override
    the OAuthLibCoreBackend core methods.
    """

    class MyOAuthLibCore(OAuthLibCore):
        def _get_extra_credentials(self, request):
            return 1

    factory = RequestFactory()

    def test_create_token_response_gets_extra_credentials(self):
        """
        Make sures that extra_credentials parameter is passed to oauthlib
        """
        payload = "grant_type=password&username=john&password=123456"
        request = self.factory.post("/o/token/", payload, content_type="application/x-www-form-urlencoded")

        with mock.patch("oauthlib.oauth2.Server.create_token_response") as create_token_response:
            mocked = mock.MagicMock()
            create_token_response.return_value = mocked, mocked, mocked
            core = self.MyOAuthLibCore()
            core.create_token_response(request)
            self.assertTrue(create_token_response.call_args[0][4] == 1)


class TestJSONOAuthLibCoreBackend(TestCase):
    factory = RequestFactory()

    def test_application_json_extract_params(self):
        payload = json.dumps(
            {
                "grant_type": "password",
                "username": "john",
                "password": "123456",
            }
        )
        request = self.factory.post("/o/token/", payload, content_type="application/json")
        with pytest.warns(DeprecationWarning):
            oauthlib_core = JSONOAuthLibCore()

        uri, http_method, body, headers = oauthlib_core._extract_params(request)
        self.assertIn("grant_type=password", body)
        self.assertIn("username=john", body)
        self.assertIn("password=123456", body)

    def test_instantiation_emits_deprecation_warning(self):
        # JSONOAuthLibCore is deprecated (removal tracked in #1773): reading JSON
        # request bodies on the OAuth endpoints is non-standard (RFC 6749/7662/7009).
        with pytest.warns(
            DeprecationWarning, match="deprecated and will be removed in django-oauth-toolkit 4.0"
        ):
            JSONOAuthLibCore()


class RecordingServer:
    """A stand-in oauthlib server recording what OAuthLibCore hands it."""

    def __init__(self, response_types=None):
        if response_types is not None:
            self.response_types = response_types
        self.calls = []

    def validate_authorization_request(self, uri, http_method="GET", body=None, headers=None):
        self.calls.append({"uri": uri, "body": body})
        return [], {}

    def create_authorization_response(self, uri, http_method="GET", body=None, headers=None, **kwargs):
        self.calls.append({"uri": uri, **kwargs})
        return {"Location": "http://example.org"}, None, 302


class TestOAuthLibCoreResponseTypeOrdering(TestCase):
    """
    The order of a multi-valued response_type does not matter (RFC 6749 §3.1.1), but
    oauthlib dispatches on the exact string, so OAuthLibCore hands it the registered one.
    """

    factory = RequestFactory()
    registered = {"code": None, "code id_token": None, "id_token token": None}

    def test_validate_authorization_request_sends_the_registered_ordering(self):
        server = RecordingServer(self.registered)
        request = self.factory.get("/o/authorize/?client_id=abc&response_type=id_token+code&state=a%2Bb")

        OAuthLibCore(server).validate_authorization_request(request)

        (call,) = server.calls
        self.assertTrue(call["uri"].endswith("?client_id=abc&response_type=code%20id_token&state=a%2Bb"))

    def test_validate_authorization_request_rewrites_a_pushed_body(self):
        server = RecordingServer(self.registered)
        request = post_form(self.factory, "/o/par/", {"client_id": "abc", "response_type": "token id_token"})

        OAuthLibCore(server).validate_authorization_request(request)

        (call,) = server.calls
        self.assertIn("response_type=id_token%20token", call["body"])
        self.assertIn("client_id=abc", call["body"])

    def test_create_authorization_response_sends_the_registered_ordering(self):
        server = RecordingServer(self.registered)
        request = self.factory.get("/o/authorize/")
        request.user = None
        credentials = {
            "client_id": "abc",
            "redirect_uri": "http://example.org",
            "response_type": "id_token code",
        }

        OAuthLibCore(server).create_authorization_response(request, [], credentials, allow=True)

        (call,) = server.calls
        self.assertEqual(call["credentials"]["response_type"], "code id_token")

    def test_a_server_without_a_registry_gets_the_value_unchanged(self):
        server = RecordingServer()
        request = self.factory.get("/o/authorize/?response_type=id_token+code")
        core = OAuthLibCore(server)

        core.validate_authorization_request(request)
        request.user = None
        credentials = {"redirect_uri": "http://example.org", "response_type": "id_token code"}
        core.create_authorization_response(request, [], credentials, allow=True)

        validate_call, create_call = server.calls
        self.assertTrue(validate_call["uri"].endswith("?response_type=id_token+code"))
        self.assertEqual(create_call["credentials"]["response_type"], "id_token code")


class TestOAuthLibCore(TestCase):
    factory = RequestFactory()

    def test_validate_authorization_request_unsafe_query(self):
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + "a_casual_token",
        }
        request = self.factory.get("/fake-resource?next=/fake", **auth_headers)

        oauthlib_core = get_oauthlib_core()
        oauthlib_core.verify_request(request, scopes=[])

    def test_authenticate_client_request_exposes_the_authenticated_client(self):
        user = UserModel.objects.create_user("client_owner", "owner@example.com")
        application = ApplicationModel.objects.create(
            name="test_client_credentials_app",
            user=user,
            client_type=ApplicationModel.CLIENT_CONFIDENTIAL,
            authorization_grant_type=ApplicationModel.GRANT_CLIENT_CREDENTIALS,
            client_secret="1234567890qwertyuiop",
        )
        credentials = base64.b64encode(f"{application.client_id}:1234567890qwertyuiop".encode()).decode()
        request = post_form(self.factory, "/o/introspect/", HTTP_AUTHORIZATION=f"Basic {credentials}")

        oauthlib_core = get_oauthlib_core()
        valid, oauthlib_request = oauthlib_core.authenticate_client_request(request)
        self.assertTrue(valid)
        self.assertEqual(oauthlib_request.client, application)
        self.assertEqual(getattr(request, _AUTHENTICATED_CLIENT_ATTRIBUTE), application)
        # The boolean wrapper is unchanged, and records the client too.
        request = post_form(self.factory, "/o/introspect/", HTTP_AUTHORIZATION=f"Basic {credentials}")
        self.assertIs(oauthlib_core.authenticate_client(request), True)
        self.assertEqual(getattr(request, _AUTHENTICATED_CLIENT_ATTRIBUTE), application)

        bad = base64.b64encode(f"{application.client_id}:wrong".encode()).decode()
        request = post_form(self.factory, "/o/introspect/", HTTP_AUTHORIZATION=f"Basic {bad}")
        valid, _oauthlib_request = oauthlib_core.authenticate_client_request(request)
        self.assertFalse(valid)
        self.assertIsNone(getattr(request, _AUTHENTICATED_CLIENT_ATTRIBUTE))
        # Body credentials with a wrong secret leave the oauthlib request's client set,
        # so nothing but the recorded None stops it being read as authenticated.
        request = post_form(
            self.factory, "/o/introspect/", {"client_id": application.client_id, "client_secret": "wrong"}
        )
        valid, oauthlib_request = oauthlib_core.authenticate_client_request(request)
        self.assertFalse(valid)
        self.assertEqual(oauthlib_request.client, application)
        self.assertIsNone(getattr(request, _AUTHENTICATED_CLIENT_ATTRIBUTE))
        # A failure overwrites a client recorded earlier on the same request.
        setattr(request, _AUTHENTICATED_CLIENT_ATTRIBUTE, application)
        self.assertIs(oauthlib_core.authenticate_client(request), False)
        self.assertIsNone(getattr(request, _AUTHENTICATED_CLIENT_ATTRIBUTE))


@pytest.mark.parametrize(
    "uri, expected_result",
    # localhost is _not_ a loopback URI
    [
        ("http://localhost:3456", False),
        # only http scheme is supported for loopback URIs
        ("https://127.0.0.1:3456", False),
        ("http://127.0.0.1:3456", True),
        ("http://[::1]", True),
        ("http://[::1]:34", True),
    ],
)
def test_uri_loopback_redirect_check(uri, expected_result):
    allowed_uris = ["http://127.0.0.1", "http://[::1]"]
    if expected_result:
        assert redirect_to_uri_allowed(uri, allowed_uris)
    else:
        assert not redirect_to_uri_allowed(uri, allowed_uris)
