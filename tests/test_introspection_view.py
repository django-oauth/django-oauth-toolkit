import calendar
import datetime
import gc
import weakref
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.db import router
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone
from oauthlib.common import Request as OauthlibRequest

from oauth2_provider.authorization_server.views import introspect
from oauth2_provider.authorization_server.views.introspect import IntrospectTokenView
from oauth2_provider.core.backends_oauthlib import (
    _AUTHENTICATED_CLIENT_ATTRIBUTE,
    JSONOAuthLibCore,
    OAuthLibCore,
)
from oauth2_provider.models import get_access_token_model, get_application_model
from oauth2_provider.oauth2_validators import OAuth2Validator

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header, post_form


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"
DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"


class NonRecordingBackend:
    """A custom backend that authenticates clients itself.

    It runs the validator directly rather than through
    ``OAuthLibCore.authenticate_client_request()``, so it cannot report which client
    authenticated. Bearer tokens are verified by the wrapped core.
    """

    def __init__(self, core):
        self._core = core

    def authenticate_client(self, request):
        uri, http_method, body, headers = self._core._extract_params(request)
        oauthlib_request = OauthlibRequest(uri, http_method, body, headers)
        return self._core.server.request_validator.authenticate_client(oauthlib_request)

    def verify_request(self, request, scopes):
        return self._core.verify_request(request, scopes)


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.INTROSPECTION_SETTINGS)
class TestTokenIntrospectionViews(TestCase):
    """
    Tests for Authorized Token Introspection Views
    """

    @classmethod
    def setUpTestData(cls):
        cls.resource_server_user = UserModel.objects.create_user("resource_server", "test@example.com")
        cls.test_user = UserModel.objects.create_user("bar_user", "dev@example.com")

        cls.application = Application.objects.create(
            name="Test Application",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=cls.test_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
        )

        cls.resource_server_token = AccessToken.objects.create(
            user=cls.resource_server_user,
            token="12345678900",
            application=cls.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="introspection",
        )

        cls.valid_token = AccessToken.objects.create(
            user=cls.test_user,
            token="12345678901",
            application=cls.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write dolphin",
        )

        cls.invalid_token = AccessToken.objects.create(
            user=cls.test_user,
            token="12345678902",
            application=cls.application,
            expires=timezone.now() + datetime.timedelta(days=-1),
            scope="read write dolphin",
        )

        cls.token_without_user = AccessToken.objects.create(
            user=None,
            token="12345678903",
            application=cls.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write dolphin",
        )

        cls.token_without_app = AccessToken.objects.create(
            user=cls.test_user,
            token="12345678904",
            application=None,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write dolphin",
        )

    def test_view_forbidden(self):
        """
        Test that the view is restricted for logged-in users.
        """
        response = self.client.get(reverse("oauth2_provider:introspect"))
        self.assertEqual(response.status_code, 403)

    def test_view_get_valid_token(self):
        """
        Test that when you pass a valid token as URL parameter,
        a json with an active token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.get(
            reverse("oauth2_provider:introspect"), {"token": self.valid_token.token}, **auth_headers
        )

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(
            content,
            {
                "active": True,
                "scope": self.valid_token.scope,
                "client_id": self.valid_token.application.client_id,
                "username": self.valid_token.user.get_username(),
                "exp": int(calendar.timegm(self.valid_token.expires.timetuple())),
            },
        )

    def test_view_get_valid_token_without_user(self):
        """
        Test that when you pass a valid token as URL parameter,
        a json with an active token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.get(
            reverse("oauth2_provider:introspect"), {"token": self.token_without_user.token}, **auth_headers
        )

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(
            content,
            {
                "active": True,
                "scope": self.token_without_user.scope,
                "client_id": self.token_without_user.application.client_id,
                "exp": int(calendar.timegm(self.token_without_user.expires.timetuple())),
            },
        )

    def test_view_get_valid_token_without_app(self):
        """
        Test that when you pass a valid token as URL parameter,
        a json with an active token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.get(
            reverse("oauth2_provider:introspect"), {"token": self.token_without_app.token}, **auth_headers
        )

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(
            content,
            {
                "active": True,
                "scope": self.token_without_app.scope,
                "username": self.token_without_app.user.get_username(),
                "exp": int(calendar.timegm(self.token_without_app.expires.timetuple())),
            },
        )

    def test_view_get_invalid_token(self):
        """
        Test that when you pass an invalid token as URL parameter,
        a json with an inactive token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.get(
            reverse("oauth2_provider:introspect"), {"token": self.invalid_token.token}, **auth_headers
        )

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(
            content,
            {
                "active": False,
            },
        )

    def test_view_get_notexisting_token(self):
        """
        Test that when you pass an non existing token as URL parameter,
        a json with an inactive token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = self.client.get(
            reverse("oauth2_provider:introspect"), {"token": "kaudawelsch"}, **auth_headers
        )

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(
            content,
            {
                "active": False,
            },
        )

    def test_view_post_valid_token(self):
        """
        Test that when you pass a valid token as form parameter,
        a json with an active token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = post_form(
            self.client,
            reverse("oauth2_provider:introspect"),
            {"token": self.valid_token.token},
            **auth_headers,
        )

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(
            content,
            {
                "active": True,
                "scope": self.valid_token.scope,
                "client_id": self.valid_token.application.client_id,
                "username": self.valid_token.user.get_username(),
                "exp": int(calendar.timegm(self.valid_token.expires.timetuple())),
            },
        )

    def test_view_post_invalid_token(self):
        """
        Test that when you pass an invalid token as form parameter,
        a json with an inactive token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = post_form(
            self.client,
            reverse("oauth2_provider:introspect"),
            {"token": self.invalid_token.token},
            **auth_headers,
        )

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(
            content,
            {
                "active": False,
            },
        )

    def test_view_post_notexisting_token(self):
        """
        Test that when you pass an non existing token as form parameter,
        a json with an inactive token state is provided
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = post_form(
            self.client, reverse("oauth2_provider:introspect"), {"token": "kaudawelsch"}, **auth_headers
        )

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(
            content,
            {
                "active": False,
            },
        )

    def test_view_post_no_token(self):
        """
        Test that when you pass no token HTTP 400 is returned
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = post_form(self.client, reverse("oauth2_provider:introspect"), **auth_headers)

        self.assertEqual(response.status_code, 400)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertEqual(content["error"], "invalid_request")

    def test_view_post_valid_client_creds_basic_auth(self):
        """Test HTTP basic auth working"""
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        response = post_form(
            self.client,
            reverse("oauth2_provider:introspect"),
            {"token": self.valid_token.token},
            **auth_headers,
        )
        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(
            content,
            {
                "active": True,
                "scope": self.valid_token.scope,
                "client_id": self.valid_token.application.client_id,
                "username": self.valid_token.user.get_username(),
                "exp": int(calendar.timegm(self.valid_token.expires.timetuple())),
            },
        )

    def test_view_post_invalid_client_creds_basic_auth(self):
        """Must fail for invalid client credentials"""
        auth_headers = get_basic_auth_header(self.application.client_id, f"{CLEARTEXT_SECRET}_so_wrong")
        response = post_form(
            self.client,
            reverse("oauth2_provider:introspect"),
            {"token": self.valid_token.token},
            **auth_headers,
        )
        self.assertEqual(response.status_code, 403)

    def test_view_post_valid_client_creds_plaintext(self):
        """Test introspecting with credentials in request body"""
        response = post_form(
            self.client,
            reverse("oauth2_provider:introspect"),
            {
                "token": self.valid_token.token,
                "client_id": self.application.client_id,
                "client_secret": CLEARTEXT_SECRET,
            },
        )
        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIsInstance(content, dict)
        self.assertDictEqual(
            content,
            {
                "active": True,
                "scope": self.valid_token.scope,
                "client_id": self.valid_token.application.client_id,
                "username": self.valid_token.user.get_username(),
                "exp": int(calendar.timegm(self.valid_token.expires.timetuple())),
            },
        )

    def test_view_post_invalid_client_creds_plaintext(self):
        """Must fail for invalid creds in request body."""
        response = post_form(
            self.client,
            reverse("oauth2_provider:introspect"),
            {
                "token": self.valid_token.token,
                "client_id": self.application.client_id,
                "client_secret": f"{CLEARTEXT_SECRET}_so_wrong",
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_select_related_in_view_for_less_db_queries(self):
        token_database = router.db_for_write(AccessToken)
        with self.assertNumQueries(1, using=token_database):
            post_form(self.client, reverse("oauth2_provider:introspect"))

    def test_introspect_returns_aud_for_token_with_resource(self):
        """
        Test that introspection returns aud field for tokens with resource binding (RFC 8707)
        """

        token_with_resource = AccessToken.objects.create(
            user=self.test_user,
            token="token_with_aud",
            application=self.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write",
            resource=["https://api.example.com", "https://data.example.com"],
        )

        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = post_form(
            self.client,
            reverse("oauth2_provider:introspect"),
            {"token": token_with_resource.token},
            **auth_headers,
        )

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIn("aud", content)
        self.assertEqual(content["aud"], ["https://api.example.com", "https://data.example.com"])

    def test_introspect_omits_aud_for_token_without_resource(self):
        """
        Test that introspection omits aud field for tokens without resource binding
        """
        auth_headers = {
            "HTTP_AUTHORIZATION": "Bearer " + self.resource_server_token.token,
        }
        response = post_form(
            self.client,
            reverse("oauth2_provider:introspect"),
            {"token": self.valid_token.token},
            **auth_headers,
        )

        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertNotIn("aud", content)


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.INTROSPECTION_SETTINGS)
class TestTokenIntrospectionAuthorization(TestCase):
    """
    #1451: only applications with ``can_introspect`` (on unless an operator turns
    it off) may introspect, whether they authenticate as themselves or present an
    access token issued to them. A client authenticating as itself must also be
    confidential (RFC 7662 section 4).
    """

    @pytest.fixture(autouse=True)
    def _reset_backend_warning_memo(self):
        """The backend-capability warning is logged once per class per process; start each test afresh."""
        introspect._warned_backends.clear()
        introspect._warned_backend_names.clear()
        yield
        introspect._warned_backends.clear()
        introspect._warned_backend_names.clear()

    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("bar_user", "dev@example.com")

        cls.introspector = Application.objects.create(
            name="Introspector",
            user=cls.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            client_secret=CLEARTEXT_SECRET,
        )
        cls.not_introspector = Application.objects.create(
            name="Not an introspector",
            user=cls.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            client_secret=CLEARTEXT_SECRET,
            can_introspect=False,
        )

        # A public client that would pass every other check: the device-code
        # shortcut in the validator authenticates it without a secret.
        cls.public_client = Application.objects.create(
            name="Public device client",
            user=cls.user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_DEVICE_CODE,
            client_secret=CLEARTEXT_SECRET,
        )

        expires = timezone.now() + datetime.timedelta(days=1)
        cls.target_token = AccessToken.objects.create(
            user=cls.user, token="target-token", application=cls.introspector, expires=expires, scope="read"
        )
        cls.introspector_token = AccessToken.objects.create(
            user=cls.user,
            token="introspector-token",
            application=cls.introspector,
            expires=expires,
            scope="introspection",
        )
        cls.introspector_token_without_scope = AccessToken.objects.create(
            user=cls.user,
            token="introspector-token-no-scope",
            application=cls.introspector,
            expires=expires,
            scope="read",
        )
        cls.not_introspector_token = AccessToken.objects.create(
            user=cls.user,
            token="not-introspector-token",
            application=cls.not_introspector,
            expires=expires,
            scope="introspection",
        )
        # Issued to a public client that has can_introspect (the model default) and
        # carries the scope: accepted on the bearer path.
        cls.public_client_token = AccessToken.objects.create(
            user=cls.user,
            token="public-client-token",
            application=cls.public_client,
            expires=expires,
            scope="introspection",
        )
        cls.token_without_app = AccessToken.objects.create(
            user=cls.user,
            token="token-without-app",
            application=None,
            expires=expires,
            scope="introspection",
        )

    def _introspect(self, data=None, **headers):
        payload = {"token": self.target_token.token}
        payload.update(data or {})
        return post_form(self.client, reverse("oauth2_provider:introspect"), payload, **headers)

    def _assert_refused(self, response):
        # The same response an unauthenticated caller gets: a bare 403 that
        # discloses nothing about the token.
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.content, b"")

    def test_basic_auth_allowed_with_can_introspect(self):
        response = self._introspect(**get_basic_auth_header(self.introspector.client_id, CLEARTEXT_SECRET))
        self.assertEqual(response.status_code, 200)
        self.assertIs(response.json()["active"], True)

    def test_basic_auth_refused_without_can_introspect(self):
        response = self._introspect(
            **get_basic_auth_header(self.not_introspector.client_id, CLEARTEXT_SECRET)
        )
        self._assert_refused(response)

    def test_body_credentials_refused_without_can_introspect(self):
        response = self._introspect(
            {"client_id": self.not_introspector.client_id, "client_secret": CLEARTEXT_SECRET}
        )
        self._assert_refused(response)

    def test_public_client_refused_with_device_code_grant_type(self):
        # RFC 7662 section 4: the caller must authenticate. A public client has
        # nothing to authenticate with, and the validator's device-code shortcut
        # must not stand in for it here.
        response = self._introspect(
            {"client_id": self.public_client.client_id, "grant_type": DEVICE_CODE_GRANT_TYPE}
        )
        self._assert_refused(response)

    def test_public_client_refused_with_device_code_grant_type_and_basic_auth(self):
        response = self._introspect(
            {"grant_type": DEVICE_CODE_GRANT_TYPE},
            **get_basic_auth_header(self.public_client.client_id, "wrong"),
        )
        self._assert_refused(response)

    def test_public_client_refused_with_its_secret(self):
        response = self._introspect(**get_basic_auth_header(self.public_client.client_id, CLEARTEXT_SECRET))
        self._assert_refused(response)

    def _with_backend(self, core):
        return mock.patch.object(IntrospectTokenView, "get_oauthlib_core", return_value=core)

    def _introspector_basic_auth(self):
        return get_basic_auth_header(self.introspector.client_id, CLEARTEXT_SECRET)

    def _introspector_body_credentials(self):
        return {"client_id": self.introspector.client_id, "client_secret": CLEARTEXT_SECRET}

    def test_backend_refusing_in_authenticate_client_is_honoured(self):
        """A backend's authenticate_client() returning False refuses the client.

        Whatever the backend's authenticate_client_request() does: the view asks the
        backend's own authenticate_client(), so no arrangement of the two methods
        lets the request past a policy the deployer wrote there.
        """

        class Strict(OAuthLibCore):
            def authenticate_client(self, request):
                return False

        class Leaf(Strict):
            def authenticate_client_request(self, request):
                return super().authenticate_client_request(request)

        class DenyMixin:
            def authenticate_client(self, request):
                return False

        class PassthroughMixin:
            def authenticate_client_request(self, request):
                return super().authenticate_client_request(request)

        class Siblings(PassthroughMixin, DenyMixin, OAuthLibCore):
            pass

        class Both(OAuthLibCore):
            def authenticate_client(self, request):
                return False

            def authenticate_client_request(self, request):
                return super().authenticate_client_request(request)

        instance = OAuthLibCore()
        instance.authenticate_client = lambda request: False

        backends = [
            ("Strict", Strict()),
            ("Leaf(Strict) with a passthrough authenticate_client_request", Leaf()),
            ("sibling mixins", Siblings()),
            ("one class overriding both", Both()),
            ("instance-assigned authenticate_client", instance),
        ]
        for label, core in backends:
            with self.subTest(backend=label):
                with self._with_backend(core):
                    # A deliberate refusal by the backend is not a misconfiguration.
                    with self.assertNoLogs(
                        "oauth2_provider.authorization_server.views.introspect", "WARNING"
                    ):
                        response = self._introspect(**self._introspector_basic_auth())
                self._assert_refused(response)

    def test_stricter_backend_calling_super_is_honoured(self):
        """A backend that adds a check on top of OAuthLibCore's is applied as written."""

        class CertificateBackend(OAuthLibCore):
            def authenticate_client(self, request):
                valid = super().authenticate_client(request)
                return valid and request.META.get("HTTP_X_CLIENT_CERT_VERIFIED") == "SUCCESS"

        with self._with_backend(CertificateBackend()):
            allowed = self._introspect(
                **self._introspector_basic_auth(), HTTP_X_CLIENT_CERT_VERIFIED="SUCCESS"
            )
            denied = self._introspect(**self._introspector_basic_auth())

        self.assertEqual(allowed.status_code, 200)
        self.assertIs(allowed.json()["active"], True)
        self._assert_refused(denied)

    def test_passthrough_backends_are_used(self):
        class Passthrough(OAuthLibCore):
            def authenticate_client(self, request):
                return super().authenticate_client(request)

            def authenticate_client_request(self, request):
                return super().authenticate_client_request(request)

        class CallsAuthenticateClientRequest(OAuthLibCore):
            def authenticate_client(self, request):
                valid, _oauthlib_request = self.authenticate_client_request(request)
                return valid

        for core in (Passthrough(), CallsAuthenticateClientRequest()):
            with self.subTest(backend=type(core).__name__):
                with self._with_backend(core):
                    response = self._introspect(**self._introspector_basic_auth())
                self.assertEqual(response.status_code, 200)

    def test_backend_cannot_accept_a_client_that_failed_authentication(self):
        """A backend returning True after OAuthLibCore refused the client authorizes nobody."""

        class Permissive(OAuthLibCore):
            def authenticate_client(self, request):
                super().authenticate_client(request)
                return True

        # Body credentials matter: body authentication runs last and leaves the
        # oauthlib request's client set even when the secret is wrong, so only
        # OAuthLibCore recording None on failure keeps this client unauthorized.
        attempts = {
            "basic": lambda: self._introspect(**get_basic_auth_header(self.introspector.client_id, "wrong")),
            "body": lambda: self._introspect(
                {"client_id": self.introspector.client_id, "client_secret": "wrong"}
            ),
        }
        for label, attempt in attempts.items():
            with self.subTest(label), self._with_backend(Permissive()):
                with self.assertLogs(
                    "oauth2_provider.authorization_server.views.introspect", "WARNING"
                ) as logs:
                    self._assert_refused(attempt())
                self.assertIn("reported success although", logs.output[0])
            introspect._warned_backends.clear()

    def test_refused_client_warning_is_distinct_from_the_unreported_one(self):
        """One backend class can trip both warnings; each is logged once."""

        class Flaky(OAuthLibCore):
            def authenticate_client(self, request):
                result = super().authenticate_client(request)
                if request.POST.get("drop"):
                    delattr(request, _AUTHENTICATED_CLIENT_ATTRIBUTE)
                return True if not result else result

        with self._with_backend(Flaky()):
            with self.assertLogs("oauth2_provider.authorization_server.views.introspect", "WARNING") as logs:
                for _ in range(2):
                    self._introspect({"client_id": self.introspector.client_id, "client_secret": "wrong"})
                for _ in range(2):
                    self._introspect({**self._introspector_body_credentials(), "drop": "1"})

        self.assertEqual(len(logs.records), 2)
        self.assertIn("reported success although", logs.records[0].getMessage())
        self.assertIn("without OAuthLibCore", logs.records[1].getMessage())

    def test_json_backend_is_used(self):
        with self.assertWarns(DeprecationWarning):
            core = JSONOAuthLibCore()

        with self._with_backend(core):
            response = self._introspect(**self._introspector_basic_auth())

        self.assertEqual(response.status_code, 200)

    def test_client_authentication_runs_the_validator_once(self):
        # One authentication per request, so an RFC 7523 assertion's jti is consumed
        # once (test_client_assertions covers the assertion end to end).
        with mock.patch.object(
            OAuth2Validator,
            "authenticate_client",
            autospec=True,
            side_effect=OAuth2Validator.authenticate_client,
        ) as spy:
            response = self._introspect(**self._introspector_basic_auth())

        self.assertEqual(response.status_code, 200)
        self.assertEqual(spy.call_count, 1)

    def test_backend_that_does_not_record_the_client_fails_closed(self):
        """A backend that authenticates without authenticate_client_request() is refused, not a 500."""
        with self._with_backend(NonRecordingBackend(IntrospectTokenView.get_oauthlib_core())):
            with self.assertLogs("oauth2_provider.authorization_server.views.introspect", "WARNING") as logs:
                refused = self._introspect(**self._introspector_basic_auth())
            bearer = self._introspect(HTTP_AUTHORIZATION="Bearer " + self.introspector_token.token)

        self._assert_refused(refused)
        self.assertIn("NonRecordingBackend", logs.output[0])
        # The bearer-token path does not depend on the backend reporting a client.
        self.assertEqual(bearer.status_code, 200)

    def test_getattr_proxy_backend(self):
        """A proxy forwarding to OAuthLibCore works; one authenticating on its own is refused."""
        real_core = IntrospectTokenView.get_oauthlib_core()

        class Proxy:
            def __init__(self, core):
                self._core = core

            def __getattr__(self, name):
                return getattr(self._core, name)

        class AuthenticatingProxy(Proxy):
            def authenticate_client(self, request):
                return NonRecordingBackend(self._core).authenticate_client(request)

        with self._with_backend(Proxy(real_core)):
            forwarded = self._introspect(**self._introspector_basic_auth())
        with self._with_backend(AuthenticatingProxy(real_core)):
            with self.assertLogs("oauth2_provider.authorization_server.views.introspect", "WARNING") as logs:
                refused = self._introspect(**self._introspector_basic_auth())

        self.assertEqual(forwarded.status_code, 200)
        self._assert_refused(refused)
        self.assertIn("AuthenticatingProxy", logs.output[0])

    def test_backend_warning_is_logged_once_per_backend_class(self):
        with self._with_backend(NonRecordingBackend(IntrospectTokenView.get_oauthlib_core())):
            with self.assertLogs("oauth2_provider.authorization_server.views.introspect", "WARNING") as logs:
                first = self._introspect(**self._introspector_basic_auth())
                second = self._introspect(**self._introspector_basic_auth())

        # The refusal is unchanged; only the log is deduplicated.
        self._assert_refused(first)
        self._assert_refused(second)
        self.assertEqual(len(logs.records), 1)

    def test_backend_warning_is_logged_for_each_class_sharing_a_name(self):
        """Two classes from one factory are distinct backends, each warned about once."""

        def make_backend():
            class FactoryBackend(NonRecordingBackend):
                pass

            return FactoryBackend(IntrospectTokenView.get_oauthlib_core())

        with self.assertLogs("oauth2_provider.authorization_server.views.introspect", "WARNING") as logs:
            for core in (make_backend(), make_backend()):
                with self._with_backend(core):
                    self._assert_refused(self._introspect(**self._introspector_basic_auth()))
                    self._assert_refused(self._introspect(**self._introspector_basic_auth()))

        self.assertEqual(len(logs.records), 2)

    def test_backend_warning_memo_does_not_keep_classes_alive(self):
        class EphemeralBackend(NonRecordingBackend):
            pass

        introspect._warn_backend_once(EphemeralBackend, introspect._NOT_REPORTED_MESSAGE)
        self.assertIn(EphemeralBackend, introspect._warned_backends)
        reference = weakref.ref(EphemeralBackend)
        del EphemeralBackend
        gc.collect()

        self.assertIsNone(reference())
        self.assertEqual(len(introspect._warned_backends), 0)

    def test_backend_warning_memo_falls_back_to_the_qualified_name(self):
        """A class that cannot be weakly referenced is remembered by its qualified name."""

        class NoWeakReferences:
            def setdefault(self, key, default=None):
                raise TypeError("cannot create weak reference")

        name = f"{NonRecordingBackend.__module__}.NonRecordingBackend"
        messages = (introspect._NOT_REPORTED_MESSAGE, introspect._REFUSED_MESSAGE)
        with mock.patch.object(introspect, "_warned_backends", NoWeakReferences()):
            with self.assertLogs("oauth2_provider.authorization_server.views.introspect", "WARNING") as logs:
                for message in messages:
                    introspect._warn_backend_once(NonRecordingBackend, message)
                    introspect._warn_backend_once(NonRecordingBackend, message)

        # Once per message, not once per class: the fallback keys on both.
        self.assertEqual(len(logs.records), 2)
        self.assertEqual(introspect._warned_backend_names, {(name, message) for message in messages})

    def test_a_client_left_on_the_request_is_not_read(self):
        """Only a client the backend records during this request is authorized."""
        request = post_form(
            RequestFactory(),
            reverse("oauth2_provider:introspect"),
            {"token": self.target_token.token},
            **self._introspector_basic_auth(),
        )
        # Left by earlier code (middleware, a previous call): an authorized client.
        setattr(request, _AUTHENTICATED_CLIENT_ATTRIBUTE, self.introspector)

        with self._with_backend(NonRecordingBackend(IntrospectTokenView.get_oauthlib_core())):
            with self.assertLogs("oauth2_provider.authorization_server.views.introspect", "WARNING"):
                response = IntrospectTokenView.as_view()(request)

        self._assert_refused(response)

    def test_client_authentication_without_a_client_is_refused(self):
        # A validator that reports success without setting request.client must
        # not crash the view (500) or authorize anyone.
        with mock.patch.object(OAuth2Validator, "authenticate_client", return_value=True):
            response = self._introspect(
                **get_basic_auth_header(self.introspector.client_id, CLEARTEXT_SECRET)
            )
        self._assert_refused(response)

    def _custom_bearer_validator(self, client):
        """A validate_bearer_token() that sets request.client but not request.access_token."""

        def validate_bearer_token(token, scopes, request):
            request.client = client
            request.user = self.user
            request.scopes = scopes
            return True

        return mock.patch.object(OAuth2Validator, "validate_bearer_token", side_effect=validate_bearer_token)

    def test_bearer_falls_back_to_request_client(self):
        with self._custom_bearer_validator(self.introspector):
            response = self._introspect(HTTP_AUTHORIZATION="Bearer opaque")
        self.assertEqual(response.status_code, 200)

        with self._custom_bearer_validator(self.not_introspector):
            response = self._introspect(HTTP_AUTHORIZATION="Bearer opaque")
        self._assert_refused(response)

    def test_bearer_prefers_the_access_tokens_application_over_request_client(self):
        """The token's own application decides, not whatever request.client holds."""

        def validator_setting(token_app, client):
            def validate_bearer_token(token, scopes, request):
                request.access_token = mock.Mock(application=token_app)
                request.client = client
                request.user = self.user
                request.scopes = scopes
                return True

            return mock.patch.object(
                OAuth2Validator, "validate_bearer_token", side_effect=validate_bearer_token
            )

        with validator_setting(self.introspector, self.not_introspector):
            self.assertEqual(self._introspect(HTTP_AUTHORIZATION="Bearer opaque").status_code, 200)
        with validator_setting(self.not_introspector, self.introspector):
            self._assert_refused(self._introspect(HTTP_AUTHORIZATION="Bearer opaque"))

    def test_bearer_ignores_an_access_token_request_parameter(self):
        # oauthlib exposes an ``access_token`` request parameter under the same
        # name as the attribute the default validator sets; a string there must
        # not be mistaken for the token, nor crash the view.
        with self._custom_bearer_validator(self.not_introspector):
            response = self._introspect({"access_token": "opaque"}, HTTP_AUTHORIZATION="Bearer opaque")
        self._assert_refused(response)

    def test_bearer_ignores_an_access_token_request_parameter_for_an_authorized_client(self):
        # The same parameter must not hide request.client either: an authorized
        # client is still found through the fallback and answered.
        with self._custom_bearer_validator(self.introspector):
            response = self._introspect({"access_token": "opaque"}, HTTP_AUTHORIZATION="Bearer opaque")
        self.assertEqual(response.status_code, 200)
        self.assertIs(response.json()["active"], True)

    def _bearer_validator_setting_no_client(self, access_token=None):
        """A validate_bearer_token() that sets neither a model access token nor request.client."""

        def validate_bearer_token(token, scopes, request):
            if access_token is not None:
                request.access_token = access_token
            request.user = self.user
            request.scopes = scopes
            return True

        return mock.patch.object(OAuth2Validator, "validate_bearer_token", side_effect=validate_bearer_token)

    def test_bearer_ignores_a_client_body_parameter(self):
        # oauthlib also exposes a ``client`` request parameter as request.client.
        # When the validator leaves request.client unset, that string must be
        # refused rather than crash the view with a 500.
        with self._bearer_validator_setting_no_client():
            response = self._introspect({"client": "evil"}, HTTP_AUTHORIZATION="Bearer opaque")
        self._assert_refused(response)

    def test_bearer_ignores_a_client_query_parameter(self):
        url = reverse("oauth2_provider:introspect")
        with self._bearer_validator_setting_no_client():
            response = post_form(
                self.client,
                f"{url}?client=evil",
                {"token": self.target_token.token},
                HTTP_AUTHORIZATION="Bearer opaque",
            )
        self._assert_refused(response)

    def test_client_authentication_ignores_a_client_request_parameter(self):
        # The same parameter on the client-authentication path, with a validator
        # that reports success without setting request.client.
        with mock.patch.object(OAuth2Validator, "authenticate_client", return_value=True):
            response = self._introspect(
                {"client": "evil"}, **get_basic_auth_header(self.introspector.client_id, CLEARTEXT_SECRET)
            )
        self._assert_refused(response)

    def test_bearer_refused_for_a_validator_that_reports_no_client(self):
        # A JWT-style validator that stores the token's claims rather than a model
        # access token, and sets no request.client, gives no client to check.
        claims = {"sub": "someone", "client_id": self.introspector.client_id, "scope": "introspection"}
        with self._bearer_validator_setting_no_client(access_token=claims):
            response = self._introspect(HTTP_AUTHORIZATION="Bearer opaque")
        self._assert_refused(response)

    def test_bearer_allowed_with_can_introspect_and_scope(self):
        response = self._introspect(HTTP_AUTHORIZATION="Bearer " + self.introspector_token.token)
        self.assertEqual(response.status_code, 200)
        self.assertIs(response.json()["active"], True)

    def test_bearer_refused_without_can_introspect(self):
        response = self._introspect(HTTP_AUTHORIZATION="Bearer " + self.not_introspector_token.token)
        self._assert_refused(response)

    def test_bearer_allowed_for_public_client_with_can_introspect_and_scope(self):
        # Only the client-authentication path requires a confidential client: a
        # token with the introspection scope issued to a public client that has
        # can_introspect is accepted, as before #1451.
        self.assertIs(self.public_client.can_introspect, True)
        response = self._introspect(HTTP_AUTHORIZATION="Bearer " + self.public_client_token.token)
        self.assertEqual(response.status_code, 200)
        self.assertIs(response.json()["active"], True)

        with self._custom_bearer_validator(self.public_client):
            response = self._introspect(HTTP_AUTHORIZATION="Bearer opaque")
        self.assertEqual(response.status_code, 200)

    def test_bearer_refused_for_public_client_without_can_introspect(self):
        Application.objects.filter(pk=self.public_client.pk).update(can_introspect=False)
        response = self._introspect(HTTP_AUTHORIZATION="Bearer " + self.public_client_token.token)
        self._assert_refused(response)

    def test_bearer_refused_without_scope(self):
        response = self._introspect(
            HTTP_AUTHORIZATION="Bearer " + self.introspector_token_without_scope.token
        )
        self._assert_refused(response)

    def test_bearer_refused_for_token_without_application(self):
        response = self._introspect(HTTP_AUTHORIZATION="Bearer " + self.token_without_app.token)
        self._assert_refused(response)

    def test_each_path_is_authorized_on_its_own(self):
        # Body credentials of a client without can_introspect do not taint an
        # authorized bearer token sent alongside them: the bearer path decides.
        response = self._introspect(
            {"client_id": self.not_introspector.client_id, "client_secret": CLEARTEXT_SECRET},
            HTTP_AUTHORIZATION="Bearer " + self.introspector_token.token,
        )
        self.assertEqual(response.status_code, 200)

    def test_revoking_the_capability_takes_effect_immediately(self):
        Application.objects.filter(pk=self.introspector.pk).update(can_introspect=False)
        response = self._introspect(**get_basic_auth_header(self.introspector.client_id, CLEARTEXT_SECRET))
        self._assert_refused(response)
        response = self._introspect(HTTP_AUTHORIZATION="Bearer " + self.introspector_token.token)
        self._assert_refused(response)

    def test_refused_bearer_reports_insufficient_scope(self):
        # Views that mix in ProtectedResourceMetadataMixin turn this into an
        # RFC 6750 insufficient_scope challenge.
        request = post_form(
            RequestFactory(),
            reverse("oauth2_provider:introspect"),
            {"token": self.target_token.token},
            HTTP_AUTHORIZATION="Bearer " + self.not_introspector_token.token,
        )
        valid, oauthlib_request = IntrospectTokenView().verify_request(request)
        self.assertFalse(valid)
        self.assertEqual(oauthlib_request.oauth2_error["error"], "insufficient_scope")
        self.assertEqual(
            oauthlib_request.oauth2_error["error_description"],
            "The access token is not authorized for token introspection.",
        )
