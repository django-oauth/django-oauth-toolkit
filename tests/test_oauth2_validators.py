import contextlib
import datetime
import json

import pytest
import requests
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from jwcrypto import jwt
from oauthlib.common import Request
from oauthlib.oauth2.rfc6749 import errors as rfc6749_errors

from oauth2_provider.exceptions import FatalClientError
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_grant_model,
    get_refresh_token_model,
)
from oauth2_provider.oauth2_backends import get_oauthlib_core
from oauth2_provider.oauth2_validators import OAuth2Validator

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .common_testing import OAuth2ProviderTransactionTestCase as TransactionTestCase
from .utils import get_basic_auth_header


try:
    from unittest import mock
except ImportError:
    import mock


UserModel = get_user_model()
Application = get_application_model()
AccessToken = get_access_token_model()
Grant = get_grant_model()
RefreshToken = get_refresh_token_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"
CLEARTEXT_BLANK_SECRET = ""


@contextlib.contextmanager
def always_invalid_token():
    # NOTE: This can happen if someone swaps the AccessToken model and
    # updates `is_valid` such that it has some criteria on top of
    # `is_expired` and `allow_scopes`.
    original_is_valid = AccessToken.is_valid
    AccessToken.is_valid = mock.MagicMock(return_value=False)
    try:
        yield
    finally:
        AccessToken.is_valid = original_is_valid


class TestOAuth2Validator(TransactionTestCase):
    def setUp(self):
        self.user = UserModel.objects.create_user("user", "test@example.com", "123456")
        self.request = mock.MagicMock(wraps=Request)
        self.request.user = self.user
        self.request.grant_type = "not client"
        self.validator = OAuth2Validator()
        self.application = Application.objects.create(
            client_id="client_id",
            client_secret=CLEARTEXT_SECRET,
            user=self.user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_PASSWORD,
        )
        self.request.client = self.application

        self.blank_secret_request = mock.MagicMock(wraps=Request)
        self.blank_secret_request.user = self.user
        self.blank_secret_request.grant_type = "not client"
        self.blank_secret_application = Application.objects.create(
            client_id="blank_secret_client_id",
            client_secret=CLEARTEXT_BLANK_SECRET,
            user=self.user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_PASSWORD,
        )
        self.blank_secret_request.client = self.blank_secret_application

    def tearDown(self):
        self.application.delete()

    def test_authenticate_request_body(self):
        self.request.client_id = "client_id"
        self.assertFalse(self.validator._authenticate_request_body(self.request))

        self.request.client_secret = ""
        self.assertFalse(self.validator._authenticate_request_body(self.request))

        self.request.client_secret = "wrong_client_secret"
        self.assertFalse(self.validator._authenticate_request_body(self.request))

        self.request.client_secret = CLEARTEXT_SECRET
        self.assertTrue(self.validator._authenticate_request_body(self.request))

        self.blank_secret_request.client_id = "blank_secret_client_id"
        self.assertTrue(self.validator._authenticate_request_body(self.blank_secret_request))

        self.blank_secret_request.client_secret = CLEARTEXT_BLANK_SECRET
        self.assertTrue(self.validator._authenticate_request_body(self.blank_secret_request))

        self.blank_secret_request.client_secret = "wrong_client_secret"
        self.assertFalse(self.validator._authenticate_request_body(self.blank_secret_request))

    def test_authenticate_request_body_unhashed_secret(self):
        self.application.client_secret = CLEARTEXT_SECRET
        self.application.hash_client_secret = False
        self.application.save()

        self.request.client_id = "client_id"
        self.request.client_secret = CLEARTEXT_SECRET
        self.assertTrue(self.validator._authenticate_request_body(self.request))

        self.application.hash_client_secret = True
        self.application.save()

    def test_extract_basic_auth(self):
        self.request.headers = {"HTTP_AUTHORIZATION": "Basic 123456"}
        self.assertEqual(self.validator._extract_basic_auth(self.request), "123456")
        self.request.headers = {}
        self.assertIsNone(self.validator._extract_basic_auth(self.request))
        self.request.headers = {"HTTP_AUTHORIZATION": "Dummy 123456"}
        self.assertIsNone(self.validator._extract_basic_auth(self.request))
        self.request.headers = {"HTTP_AUTHORIZATION": "Basic"}
        self.assertIsNone(self.validator._extract_basic_auth(self.request))
        self.request.headers = {"HTTP_AUTHORIZATION": "Basic 123456 789"}
        self.assertEqual(self.validator._extract_basic_auth(self.request), "123456 789")

    def test_authenticate_basic_auth_hashed_secret(self):
        self.request.encoding = "utf-8"
        self.request.headers = get_basic_auth_header("client_id", CLEARTEXT_SECRET)
        self.assertTrue(self.validator._authenticate_basic_auth(self.request))

    def test_authenticate_basic_auth_unhashed_secret(self):
        self.application.client_secret = CLEARTEXT_SECRET
        self.application.hash_client_secret = False
        self.application.save()

        self.request.encoding = "utf-8"
        self.request.headers = get_basic_auth_header("client_id", CLEARTEXT_SECRET)
        self.assertTrue(self.validator._authenticate_basic_auth(self.request))

    def test_authenticate_basic_auth_default_encoding(self):
        self.request.encoding = None
        self.request.headers = get_basic_auth_header("client_id", CLEARTEXT_SECRET)
        self.assertTrue(self.validator._authenticate_basic_auth(self.request))

    def test_authenticate_basic_auth_wrong_client_id(self):
        self.request.encoding = "utf-8"
        self.request.headers = get_basic_auth_header("wrong_id", CLEARTEXT_SECRET)
        self.assertFalse(self.validator._authenticate_basic_auth(self.request))

    def test_authenticate_basic_auth_wrong_client_secret(self):
        self.request.encoding = "utf-8"
        self.request.headers = get_basic_auth_header("client_id", "wrong_secret")
        self.assertFalse(self.validator._authenticate_basic_auth(self.request))

    def test_authenticate_basic_auth_wrong_client_secret_not_logged(self):
        """The client secret must never be written to the logs (basic auth)."""
        self.request.encoding = "utf-8"
        self.request.headers = get_basic_auth_header("client_id", "super_secret_value")
        with self.assertLogs("oauth2_provider", level="DEBUG") as logs:
            self.assertFalse(self.validator._authenticate_basic_auth(self.request))
        self.assertFalse(any("super_secret_value" in message for message in logs.output))

    def test_authenticate_request_body_wrong_client_secret_not_logged(self):
        """The client secret must never be written to the logs (body auth)."""
        self.request.client_id = "client_id"
        self.request.client_secret = "super_secret_value"
        with self.assertLogs("oauth2_provider", level="DEBUG") as logs:
            self.assertFalse(self.validator._authenticate_request_body(self.request))
        self.assertFalse(any("super_secret_value" in message for message in logs.output))

    def test_authenticate_basic_auth_undecodable_credentials_not_logged(self):
        """The raw credential string must not be logged when base64/unicode decoding fails."""
        self.request.encoding = "utf-8"

        # Not valid base64 -> hits the base64 decode failure branch.
        self.request.headers = {"HTTP_AUTHORIZATION": "Basic not_base64"}
        with self.assertLogs("oauth2_provider", level="DEBUG") as logs:
            self.assertFalse(self.validator._authenticate_basic_auth(self.request))
        output = "\n".join(logs.output)
        # Assert the base64-decode-failure branch actually ran (not some later path) ...
        self.assertIn("can't be decoded as base64", output)
        # ... and that it did not log the raw credential string.
        self.assertNotIn("not_base64", output)

        # Valid base64 but not valid utf-8 -> hits the unicode decode failure branch.
        self.request.headers = {"HTTP_AUTHORIZATION": "Basic SECRETNEEDLE"}
        with self.assertLogs("oauth2_provider", level="DEBUG") as logs:
            self.assertFalse(self.validator._authenticate_basic_auth(self.request))
        output = "\n".join(logs.output)
        # Assert the unicode-decode-failure branch actually ran ...
        self.assertIn("can't be decoded as unicode", output)
        # ... and that it did not log the raw credential string.
        self.assertNotIn("SECRETNEEDLE", output)

    def test_authenticate_basic_auth_not_b64_auth_string(self):
        self.request.encoding = "utf-8"
        # Can"t b64decode
        self.request.headers = {"HTTP_AUTHORIZATION": "Basic not_base64"}
        self.assertFalse(self.validator._authenticate_basic_auth(self.request))

    def test_authenticate_basic_auth_invalid_b64_string(self):
        self.request.encoding = "utf-8"
        self.request.headers = {"HTTP_AUTHORIZATION": "Basic ZHVtbXk=:ZHVtbXk=\n"}
        self.assertFalse(self.validator._authenticate_basic_auth(self.request))

    def test_authenticate_basic_auth_not_utf8(self):
        self.request.encoding = "utf-8"
        # b64decode("test") will become b"\xb5\xeb-", it can"t be decoded as utf-8
        self.request.headers = {"HTTP_AUTHORIZATION": "Basic test"}
        self.assertFalse(self.validator._authenticate_basic_auth(self.request))

    def test_authenticate_basic_auth_public_app_with_device_code(self):
        self.request.grant_type = "urn:ietf:params:oauth:grant-type:device_code"
        self.request.headers = get_basic_auth_header("client_id", CLEARTEXT_SECRET)
        self.application.client_type = Application.CLIENT_PUBLIC
        self.assertTrue(self.validator._authenticate_basic_auth(self.request))

    def test_authenticate_check_secret(self):
        hashed = make_password(CLEARTEXT_SECRET)
        self.assertTrue(self.validator._check_secret(CLEARTEXT_SECRET, CLEARTEXT_SECRET))
        self.assertTrue(self.validator._check_secret(CLEARTEXT_SECRET, hashed))
        self.assertFalse(self.validator._check_secret(hashed, hashed))
        self.assertFalse(self.validator._check_secret(hashed, CLEARTEXT_SECRET))

    def test_authenticate_client_id(self):
        self.assertTrue(self.validator.authenticate_client_id("client_id", self.request))

    def test_authenticate_client_id_fail(self):
        self.application.client_type = Application.CLIENT_CONFIDENTIAL
        self.application.save()
        self.assertFalse(self.validator.authenticate_client_id("client_id", self.request))
        self.assertFalse(self.validator.authenticate_client_id("fake_client_id", self.request))

    def test_client_authentication_required(self):
        self.request.headers = {"HTTP_AUTHORIZATION": "Basic 123456"}
        self.assertTrue(self.validator.client_authentication_required(self.request))
        self.request.headers = {}
        self.request.client_id = "client_id"
        self.request.client_secret = CLEARTEXT_SECRET
        self.assertTrue(self.validator.client_authentication_required(self.request))
        self.request.client_secret = ""
        self.assertFalse(self.validator.client_authentication_required(self.request))
        self.application.client_type = Application.CLIENT_CONFIDENTIAL
        self.application.save()
        self.request.client = ""
        self.assertTrue(self.validator.client_authentication_required(self.request))

    def test_load_application_loads_client_id_when_request_has_no_client(self):
        self.request.client = None
        application = self.validator._load_application("client_id", self.request)
        self.assertEqual(application, self.application)

    def test_load_application_uses_cached_when_request_has_valid_client_matching_client_id(self):
        self.request.client = self.application
        application = self.validator._load_application("client_id", self.request)
        self.assertIs(application, self.application)
        self.assertIs(self.request.client, self.application)

    def test_load_application_succeeds_when_request_has_invalid_client_valid_client_id(self):
        self.request.client = "invalid_client"
        application = self.validator._load_application("client_id", self.request)
        self.assertEqual(application, self.application)
        self.assertEqual(self.request.client, self.application)

    def test_load_application_overwrites_client_on_client_id_mismatch(self):
        another_application = Application.objects.create(
            client_id="another_client_id",
            client_secret=CLEARTEXT_SECRET,
            user=self.user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_PASSWORD,
        )
        self.request.client = another_application
        application = self.validator._load_application("client_id", self.request)
        self.assertEqual(application, self.application)
        self.assertEqual(self.request.client, self.application)
        another_application.delete()

    @mock.patch.object(Application, "is_usable")
    def test_load_application_returns_none_when_client_not_usable_cached(self, mock_is_usable):
        mock_is_usable.return_value = False
        self.request.client = self.application
        application = self.validator._load_application("client_id", self.request)
        self.assertIsNone(application)
        self.assertIsNone(self.request.client)

    @mock.patch.object(Application, "is_usable")
    def test_load_application_returns_none_when_client_not_usable_db_lookup(self, mock_is_usable):
        mock_is_usable.return_value = False
        self.request.client = None
        application = self.validator._load_application("client_id", self.request)
        self.assertIsNone(application)
        self.assertIsNone(self.request.client)

    def test_rotate_refresh_token__is_true(self):
        self.assertTrue(self.validator.rotate_refresh_token(mock.MagicMock()))

    def test_validate_refresh_token_with_long_token(self):
        long_token = "x" * 500
        access_token = AccessToken.objects.create(
            user=self.user,
            token="12345678901",
            application=self.application,
            expires=timezone.now() + datetime.timedelta(days=1),
        )
        RefreshToken.objects.create(
            user=self.user,
            token=long_token,
            application=self.application,
            access_token=access_token,
        )
        request = mock.MagicMock(wraps=Request)

        self.assertTrue(self.validator.validate_refresh_token(long_token, self.application, request))
        self.assertEqual(request.user, self.user)
        self.assertEqual(request.refresh_token, long_token)

    def test_validate_refresh_token_with_unknown_token(self):
        request = mock.MagicMock(wraps=Request)
        self.assertFalse(self.validator.validate_refresh_token("unknown", self.application, request))

    def test_revoke_token_with_long_refresh_token(self):
        long_token = "x" * 500
        refresh_token = RefreshToken.objects.create(
            user=self.user,
            token=long_token,
            application=self.application,
        )

        self.validator.revoke_token(long_token, "refresh_token", mock.MagicMock(wraps=Request))

        refresh_token.refresh_from_db()
        self.assertIsNotNone(refresh_token.revoked)

    def test_validate_refresh_token_prefers_unrevoked_row_over_revoked_duplicate(self):
        # (token_checksum, revoked) uniqueness allows the same token value to exist
        # as both a revoked row and an active row; validation must pick the active one.
        token = "duplicate-refresh-token"
        RefreshToken.objects.create(
            user=self.user,
            token=token,
            application=self.application,
            revoked=timezone.now() - datetime.timedelta(days=1),
        )
        RefreshToken.objects.create(
            user=self.user,
            token=token,
            application=self.application,
        )
        request = mock.MagicMock(wraps=Request)

        self.assertTrue(self.validator.validate_refresh_token(token, self.application, request))
        self.assertIsNone(request.refresh_token_instance.revoked)

    def test_revoke_token_with_duplicate_refresh_token_checksums(self):
        token = "duplicate-refresh-token"
        RefreshToken.objects.create(
            user=self.user,
            token=token,
            application=self.application,
            revoked=timezone.now() - datetime.timedelta(days=1),
        )
        active_token = RefreshToken.objects.create(
            user=self.user,
            token=token,
            application=self.application,
        )

        self.validator.revoke_token(token, "refresh_token", mock.MagicMock(wraps=Request))

        active_token.refresh_from_db()
        self.assertIsNotNone(active_token.revoked)

    def test_save_bearer_token__without_user__raises_fatal_client(self):
        token = {}

        with self.assertRaises(FatalClientError):
            self.validator.save_bearer_token(token, mock.MagicMock())

    def test_save_bearer_token__with_existing_tokens__does_not_create_new_tokens(self):
        rotate_token_function = mock.MagicMock()
        rotate_token_function.return_value = False
        self.validator.rotate_refresh_token = rotate_token_function

        access_token = AccessToken.objects.create(
            token="123",
            user=self.user,
            expires=timezone.now() + datetime.timedelta(seconds=60),
            application=self.application,
        )
        refresh_token = RefreshToken.objects.create(
            access_token=access_token, token="abc", user=self.user, application=self.application
        )
        self.request.refresh_token_instance = refresh_token
        token = {
            "scope": "foo bar",
            "refresh_token": "abc",
            "access_token": "123",
        }

        self.assertEqual(1, RefreshToken.objects.count())
        self.assertEqual(1, AccessToken.objects.count())

        self.validator.save_bearer_token(token, self.request)

        self.assertEqual(1, RefreshToken.objects.count())
        self.assertEqual(1, AccessToken.objects.count())

    def test_save_bearer_token__checks_to_rotate_tokens(self):
        rotate_token_function = mock.MagicMock()
        rotate_token_function.return_value = False
        self.validator.rotate_refresh_token = rotate_token_function

        access_token = AccessToken.objects.create(
            token="123",
            user=self.user,
            expires=timezone.now() + datetime.timedelta(seconds=60),
            application=self.application,
        )
        refresh_token = RefreshToken.objects.create(
            access_token=access_token, token="abc", user=self.user, application=self.application
        )
        self.request.refresh_token_instance = refresh_token
        token = {
            "scope": "foo bar",
            "refresh_token": "abc",
            "access_token": "123",
        }

        self.validator.save_bearer_token(token, self.request)
        rotate_token_function.assert_called_once_with(self.request)

    def test_save_bearer_token__with_new_token__creates_new_tokens(self):
        token = {
            "scope": "foo bar",
            "refresh_token": "abc",
            "access_token": "123",
        }

        self.assertEqual(0, RefreshToken.objects.count())
        self.assertEqual(0, AccessToken.objects.count())

        self.validator.save_bearer_token(token, self.request)

        self.assertEqual(1, RefreshToken.objects.count())
        self.assertEqual(1, AccessToken.objects.count())

    def test_save_bearer_token__with_new_token_equal_to_existing_token__revokes_old_tokens(self):
        access_token = AccessToken.objects.create(
            token="123",
            user=self.user,
            expires=timezone.now() + datetime.timedelta(seconds=60),
            application=self.application,
        )
        refresh_token = RefreshToken.objects.create(
            access_token=access_token, token="abc", user=self.user, application=self.application
        )

        self.request.refresh_token_instance = refresh_token

        token = {
            "scope": "foo bar",
            "refresh_token": "abc",
            "access_token": "123",
        }

        self.assertEqual(1, RefreshToken.objects.count())
        self.assertEqual(1, AccessToken.objects.count())

        self.validator.save_bearer_token(token, self.request)

        self.assertEqual(1, RefreshToken.objects.filter(revoked__isnull=True).count())
        self.assertEqual(1, AccessToken.objects.count())

    def test_save_bearer_token__with_no_refresh_token__creates_new_access_token_only(self):
        token = {
            "scope": "foo bar",
            "access_token": "123",
        }

        self.validator.save_bearer_token(token, self.request)

        self.assertEqual(0, RefreshToken.objects.count())
        self.assertEqual(1, AccessToken.objects.count())

    def test_save_bearer_token__with_new_token__calls_methods_to_create_access_and_refresh_tokens(self):
        token = {
            "scope": "foo bar",
            "refresh_token": "abc",
            "access_token": "123",
        }
        # Mock private methods to create access and refresh tokens
        create_access_token_mock = mock.MagicMock()
        create_refresh_token_mock = mock.MagicMock()
        self.validator._create_refresh_token = create_refresh_token_mock
        self.validator._create_access_token = create_access_token_mock

        self.validator.save_bearer_token(token, self.request)

        assert create_access_token_mock.call_count == 1
        assert create_refresh_token_mock.call_count == 1

    def test_get_or_create_user_from_content(self):
        content = {"username": "test_user"}
        UserModel.objects.filter(username=content["username"]).delete()
        user = self.validator.get_or_create_user_from_content(content)

        self.assertIsNotNone(user)
        self.assertEqual(content["username"], user.username)


class TestOAuth2ValidatorProvidesErrorData(TransactionTestCase):
    """These test cases check that the recommended error codes are returned
    when token authentication fails.

    RFC-6750: https://rfc-editor.org/rfc/rfc6750.html

    > If the protected resource request does not include authentication
    > credentials or does not contain an access token that enables access
    > to the protected resource, the resource server MUST include the HTTP
    > "WWW-Authenticate" response header field[.]
    >
    > ...
    >
    > If the request lacks any authentication information..., the
    > resource server SHOULD NOT include an error code or other error
    > information.
    >
    > ...
    >
    > If the protected resource request included an access token and failed
    > authentication, the resource server SHOULD include the "error"
    > attribute to provide the client with the reason why the access
    > request was declined.

    See https://rfc-editor.org/rfc/rfc6750.html#section-3.1 for the allowed error
    codes.
    """

    def setUp(self):
        self.user = UserModel.objects.create_user(
            "user",
            "test@example.com",
            "123456",
        )
        self.request = mock.MagicMock(wraps=Request)
        self.request.user = self.user
        self.request.grant_type = "not client"
        self.validator = OAuth2Validator()
        self.application = Application.objects.create(
            client_id="client_id",
            client_secret=CLEARTEXT_SECRET,
            user=self.user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_PASSWORD,
        )
        self.request.client = self.application

    def test_validate_bearer_token_does_not_add_error_when_no_token_is_provided(self):
        self.assertFalse(self.validator.validate_bearer_token(None, ["dolphin"], self.request))
        with self.assertRaises(AttributeError):
            self.request.oauth2_error

    def test_validate_bearer_token_adds_error_to_the_request_when_an_invalid_token_is_provided(self):
        access_token = mock.MagicMock(token="some_invalid_token")
        self.assertFalse(
            self.validator.validate_bearer_token(
                access_token.token,
                [],
                self.request,
            )
        )
        self.assertDictEqual(
            self.request.oauth2_error,
            {
                "error": "invalid_token",
                "error_description": "The access token is invalid.",
            },
        )

    def test_validate_bearer_token_adds_error_to_the_request_when_an_expired_token_is_provided(self):
        access_token = AccessToken.objects.create(
            token="some_valid_token",
            user=self.user,
            expires=timezone.now() - datetime.timedelta(seconds=1),
            application=self.application,
        )
        self.assertFalse(
            self.validator.validate_bearer_token(
                access_token.token,
                [],
                self.request,
            )
        )
        self.assertDictEqual(
            self.request.oauth2_error,
            {
                "error": "invalid_token",
                "error_description": "The access token has expired.",
            },
        )

    def test_validate_bearer_token_adds_error_to_the_request_when_a_valid_token_has_insufficient_scope(self):
        access_token = AccessToken.objects.create(
            token="some_valid_token",
            user=self.user,
            expires=timezone.now() + datetime.timedelta(seconds=1),
            application=self.application,
        )
        self.assertFalse(
            self.validator.validate_bearer_token(
                access_token.token,
                ["some_extra_scope"],
                self.request,
            )
        )
        self.assertDictEqual(
            self.request.oauth2_error,
            {
                "error": "insufficient_scope",
                "error_description": "The access token is valid but does not have enough scope.",
            },
        )

    def test_validate_bearer_token_adds_error_to_the_request_when_a_invalid_custom_token_is_provided(self):
        access_token = AccessToken.objects.create(
            token="some_valid_token",
            user=self.user,
            expires=timezone.now() + datetime.timedelta(seconds=1),
            application=self.application,
        )
        with always_invalid_token():
            self.assertFalse(
                self.validator.validate_bearer_token(
                    access_token.token,
                    [],
                    self.request,
                )
            )
        self.assertDictEqual(
            self.request.oauth2_error,
            {
                "error": "invalid_token",
            },
        )


class TestOAuth2ValidatorErrorResourceToken(TestCase):
    """The following tests check logger information when response from oauth2
    is unsuccessful.
    """

    @classmethod
    def setUpTestData(cls):
        cls.token = "test_token"
        cls.introspection_url = "http://example.com/token/introspection/"
        cls.introspection_token = "test_introspection_token"
        cls.validator = OAuth2Validator()

    def test_response_when_auth_server_response_not_200(self):
        """
        Ensure we log the error when the authentication server returns a non-200 response.
        """
        mock_response = requests.Response()
        mock_response.status_code = 404
        mock_response.reason = "Not Found"
        with mock.patch("requests.post") as mock_post:
            mock_post.return_value = mock_response
            with self.assertLogs(logger="oauth2_provider") as mock_log:
                self.validator._get_token_from_authentication_server(
                    self.token, self.introspection_url, self.introspection_token, None
                )
                self.assertIn(
                    "ERROR:oauth2_provider:Introspection: Failed to "
                    "get a valid response from authentication server. "
                    "Status code: 404, Reason: "
                    "Not Found.\nNoneType: None",
                    mock_log.output,
                )


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_oidc_endpoint_generation(oauth2_settings, rf):
    oauth2_settings.OIDC_ISS_ENDPOINT = ""
    django_request = rf.get("/")
    request = Request("/", headers=django_request.META)
    validator = OAuth2Validator()
    oidc_issuer_endpoint = validator.get_oidc_issuer_endpoint(request)
    assert oidc_issuer_endpoint == "http://testserver/o"


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_oidc_endpoint_generation_ssl(oauth2_settings, rf, settings):
    oauth2_settings.OIDC_ISS_ENDPOINT = ""
    django_request = rf.get("/", secure=True)
    # Calling the settings method with a django https request should generate a https url
    oidc_issuer_endpoint = oauth2_settings.oidc_issuer(django_request)
    assert oidc_issuer_endpoint == "https://testserver/o"

    # Should also work with an oauthlib request (via validator)
    core = get_oauthlib_core()
    uri, http_method, body, headers = core._extract_params(django_request)
    request = Request(uri=uri, http_method=http_method, body=body, headers=headers)
    validator = OAuth2Validator()
    oidc_issuer_endpoint = validator.get_oidc_issuer_endpoint(request)
    assert oidc_issuer_endpoint == "https://testserver/o"


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_get_jwt_bearer_token(oauth2_settings, mocker):
    # oauthlib instructs us to make get_jwt_bearer_token call get_id_token
    request = mocker.MagicMock(wraps=Request)
    validator = OAuth2Validator()
    mock_get_id_token = mocker.patch.object(validator, "get_id_token")
    validator.get_jwt_bearer_token(None, None, request)
    assert mock_get_id_token.call_count == 1
    assert mock_get_id_token.call_args[0] == (None, None, request)
    assert mock_get_id_token.call_args[1] == {}


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_validate_id_token_expired_jwt(oauth2_settings, mocker, oidc_tokens):
    mocker.patch("oauth2_provider.oauth2_validators.jwt.JWT", side_effect=jwt.JWTExpired)
    validator = OAuth2Validator()
    status = validator.validate_id_token(oidc_tokens.id_token, ["openid"], mocker.sentinel.request)
    assert status is False


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_validate_id_token_no_token(oauth2_settings, mocker):
    validator = OAuth2Validator()
    status = validator.validate_id_token("", ["openid"], mocker.sentinel.request)
    assert status is False


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_validate_id_token_app_removed(oauth2_settings, mocker, oidc_tokens):
    oidc_tokens.application.delete()
    validator = OAuth2Validator()
    status = validator.validate_id_token(oidc_tokens.id_token, ["openid"], mocker.sentinel.request)
    assert status is False


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_validate_id_token_bad_token_no_aud(oauth2_settings, mocker, oidc_key):
    token = jwt.JWT(header=json.dumps({"alg": "RS256"}), claims=json.dumps({"bad": "token"}))
    token.make_signed_token(oidc_key)
    validator = OAuth2Validator()
    status = validator.validate_id_token(token.serialize(), ["openid"], mocker.sentinel.request)
    assert status is False


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_get_id_token_dictionary_auth_time_naive_last_login_is_utc(oauth2_settings, rf):
    validator = OAuth2Validator()
    django_request = rf.get("/")
    request = Request("/", headers=django_request.META)
    request.scopes = ["openid"]
    request.client = mock.MagicMock()

    naive_last_login = datetime.datetime(2026, 1, 1, 12, 0, 0)
    request.user = mock.MagicMock(pk=1, last_login=naive_last_login)

    with timezone.override("Europe/Rome"):
        claims, _ = validator.get_id_token_dictionary(None, None, request)

    expected_auth_time = int(naive_last_login.replace(tzinfo=datetime.timezone.utc).timestamp())
    assert claims["auth_time"] == expected_auth_time


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_get_id_token_dictionary_auth_time_last_login_none_falls_back_to_now(oauth2_settings, rf):
    validator = OAuth2Validator()
    django_request = rf.get("/")
    request = Request("/", headers=django_request.META)
    request.scopes = ["openid"]
    request.client = mock.MagicMock()
    request.user = mock.MagicMock(pk=1, last_login=None)

    frozen_now = datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
    with mock.patch("oauth2_provider.oauth2_validators.timezone.now", return_value=frozen_now):
        claims, _ = validator.get_id_token_dictionary(None, None, request)

    assert claims["auth_time"] == int(frozen_now.timestamp())


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_get_id_token_dictionary_auth_time_naive_last_login_use_tz_false_uses_default_timezone(
    oauth2_settings, rf, settings
):
    settings.USE_TZ = False
    settings.TIME_ZONE = "Europe/Rome"

    validator = OAuth2Validator()
    django_request = rf.get("/")
    request = Request("/", headers=django_request.META)
    request.scopes = ["openid"]
    request.client = mock.MagicMock()

    naive_last_login = datetime.datetime(2026, 1, 1, 12, 0, 0)
    request.user = mock.MagicMock(pk=1, last_login=naive_last_login)

    claims, _ = validator.get_id_token_dictionary(None, None, request)

    expected_auth_time = int(
        timezone.make_aware(naive_last_login, timezone=timezone.get_default_timezone())
        .astimezone(datetime.timezone.utc)
        .timestamp()
    )
    assert claims["auth_time"] == expected_auth_time


@pytest.mark.django_db(databases="__all__")
def test_invalidate_authorization_token_returns_invalid_grant_error_when_grant_does_not_exist():
    client_id = "123"
    code = "12345"
    request = Request("/")
    assert Grant.objects.all().count() == 0
    with pytest.raises(rfc6749_errors.InvalidGrantError):
        validator = OAuth2Validator()
        validator.invalidate_authorization_code(client_id=client_id, code=code, request=request)
