import datetime
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from oauthlib.common import Request as OauthlibRequest

from oauth2_provider.models import get_access_token_model, get_application_model
from oauth2_provider.oauth2_validators import OAuth2Validator, validate_resource_as_url_prefix
from oauth2_provider.settings import oauth2_settings


class TestResourceValidatorPrefixMatch(TestCase):
    """
    Tests for validate_resource_as_url_prefix - default RFC 8707 audience validator.
    Uses prefix matching: token audience acts as base URI.
    """

    def test_prefix_match_exact_uri(self):
        """Token with audience 'https://api.example.com' matches request to 'https://api.example.com'"""
        audiences = ["https://api.example.com"]
        request_uri = "https://api.example.com/"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertTrue(result)

    def test_prefix_match_with_path(self):
        """Token with audience 'https://api.example.com/foo' matches request to 'https://api.example.com/foo/bar'"""
        audiences = ["https://api.example.com/foo"]
        request_uri = "https://api.example.com/foo/bar"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertTrue(result)

    def test_prefix_match_ignores_query_params(self):
        """Validator works with query params already stripped from URI"""
        audiences = ["https://api.example.com/api"]
        request_uri = "https://api.example.com/api/users"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertTrue(result)

    def test_no_match_different_path(self):
        """Token with audience 'https://api.example.com/foo' does NOT match request to 'https://api.example.com/bar'"""
        audiences = ["https://api.example.com/foo"]
        request_uri = "https://api.example.com/bar"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertFalse(result)

    def test_no_match_different_domain(self):
        """Token with audience 'https://api.example.com' does NOT match request to 'https://other.example.com'"""
        audiences = ["https://api.example.com"]
        request_uri = "https://other.example.com/"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertFalse(result)

    def test_no_match_http_vs_https(self):
        """Token with audience 'https://api.example.com' does NOT match request to 'http://api.example.com'"""
        audiences = ["https://api.example.com"]
        request_uri = "http://api.example.com/"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertFalse(result)

    def test_multiple_audiences_one_matches(self):
        """Token with multiple audiences matches if any audience prefix matches"""
        audiences = ["https://api.example.com", "https://data.example.com"]
        request_uri = "https://data.example.com/v1/records"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertTrue(result)

    def test_no_audiences_allows_any_request(self):
        """Token without audiences (unrestricted) allows any request (backward compatibility)"""
        audiences = []
        request_uri = "https://any.example.com/anything"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertTrue(result)

    def test_prefix_must_match_path_segments(self):
        """Token with audience 'https://api.example.com/ap' does NOT match 'https://api.example.com/api'"""
        audiences = ["https://api.example.com/ap"]
        request_uri = "https://api.example.com/api"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertFalse(result)

    def test_trailing_slash_normalization(self):
        """Token with audience 'https://api.example.com/foo/' matches 'https://api.example.com/foo/bar'"""
        audiences = ["https://api.example.com/foo/"]
        request_uri = "https://api.example.com/foo/bar"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertTrue(result)


class TestResourceValidatorIntegration(TestCase):
    """
    Tests for resource validator integration with validate_bearer_token.
    """

    def setUp(self):
        User = get_user_model()
        Application = get_application_model()
        AccessToken = get_access_token_model()

        self.user = User.objects.create_user("test_user", "test@example.com")
        self.app = Application.objects.create(
            name="Test App",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            user=self.user,
        )

        # Token with resource binding
        self.token_with_resource = AccessToken.objects.create(
            user=self.user,
            application=self.app,
            token="token_with_aud",
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write",
            resource=["https://api.example.com/v1"],
        )

        # Unrestricted token
        self.token_unrestricted = AccessToken.objects.create(
            user=self.user,
            application=self.app,
            token="token_unrestricted",
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write",
            resource=[],
        )

    def _make_oauthlib_request(self, uri):
        """Helper to create an oauthlib Request object with the given URI"""
        return OauthlibRequest(uri, http_method="GET")

    def test_validate_bearer_token_accepts_matching_resource(self):
        """validate_bearer_token accepts token when audience matches request"""

        validator = OAuth2Validator()
        request = self._make_oauthlib_request("https://api.example.com/v1/users")

        result = validator.validate_bearer_token(
            self.token_with_resource.token, scopes=["read"], request=request
        )

        self.assertTrue(result)
        self.assertEqual(request.user, self.user)

    def test_validate_bearer_token_rejects_non_matching_resource(self):
        """validate_bearer_token rejects token when audience doesn't match request"""

        validator = OAuth2Validator()
        request = self._make_oauthlib_request("https://other.example.com/v1/users")

        result = validator.validate_bearer_token(
            self.token_with_resource.token, scopes=["read"], request=request
        )

        self.assertFalse(result)

    def test_validate_bearer_token_accepts_unrestricted_token(self):
        """validate_bearer_token accepts unrestricted token for any resource"""

        validator = OAuth2Validator()
        request = self._make_oauthlib_request("https://any.example.com/anything")

        result = validator.validate_bearer_token(
            self.token_unrestricted.token, scopes=["read"], request=request
        )

        self.assertTrue(result)

    def test_validate_bearer_token_with_disabled_validator(self):
        """validate_bearer_token works when validator is disabled (None)"""

        validator = OAuth2Validator()
        # Request to non-matching resource
        request = self._make_oauthlib_request("https://other.example.com/v1/users")

        # Temporarily disable the validator
        with patch.object(oauth2_settings, "RESOURCE_SERVER_TOKEN_RESOURCE_VALIDATOR", None):
            result = validator.validate_bearer_token(
                self.token_with_resource.token, scopes=["read"], request=request
            )

        # Should succeed because validator is disabled
        self.assertTrue(result)
