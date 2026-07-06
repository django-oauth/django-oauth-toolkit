import datetime
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.utils import timezone
from oauthlib.common import Request as OauthlibRequest

from oauth2_provider.models import get_access_token_model, get_application_model
from oauth2_provider.oauth2_validators import OAuth2Validator, validate_resource_as_url_prefix
from oauth2_provider.settings import oauth2_settings

from .common_testing import OAuth2ProviderTestCase as TestCase


class TestResourceValidatorPrefixMatch(TestCase):
    """
    Tests for validate_resource_as_url_prefix - default RFC 8707 audience validator.
    Uses prefix matching: token audience acts as base URI.
    """

    def test_prefix_match_exact_uri(self):
        """Token with audience 'https://api.example.com' matches request to 'https://api.example.com/'"""
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

    def test_rejects_userinfo_injection(self):
        """Userinfo in request URI must not bypass audience check"""
        audiences = ["https://api.example.com"]
        request_uri = "https://api.example.com@evil.com/"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertFalse(result)

    def test_rejects_userinfo_in_audience(self):
        """Audience URIs containing userinfo are rejected"""
        audiences = ["https://user:pass@api.example.com"]
        request_uri = "https://api.example.com/"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertFalse(result)

    def test_rejects_fragment_in_audience(self):
        """Audience URIs with fragments are rejected (RFC 3986 absolute-URI)"""
        audiences = ["https://api.example.com/v1#section"]
        request_uri = "https://api.example.com/v1/foo"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertFalse(result)

    def test_rejects_fragment_in_request(self):
        """Request URIs with fragments are rejected"""
        audiences = ["https://api.example.com"]
        request_uri = "https://api.example.com/foo#bar"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertFalse(result)

    def test_rejects_empty_fragment(self):
        """A bare fragment delimiter is rejected even though urlsplit sees an empty fragment"""
        audiences = ["https://api.example.com"]
        request_uri = "https://api.example.com/foo#"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertFalse(result)

    def test_rejects_empty_userinfo(self):
        """An empty userinfo component ("https://@host") is still userinfo and is rejected"""
        audiences = ["https://api.example.com"]
        request_uri = "https://@api.example.com/foo"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertFalse(result)

    def test_port_mismatch(self):
        """Different ports are treated as different origins"""
        audiences = ["https://api.example.com:8443"]
        request_uri = "https://api.example.com:9443/foo"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertFalse(result)

    def test_port_match(self):
        """Matching explicit ports are accepted"""
        audiences = ["https://api.example.com:8443"]
        request_uri = "https://api.example.com:8443/foo"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertTrue(result)

    def test_explicit_default_port_in_request_matches_bare_audience(self):
        """'https://api.example.com:443/foo' matches audience 'https://api.example.com/foo'"""
        audiences = ["https://api.example.com/foo"]
        request_uri = "https://api.example.com:443/foo"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertTrue(result)

    def test_bare_request_matches_explicit_default_port_in_audience(self):
        """'https://api.example.com/foo' matches audience 'https://api.example.com:443/foo'"""
        audiences = ["https://api.example.com:443/foo"]
        request_uri = "https://api.example.com/foo"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertTrue(result)

    def test_explicit_default_port_http(self):
        """'http://api.example.com:80/foo' matches audience 'http://api.example.com/foo'"""
        audiences = ["http://api.example.com/foo"]
        request_uri = "http://api.example.com:80/foo"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertTrue(result)

    def test_default_port_is_scheme_specific(self):
        """'https://api.example.com:80/foo' does NOT match audience 'https://api.example.com/foo'"""
        audiences = ["https://api.example.com/foo"]
        request_uri = "https://api.example.com:80/foo"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertFalse(result)

    def test_rejects_invalid_port(self):
        """URIs with a non-numeric port are rejected instead of raising"""
        audiences = ["https://api.example.com/foo"]
        request_uri = "https://api.example.com:bad/foo"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertFalse(result)

    def test_query_component_in_audience_is_ignored(self):
        """RFC 8707 allows a query component on resource indicators; matching ignores it"""
        audiences = ["https://api.example.com/foo?version=2"]
        request_uri = "https://api.example.com/foo/bar"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertTrue(result)

    def test_rejects_dot_segment_bypass(self):
        """Path traversal with '..' must not bypass audience check"""
        audiences = ["https://api.example.com/foo"]
        request_uri = "https://api.example.com/foo/../admin"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertFalse(result)

    def test_dot_segment_resolved_match(self):
        """Path with '..' that resolves to a valid prefix still matches"""
        audiences = ["https://api.example.com/foo"]
        request_uri = "https://api.example.com/foo/bar/../baz"

        result = validate_resource_as_url_prefix(request_uri, audiences)

        self.assertTrue(result)

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

    def test_allows_audience_short_circuits_empty_resource(self):
        """Unrestricted tokens allow any audience even if a custom validator would deny []"""

        def deny_everything(request_uri, audiences):
            return False

        with patch.object(oauth2_settings, "RESOURCE_SERVER_TOKEN_RESOURCE_VALIDATOR", deny_everything):
            self.assertTrue(self.token_unrestricted.allows_audience("https://any.example.com"))
            self.assertFalse(self.token_with_resource.allows_audience("https://other.example.com"))

    def test_validate_bearer_token_unrestricted_token_without_request_uri(self):
        """Unrestricted tokens skip the audience check and don't require request.uri"""

        class MinimalRequest:
            """A request object with no uri attribute, as some callers provide"""

        validator = OAuth2Validator()
        request = MinimalRequest()

        result = validator.validate_bearer_token(
            self.token_unrestricted.token, scopes=["read"], request=request
        )

        self.assertTrue(result)

    def test_validate_bearer_token_restricted_token_without_request_uri_fails_closed(self):
        """Restricted tokens are rejected when the request has no uri to compare"""

        class MinimalRequest:
            """A request object with no uri attribute"""

        validator = OAuth2Validator()
        request = MinimalRequest()

        result = validator.validate_bearer_token(
            self.token_with_resource.token, scopes=["read"], request=request
        )

        self.assertFalse(result)

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


class TestResourceJSONFieldValidation(TestCase):
    """ResourceJSONField only persists lists of strings."""

    def setUp(self):
        User = get_user_model()
        Application = get_application_model()
        self.user = User.objects.create_user("field_user", "test@example.com")
        self.app = Application.objects.create(
            name="Field Test App",
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            user=self.user,
        )

    def _make_token(self, resource):
        AccessToken = get_access_token_model()
        return AccessToken.objects.create(
            user=self.user,
            application=self.app,
            token="field_test_token",
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read",
            resource=resource,
        )

    def test_rejects_non_list_value(self):
        from django.core.exceptions import ValidationError

        with self.assertRaises(ValidationError):
            self._make_token("https://api.example.com")

    def test_rejects_non_string_entries(self):
        from django.core.exceptions import ValidationError

        with self.assertRaises(ValidationError):
            self._make_token([{"uri": "https://api.example.com"}])

    def test_accepts_list_of_strings(self):
        token = self._make_token(["https://api.example.com"])
        token.refresh_from_db()
        self.assertEqual(token.resource, ["https://api.example.com"])

    def test_normalizes_none_to_empty_list(self):
        token = self._make_token(None)
        token.refresh_from_db()
        self.assertEqual(token.resource, [])


class TestResourceValidatorThroughViewStack(TestCase):
    """
    End-to-end audience validation through the real Django view stack
    (OAuthLibMixin -> OAuthLibCore._extract_params -> validate_bearer_token).

    Regression test: _extract_params passes request.get_full_path() (a relative
    URI) to oauthlib, so verify_request must upgrade it to an absolute URI or
    every resource-restricted token is rejected regardless of audience.
    """

    def setUp(self):
        from django.http import HttpResponse

        from oauth2_provider.views.generic import ProtectedResourceView

        class ResourceView(ProtectedResourceView):
            def get(self, request, *args, **kwargs):
                return HttpResponse("ok")

        self.view = ResourceView.as_view()

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
        # The Django test RequestFactory produces requests for http://testserver
        self.restricted_token = AccessToken.objects.create(
            user=self.user,
            application=self.app,
            token="e2e_restricted",
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write",
            resource=["http://testserver/api"],
        )
        self.mismatched_token = AccessToken.objects.create(
            user=self.user,
            application=self.app,
            token="e2e_mismatched",
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write",
            resource=["https://other.example.com/api"],
        )
        self.unrestricted_token = AccessToken.objects.create(
            user=self.user,
            application=self.app,
            token="e2e_unrestricted",
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write",
            resource=[],
        )

    def _get(self, token, path="/api/things"):
        from django.test import RequestFactory

        request = RequestFactory().get(path, HTTP_AUTHORIZATION="Bearer {}".format(token))
        return self.view(request)

    def test_restricted_token_with_matching_audience_is_accepted(self):
        response = self._get(self.restricted_token.token)
        self.assertEqual(response.status_code, 200)

    def test_restricted_token_with_mismatched_audience_is_rejected(self):
        response = self._get(self.mismatched_token.token)
        self.assertEqual(response.status_code, 403)

    def test_restricted_token_outside_audience_path_is_rejected(self):
        response = self._get(self.restricted_token.token, path="/admin/things")
        self.assertEqual(response.status_code, 403)

    def test_unrestricted_token_is_accepted(self):
        response = self._get(self.unrestricted_token.token)
        self.assertEqual(response.status_code, 200)
