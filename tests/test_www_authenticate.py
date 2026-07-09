import pytest
from django.test import RequestFactory, override_settings

from oauth2_provider.www_authenticate import build_bearer_challenge

from .common_testing import OAuth2ProviderTestCase as TestCase


@pytest.mark.usefixtures("oauth2_settings")
class TestBuildBearerChallenge(TestCase):
    def setUp(self):
        self.request = RequestFactory().get("/whatever")

    @override_settings(ROOT_URLCONF="tests.urls_oidc_discovery_only")
    def test_bare_bearer_when_nothing_to_advertise(self):
        """No realm, no error, and no reachable metadata route -> a bare ``Bearer``."""
        assert build_bearer_challenge(self.request) == "Bearer"

    def test_includes_error_and_resource_metadata(self):
        challenge = build_bearer_challenge(
            self.request,
            oauth2_error={"error": "invalid_token", "error_description": "nope"},
            realm="api",
        )
        assert challenge.startswith("Bearer ")
        assert 'realm="api"' in challenge
        assert 'error="invalid_token"' in challenge
        assert 'error_description="nope"' in challenge
        assert 'resource_metadata="http://testserver/o/.well-known/oauth-protected-resource"' in challenge
        # auth-params are comma-separated with no following space (matches the DRF builder).
        assert ", " not in challenge

    def test_explicit_resource_metadata_url_overrides_default(self):
        """A path-component / multi-tenant URL can be advertised instead of the root."""
        url = "https://api.example.com/.well-known/oauth-protected-resource/tenant1"
        challenge = build_bearer_challenge(self.request, realm="api", resource_metadata_url=url)
        assert 'resource_metadata="{}"'.format(url) in challenge
        # The default root route is not advertised when an explicit URL is given.
        assert '/o/.well-known/oauth-protected-resource"' not in challenge

    def test_explicit_none_omits_resource_metadata(self):
        challenge = build_bearer_challenge(self.request, realm="api", resource_metadata_url=None)
        assert challenge == 'Bearer realm="api"'

    @override_settings(ROOT_URLCONF="tests.urls_oidc_discovery_only")
    def test_quoted_string_values_are_escaped(self):
        """Quotes/backslashes are escaped and CR/LF stripped so a value cannot break
        out of the quoted string or inject header content."""
        challenge = build_bearer_challenge(
            self.request,
            oauth2_error={"error_description": 'bad " \\ value\r\ninjected: x'},
        )
        assert challenge == r'Bearer error_description="bad \" \\ valueinjected: x"'
