from urllib.parse import parse_qs, urlparse

import pytest
from django.conf import settings
from django.contrib.auth import get_user, get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory, override_settings
from django.urls import NoReverseMatch, reverse
from django.utils import timezone
from pytest_django.asserts import assertRedirects

from oauth2_provider.exceptions import (
    ClientIdMissmatch,
    InvalidIDTokenError,
    InvalidOIDCClientError,
    InvalidOIDCRedirectURIError,
)
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_id_token_model,
    get_refresh_token_model,
)
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.views.base import AuthorizationView
from oauth2_provider.views.oidc import RPInitiatedLogoutView, _load_id_token, _validate_claims

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestConnectDiscoveryInfoView(TestCase):
    def test_get_connect_discovery_info(self):
        expected_response = {
            "issuer": "http://localhost/o",
            "authorization_endpoint": "http://localhost/o/authorize/",
            "token_endpoint": "http://localhost/o/token/",
            "userinfo_endpoint": "http://localhost/o/userinfo/",
            "jwks_uri": "http://localhost/o/.well-known/jwks.json",
            "scopes_supported": ["read", "write", "openid"],
            "response_types_supported": [
                "code",
                "token",
                "id_token",
                "id_token token",
                "code token",
                "code id_token",
                "code id_token token",
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "HS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": ["plain", "S256"],
            "claims_supported": ["sub"],
            "prompt_values_supported": ["none", "login"],
        }
        response = self.client.get("/o/.well-known/openid-configuration")
        self.assertEqual(response.status_code, 200)
        assert response.json() == expected_response

    def test_get_connect_discovery_info_deprecated(self):
        expected_response = {
            "issuer": "http://localhost/o",
            "authorization_endpoint": "http://localhost/o/authorize/",
            "token_endpoint": "http://localhost/o/token/",
            "userinfo_endpoint": "http://localhost/o/userinfo/",
            "jwks_uri": "http://localhost/o/.well-known/jwks.json",
            "scopes_supported": ["read", "write", "openid"],
            "response_types_supported": [
                "code",
                "token",
                "id_token",
                "id_token token",
                "code token",
                "code id_token",
                "code id_token token",
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "HS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": ["plain", "S256"],
            "claims_supported": ["sub"],
            "prompt_values_supported": ["none", "login"],
        }
        response = self.client.get("/o/.well-known/openid-configuration/")
        self.assertEqual(response.status_code, 200)
        assert response.json() == expected_response

    def expect_json_response_with_rp_logout(self, base):
        expected_response = {
            "issuer": f"{base}",
            "authorization_endpoint": f"{base}/authorize/",
            "token_endpoint": f"{base}/token/",
            "userinfo_endpoint": f"{base}/userinfo/",
            "jwks_uri": f"{base}/.well-known/jwks.json",
            "scopes_supported": ["read", "write", "openid"],
            "response_types_supported": [
                "code",
                "token",
                "id_token",
                "id_token token",
                "code token",
                "code id_token",
                "code id_token token",
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "HS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": ["plain", "S256"],
            "claims_supported": ["sub"],
            "prompt_values_supported": ["none", "login"],
            "end_session_endpoint": f"{base}/logout/",
        }
        response = self.client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))
        self.assertEqual(response.status_code, 200)
        assert response.json() == expected_response

    def test_get_connect_discovery_info_with_rp_logout(self):
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED = True
        self.expect_json_response_with_rp_logout(self.oauth2_settings.OIDC_ISS_ENDPOINT)

    def test_get_connect_discovery_info_without_issuer_url(self):
        self.oauth2_settings.OIDC_ISS_ENDPOINT = None
        self.oauth2_settings.OIDC_USERINFO_ENDPOINT = None
        expected_response = {
            "issuer": "http://testserver/o",
            "authorization_endpoint": "http://testserver/o/authorize/",
            "token_endpoint": "http://testserver/o/token/",
            "userinfo_endpoint": "http://testserver/o/userinfo/",
            "jwks_uri": "http://testserver/o/.well-known/jwks.json",
            "scopes_supported": ["read", "write", "openid"],
            "response_types_supported": [
                "code",
                "token",
                "id_token",
                "id_token token",
                "code token",
                "code id_token",
                "code id_token token",
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "HS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": ["plain", "S256"],
            "claims_supported": ["sub"],
            "prompt_values_supported": ["none", "login"],
        }
        response = self.client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))
        self.assertEqual(response.status_code, 200)
        assert response.json() == expected_response

    def test_get_connect_discovery_info_without_issuer_url_with_rp_logout(self):
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED = True
        self.oauth2_settings.OIDC_ISS_ENDPOINT = None
        self.oauth2_settings.OIDC_USERINFO_ENDPOINT = None
        self.expect_json_response_with_rp_logout("http://testserver/o")

    def test_get_connect_discovery_info_without_rsa_key(self):
        self.oauth2_settings.OIDC_RSA_PRIVATE_KEY = None
        response = self.client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))
        self.assertEqual(response.status_code, 200)
        assert response.json()["id_token_signing_alg_values_supported"] == ["HS256"]

    @override_settings(ROOT_URLCONF="tests.urls_oidc_discovery_only")
    def test_get_connect_discovery_info_fails_fast_on_unregistered_endpoint(self):
        """Required OIDC endpoints must fail fast, not emit null, when unreversible."""
        with self.assertRaises(NoReverseMatch):
            self.client.get("/.well-known/openid-configuration")


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestJwksInfoView(TestCase):
    def test_get_jwks_info(self):
        self.oauth2_settings.OIDC_RSA_PRIVATE_KEYS_INACTIVE = []
        expected_response = {
            "keys": [
                {
                    "alg": "RS256",
                    "use": "sig",
                    "kid": "s4a1o8mFEd1tATAIH96caMlu4hOxzBUaI2QTqbYNBHs",
                    "e": "AQAB",
                    "kty": "RSA",
                    "n": "mwmIeYdjZkLgalTuhvvwjvnB5vVQc7G9DHgOm20Hw524bLVTk49IXJ2Scw42HOmowWWX-oMVT_ca3ZvVIeffVSN1-TxVy2zB65s0wDMwhiMoPv35z9IKHGMZgl9vlyso_2b7daVF_FQDdgIayUn8TQylBxEU1RFfW0QSYOBdAt8",  # noqa
                }
            ]
        }
        response = self.client.get(reverse("oauth2_provider:jwks-info"))
        self.assertEqual(response.status_code, 200)
        assert response.json() == expected_response

    def test_get_jwks_info_cache_control_header(self):
        response = self.client.get(reverse("oauth2_provider:jwks-info"))
        max_age = self.oauth2_settings.OIDC_JWKS_MAX_AGE_SECONDS

        self.assertEqual(response.status_code, 200)
        assert response["Cache-Control"] == (
            f"public, max-age={max_age}, stale-while-revalidate={max_age}, stale-if-error={max_age}"
        )

    def test_get_jwks_info_no_rsa_key(self):
        self.oauth2_settings.OIDC_RSA_PRIVATE_KEY = None
        response = self.client.get(reverse("oauth2_provider:jwks-info"))
        self.assertEqual(response.status_code, 200)
        assert response.json() == {"keys": []}

    def test_get_jwks_info_multiple_rsa_keys(self):
        expected_response = {
            "keys": [
                {
                    "alg": "RS256",
                    "e": "AQAB",
                    "kid": "s4a1o8mFEd1tATAIH96caMlu4hOxzBUaI2QTqbYNBHs",
                    "kty": "RSA",
                    "n": "mwmIeYdjZkLgalTuhvvwjvnB5vVQc7G9DHgOm20Hw524bLVTk49IXJ2Scw42HOmowWWX-oMVT_ca3ZvVIeffVSN1-TxVy2zB65s0wDMwhiMoPv35z9IKHGMZgl9vlyso_2b7daVF_FQDdgIayUn8TQylBxEU1RFfW0QSYOBdAt8",  # noqa
                    "use": "sig",
                },
                {
                    "alg": "RS256",
                    "e": "AQAB",
                    "kid": "AJ_IkYJUFWqiKKE2FvPIESroTvownbaj0OzL939oIIE",
                    "kty": "RSA",
                    "n": "0qVzbcWg_fgygZ0liTaFeodD2bkinhj8gPJ9P2rPzvqG6ImI9YKkEk8Dxcc7eWcudnw5iEL8wx_tgooaRiHiYfUrFBBXfA15D_15PdX_5gG8rQbJ7XMxQrYoRUcVm2wQDB4fIuR7sTPqx9p8OR4f--BixOfM5Oa7SEUtQ8kvrlE",  # noqa
                    "use": "sig",
                },
            ]
        }
        response = self.client.get(reverse("oauth2_provider:jwks-info"))
        self.assertEqual(response.status_code, 200)
        assert response.json() == expected_response


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RP_REGISTRATION)
class TestRPInitiatedRegistration(TestCase):
    def setUp(self):
        Application = get_application_model()
        self.application = Application.objects.create(
            name="Test Application",
            redirect_uris="http://localhost http://example.com",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        User = get_user_model()
        self.test_user = User.objects.create_user("test_user", "test@example.com", "123456")

    def _build_authorization_request(self, query_params, user=None):
        auth_url = reverse("oauth2_provider:authorize")
        request = RequestFactory().get(auth_url, data=query_params)
        request.user = user or AnonymousUser()
        return request

    def test_connect_discovery_info_has_create(self):
        expected_response = {
            "issuer": "http://localhost/o",
            "authorization_endpoint": "http://localhost/o/authorize/",
            "token_endpoint": "http://localhost/o/token/",
            "userinfo_endpoint": "http://localhost/o/userinfo/",
            "jwks_uri": "http://localhost/o/.well-known/jwks.json",
            "scopes_supported": ["read", "write", "openid"],
            "response_types_supported": [
                "code",
                "token",
                "id_token",
                "id_token token",
                "code token",
                "code id_token",
                "code id_token token",
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "HS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": ["plain", "S256"],
            "claims_supported": ["sub"],
            "prompt_values_supported": ["none", "login", "create"],
        }
        response = self.client.get("/o/.well-known/openid-configuration")
        self.assertEqual(response.status_code, 200)
        assert response.json() == expected_response

    def test_prompt_create_redirects_to_registration_view(self):
        request = self._build_authorization_request(
            query_params={
                "response_type": "code",
                "client_id": self.application.client_id,
                "redirect_uri": "http://localhost",
                "scope": "openid",
                "prompt": "create",
            }
        )
        view = AuthorizationView()
        view.setup(request)
        response = view.get(request)

        self.assertEqual(response.status_code, 302)
        redirect_url = response.url
        parsed_url = urlparse(redirect_url)

        # Verify it's the registration URL configured in the preset
        self.assertEqual(parsed_url.path, "/accounts/signup/")

        # Verify the query parameters
        query = parse_qs(parsed_url.query)
        self.assertIn("next", query)

        # Verify the next parameter doesn't contain prompt=create
        next_url = query["next"][0]
        self.assertNotIn("prompt=create", next_url)

        # But it should contain the other original parameters
        self.assertIn("response_type=code", next_url)
        self.assertIn(f"client_id={self.application.client_id}", next_url)

    def test_multi_value_prompt_containing_create_triggers_registration(self):
        """
        prompt is a space-delimited list (OpenID Connect Core 1.0 section
        3.1.2.1): create must be honored when combined with other values,
        and the other values are preserved in the next URL.
        """
        request = self._build_authorization_request(
            query_params={
                "response_type": "code",
                "client_id": self.application.client_id,
                "redirect_uri": "http://localhost",
                "scope": "openid",
                "prompt": "login create",
            }
        )
        view = AuthorizationView()
        view.setup(request)
        response = view.get(request)

        self.assertEqual(response.status_code, 302)
        parsed_url = urlparse(response.url)
        self.assertEqual(parsed_url.path, "/accounts/signup/")
        next_url = parse_qs(parsed_url.query)["next"][0]
        self.assertIn("prompt=login", next_url)
        self.assertNotIn("create", next_url)

    def test_anonymous_multi_value_prompt_redirects_to_registration(self):
        """
        The same multi-value prompt must also trigger registration when it
        arrives via handle_no_permission (full request cycle, anonymous user).
        """
        query_data = {
            "response_type": "code",
            "client_id": self.application.client_id,
            "redirect_uri": "http://localhost",
            "scope": "openid",
            "prompt": "login create",
        }

        response = self.client.get(reverse("oauth2_provider:authorize"), data=query_data)

        self.assertEqual(response.status_code, 302)
        parsed_url = urlparse(response["Location"])
        self.assertEqual(parsed_url.path, "/accounts/signup/")
        next_url = parse_qs(parsed_url.query)["next"][0]
        self.assertIn("prompt=login", next_url)
        self.assertNotIn("create", next_url)

    def test_authenticated_users_proceed_to_authorization(self):
        """
        create is a no-op for a user with an existing authenticated session:
        the authorization request proceeds to the normal consent flow.
        """
        self.client.force_login(self.test_user)
        response = self.client.get(
            reverse("oauth2_provider:authorize"),
            data={
                "response_type": "code",
                "client_id": self.application.client_id,
                "redirect_uri": "http://localhost",
                "scope": "openid",
                "prompt": "create",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["application"], self.application)

    def test_authenticated_users_are_not_affected_by_misconfiguration(self):
        """
        The authenticated no-op happens before the registration URL is
        resolved, so a misconfigured URL cannot break flows that never
        redirect to registration.
        """
        self.oauth2_settings.OIDC_RP_INITIATED_REGISTRATION_URL = None
        self.client.force_login(self.test_user)
        response = self.client.get(
            reverse("oauth2_provider:authorize"),
            data={
                "response_type": "code",
                "client_id": self.application.client_id,
                "redirect_uri": "http://localhost",
                "scope": "openid",
                "prompt": "create",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["application"], self.application)

    def test_authenticated_multi_value_prompt_forces_login(self):
        """
        A Relying Party that wants re-authentication of a logged-in user can
        combine prompt values: create is skipped and login is honored.
        """
        self.client.force_login(self.test_user)
        response = self.client.get(
            reverse("oauth2_provider:authorize"),
            data={
                "response_type": "code",
                "client_id": self.application.client_id,
                "redirect_uri": "http://localhost",
                "scope": "openid",
                "prompt": "create login",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(urlparse(response["Location"]).path, settings.LOGIN_URL)

    def test_missing_redirect_uri_is_rejected_without_redirect(self):
        """
        A request without redirect_uri is fatal when the client has more than
        one registered redirect_uri (RFC 6749 section 3.1.2.3), so the error
        page is rendered and no redirect is emitted.
        """
        view = AuthorizationView()
        request = self._build_authorization_request(
            query_params={
                "response_type": "code",
                "client_id": self.application.client_id,
                "scope": "openid",
                "prompt": "create",
            },
        )
        view.setup(request)
        response = view.handle_prompt_create()
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("Location", response)

    def test_prompt_create_open_redirect_unregistered_redirect_uri(self):
        """
        Regression test for the prompt=create open redirect.

        An unauthenticated prompt=create request enters handle_prompt_create
        via handle_no_permission, where no validation has run yet. With a
        redirect_uri that is not registered for the client, the error path
        must not redirect at all: the error page is rendered instead of any
        Location header being emitted.
        """
        query_data = {
            "response_type": "code",
            "client_id": self.application.client_id,
            "scope": "openid",
            "prompt": "create",
            "redirect_uri": "http://attacker.example/cb",
            "state": "phish-123",
        }

        response = self.client.get(reverse("oauth2_provider:authorize"), data=query_data)

        self.assertEqual(response.status_code, 400)
        self.assertNotIn("Location", response)

    def test_prompt_create_open_redirect_no_client(self):
        """
        Regression test for the prompt=create open redirect.

        With no client_id at all, nothing can be validated, so no redirect
        may be emitted for the error.
        """
        query_data = {
            "prompt": "create",
            "redirect_uri": "http://attacker.example/cb",
            "state": "phish-123",
        }

        response = self.client.get(reverse("oauth2_provider:authorize"), data=query_data)

        self.assertEqual(response.status_code, 400)
        self.assertNotIn("Location", response)

    def test_redirect_on_handle_no_permission(self):
        view = AuthorizationView()
        request = self._build_authorization_request(
            query_params={
                "response_type": "code",
                "redirect_uri": "http://localhost",
                "client_id": self.application.client_id,
                "scope": "openid",
                "prompt": "create",
            }
        )
        view.setup(request)
        response = view.handle_no_permission()
        self.assertEqual(response.status_code, 302)

    def _get_with_prompt_create(self):
        view = AuthorizationView()
        request = self._build_authorization_request(
            query_params={
                "response_type": "code",
                "client_id": self.application.client_id,
                "redirect_uri": "http://localhost",
                "scope": "openid",
                "prompt": "create",
            }
        )
        view.setup(request)
        return view.get(request)

    def test_registration_url_accepts_a_url_pattern_name(self):
        """
        Like LOGIN_URL, the setting is resolved with resolve_url() and so
        accepts a URL pattern name as well as a path.
        """
        self.oauth2_settings.OIDC_RP_INITIATED_REGISTRATION_URL = "admin:login"
        response = self._get_with_prompt_create()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(urlparse(response.url).path, reverse("admin:login"))

    def test_registration_url_query_and_fragment_are_preserved(self):
        """
        next is merged into the configured URL's query string, so an existing
        query or fragment survives (naive concatenation would append the
        parameter after the fragment, where it never reaches the server).
        """
        self.oauth2_settings.OIDC_RP_INITIATED_REGISTRATION_URL = "/accounts/signup/?plan=free#form"
        response = self._get_with_prompt_create()
        self.assertEqual(response.status_code, 302)
        parsed_url = urlparse(response.url)
        self.assertEqual(parsed_url.path, "/accounts/signup/")
        self.assertEqual(parsed_url.fragment, "form")
        query = parse_qs(parsed_url.query)
        self.assertEqual(query["plan"], ["free"])
        self.assertIn("next", query)

    def test_unset_registration_url_raises_improperly_configured(self):
        self.oauth2_settings.OIDC_RP_INITIATED_REGISTRATION_URL = None
        with self.assertRaises(ImproperlyConfigured):
            self._get_with_prompt_create()

    def test_unresolvable_registration_url_raises_improperly_configured(self):
        self.oauth2_settings.OIDC_RP_INITIATED_REGISTRATION_URL = "nonexistent_signup_view"
        with self.assertRaises(ImproperlyConfigured):
            self._get_with_prompt_create()


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestRPInitiatedRegistrationDisabled(TestCase):
    """
    Per OpenID Connect Prompt Create 1.0 section 4.1.1, an OP receiving a
    prompt value it does not support SHOULD respond with HTTP 400 and an
    error value of invalid_request.
    """

    def setUp(self):
        Application = get_application_model()
        self.application = Application.objects.create(
            name="Test Application",
            redirect_uris="http://localhost http://example.com",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        User = get_user_model()
        self.test_user = User.objects.create_user("test_user", "test@example.com", "123456")

    def _authorize_with_prompt_create(self):
        query_data = {
            "response_type": "code",
            "client_id": self.application.client_id,
            "redirect_uri": "http://localhost",
            "scope": "openid",
            "prompt": "create",
            "state": "some_state",
        }
        return self.client.get(reverse("oauth2_provider:authorize"), data=query_data)

    def test_prompt_create_is_invalid_request_for_anonymous_user(self):
        response = self._authorize_with_prompt_create()
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("Location", response)
        self.assertEqual(response.json()["error"], "invalid_request")

    def test_prompt_create_is_invalid_request_for_authenticated_user(self):
        self.client.force_login(self.test_user)
        response = self._authorize_with_prompt_create()
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("Location", response)
        self.assertEqual(response.json()["error"], "invalid_request")


def mock_request():
    """
    Dummy request with an AnonymousUser attached.
    """
    return mock_request_for(AnonymousUser())


def mock_request_for(user):
    """
    Dummy request with the `user` attached.
    """
    request = RequestFactory().get("")
    request.user = user
    return request


@pytest.mark.django_db(databases="__all__")
def test_validate_logout_request(oidc_tokens, public_application, rp_settings):
    oidc_tokens = oidc_tokens
    application = oidc_tokens.application
    client_id = application.client_id
    id_token = oidc_tokens.id_token
    view = RPInitiatedLogoutView()
    view.request = mock_request_for(oidc_tokens.user)
    assert view.validate_logout_request(
        id_token_hint=None,
        client_id=None,
        post_logout_redirect_uri=None,
    ) == (None, None)
    assert view.validate_logout_request(
        id_token_hint=None,
        client_id=client_id,
        post_logout_redirect_uri=None,
    ) == (application, None)
    assert view.validate_logout_request(
        id_token_hint=None,
        client_id=client_id,
        post_logout_redirect_uri="http://example.org",
    ) == (application, None)
    assert view.validate_logout_request(
        id_token_hint=id_token,
        client_id=None,
        post_logout_redirect_uri="http://example.org",
    ) == (application, oidc_tokens.user)
    assert view.validate_logout_request(
        id_token_hint=id_token,
        client_id=client_id,
        post_logout_redirect_uri="http://example.org",
    ) == (application, oidc_tokens.user)
    with pytest.raises(InvalidIDTokenError):
        view.validate_logout_request(
            id_token_hint="111",
            client_id=public_application.client_id,
            post_logout_redirect_uri="http://other.org",
        )
    with pytest.raises(ClientIdMissmatch):
        view.validate_logout_request(
            id_token_hint=id_token,
            client_id=public_application.client_id,
            post_logout_redirect_uri="http://other.org",
        )
    with pytest.raises(InvalidOIDCClientError):
        view.validate_logout_request(
            id_token_hint=None,
            client_id=None,
            post_logout_redirect_uri="http://example.org",
        )
    with pytest.raises(InvalidOIDCRedirectURIError):
        view.validate_logout_request(
            id_token_hint=None,
            client_id=client_id,
            post_logout_redirect_uri="example.org",
        )
    with pytest.raises(InvalidOIDCRedirectURIError):
        view.validate_logout_request(
            id_token_hint=None,
            client_id=client_id,
            post_logout_redirect_uri="imap://example.org",
        )
    with pytest.raises(InvalidOIDCRedirectURIError):
        view.validate_logout_request(
            id_token_hint=None,
            client_id=client_id,
            post_logout_redirect_uri="http://other.org",
        )
    with pytest.raises(InvalidOIDCRedirectURIError):
        rp_settings.OIDC_RP_INITIATED_LOGOUT_STRICT_REDIRECT_URIS = True
        view.validate_logout_request(
            id_token_hint=None,
            client_id=public_application.client_id,
            post_logout_redirect_uri="http://other.org",
        )


@pytest.mark.django_db(databases="__all__")
@pytest.mark.parametrize("ALWAYS_PROMPT", [True, False])
def test_must_prompt(oidc_tokens, other_user, rp_settings, ALWAYS_PROMPT):
    rp_settings.OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT = ALWAYS_PROMPT
    oidc_tokens = oidc_tokens
    assert RPInitiatedLogoutView(request=mock_request_for(oidc_tokens.user)).must_prompt(None) is True
    assert (
        RPInitiatedLogoutView(request=mock_request_for(oidc_tokens.user)).must_prompt(oidc_tokens.user)
        == ALWAYS_PROMPT
    )
    assert RPInitiatedLogoutView(request=mock_request_for(other_user)).must_prompt(oidc_tokens.user) is True
    assert (
        RPInitiatedLogoutView(request=mock_request_for(AnonymousUser())).must_prompt(oidc_tokens.user)
        is False
    )


def test__load_id_token():
    assert _load_id_token("Not a Valid ID Token.") == (None, None)


def is_logged_in(client):
    return get_user(client).is_authenticated


@pytest.mark.django_db(databases="__all__")
def test_rp_initiated_logout_get(logged_in_client, rp_settings):
    rsp = logged_in_client.get(reverse("oauth2_provider:rp-initiated-logout"), data={})
    assert rsp.status_code == 200
    assert is_logged_in(logged_in_client)


@pytest.mark.django_db(databases="__all__")
def test_rp_initiated_logout_get_id_token(logged_in_client, oidc_tokens, rp_settings):
    rsp = logged_in_client.get(
        reverse("oauth2_provider:rp-initiated-logout"), data={"id_token_hint": oidc_tokens.id_token}
    )
    assert rsp.status_code == 302
    assert rsp["Location"] == "http://testserver/"
    assert not is_logged_in(logged_in_client)


@pytest.mark.django_db(databases="__all__")
def test_rp_initiated_logout_get_revoked_id_token(logged_in_client, oidc_tokens, rp_settings):
    validator = oauth2_settings.OAUTH2_VALIDATOR_CLASS()
    validator._load_id_token(oidc_tokens.id_token).revoke()
    rsp = logged_in_client.get(
        reverse("oauth2_provider:rp-initiated-logout"), data={"id_token_hint": oidc_tokens.id_token}
    )
    assert rsp.status_code == 400
    assert is_logged_in(logged_in_client)


@pytest.mark.django_db(databases="__all__")
def test_rp_initiated_logout_get_id_token_redirect(logged_in_client, oidc_tokens, rp_settings):
    rsp = logged_in_client.get(
        reverse("oauth2_provider:rp-initiated-logout"),
        data={"id_token_hint": oidc_tokens.id_token, "post_logout_redirect_uri": "http://example.org"},
    )
    assert rsp.status_code == 302
    assert rsp["Location"] == "http://example.org"
    assert not is_logged_in(logged_in_client)


@pytest.mark.django_db(databases="__all__")
def test_rp_initiated_logout_get_id_token_redirect_with_state(logged_in_client, oidc_tokens, rp_settings):
    rsp = logged_in_client.get(
        reverse("oauth2_provider:rp-initiated-logout"),
        data={
            "id_token_hint": oidc_tokens.id_token,
            "post_logout_redirect_uri": "http://example.org",
            "state": "987654321",
        },
    )
    assert rsp.status_code == 302
    assert rsp["Location"] == "http://example.org?state=987654321"
    assert not is_logged_in(logged_in_client)


@pytest.mark.django_db(databases="__all__")
def test_rp_initiated_logout_get_id_token_missmatch_client_id(
    logged_in_client, oidc_tokens, public_application, rp_settings
):
    rsp = logged_in_client.get(
        reverse("oauth2_provider:rp-initiated-logout"),
        data={"id_token_hint": oidc_tokens.id_token, "client_id": public_application.client_id},
    )
    assert rsp.status_code == 400
    assert is_logged_in(logged_in_client)


@pytest.mark.django_db(databases="__all__")
def test_rp_initiated_logout_public_client_redirect_client_id(
    logged_in_client, oidc_non_confidential_tokens, public_application, rp_settings
):
    rsp = logged_in_client.get(
        reverse("oauth2_provider:rp-initiated-logout"),
        data={
            "id_token_hint": oidc_non_confidential_tokens.id_token,
            "client_id": public_application.client_id,
            "post_logout_redirect_uri": "http://other.org",
        },
    )
    assert rsp.status_code == 302
    assert not is_logged_in(logged_in_client)


@pytest.mark.django_db(databases="__all__")
def test_rp_initiated_logout_public_client_strict_redirect_client_id(
    logged_in_client, oidc_non_confidential_tokens, public_application, oauth2_settings
):
    oauth2_settings.update(presets.OIDC_SETTINGS_RP_LOGOUT_STRICT_REDIRECT_URI)
    rsp = logged_in_client.get(
        reverse("oauth2_provider:rp-initiated-logout"),
        data={
            "id_token_hint": oidc_non_confidential_tokens.id_token,
            "client_id": public_application.client_id,
            "post_logout_redirect_uri": "http://other.org",
        },
    )
    assert rsp.status_code == 400
    assert is_logged_in(logged_in_client)


@pytest.mark.django_db(databases="__all__")
def test_rp_initiated_logout_get_client_id(logged_in_client, oidc_tokens, rp_settings):
    rsp = logged_in_client.get(
        reverse("oauth2_provider:rp-initiated-logout"), data={"client_id": oidc_tokens.application.client_id}
    )
    assert rsp.status_code == 200
    assert is_logged_in(logged_in_client)


@pytest.mark.django_db(databases="__all__")
def test_rp_initiated_logout_post(logged_in_client, oidc_tokens, rp_settings):
    form_data = {
        "client_id": oidc_tokens.application.client_id,
    }
    rsp = logged_in_client.post(reverse("oauth2_provider:rp-initiated-logout"), form_data)
    assert rsp.status_code == 400
    assert is_logged_in(logged_in_client)


@pytest.mark.django_db(databases="__all__")
def test_rp_initiated_logout_post_allowed(logged_in_client, oidc_tokens, rp_settings):
    form_data = {"client_id": oidc_tokens.application.client_id, "allow": True}
    rsp = logged_in_client.post(reverse("oauth2_provider:rp-initiated-logout"), form_data)
    assert rsp.status_code == 302
    assert rsp["Location"] == "http://testserver/"
    assert not is_logged_in(logged_in_client)


@pytest.mark.django_db(databases="__all__")
def test_rp_initiated_logout_post_no_session(client, oidc_tokens, rp_settings):
    form_data = {"client_id": oidc_tokens.application.client_id, "allow": True}
    rsp = client.post(reverse("oauth2_provider:rp-initiated-logout"), form_data)
    assert rsp.status_code == 302
    assert rsp["Location"] == "http://testserver/"
    assert not is_logged_in(client)


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RP_LOGOUT)
def test_rp_initiated_logout_expired_tokens_accept(logged_in_client, application, expired_id_token):
    # Accepting expired (but otherwise valid and signed by us) tokens is enabled. Logout should go through.
    rsp = logged_in_client.get(
        reverse("oauth2_provider:rp-initiated-logout"),
        data={
            "id_token_hint": expired_id_token,
            "client_id": application.client_id,
        },
    )
    assert rsp.status_code == 302
    assert not is_logged_in(logged_in_client)


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RP_LOGOUT_DENY_EXPIRED)
def test_rp_initiated_logout_expired_tokens_deny(logged_in_client, application, expired_id_token):
    # Expired tokens should not be accepted by default.
    rsp = logged_in_client.get(
        reverse("oauth2_provider:rp-initiated-logout"),
        data={
            "id_token_hint": expired_id_token,
            "client_id": application.client_id,
        },
    )
    assert rsp.status_code == 400
    assert is_logged_in(logged_in_client)


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RP_LOGOUT)
def test_load_id_token_accept_expired(expired_id_token):
    id_token, _ = _load_id_token(expired_id_token)
    assert isinstance(id_token, get_id_token_model())


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RP_LOGOUT)
def test_load_id_token_wrong_aud(id_token_wrong_aud):
    id_token, claims = _load_id_token(id_token_wrong_aud)
    assert id_token is None
    assert claims is None


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RP_LOGOUT_DENY_EXPIRED)
def test_load_id_token_deny_expired(expired_id_token):
    id_token, claims = _load_id_token(expired_id_token)
    assert id_token is None
    assert claims is None


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RP_LOGOUT)
def test_validate_claims_wrong_iss(id_token_wrong_iss):
    id_token, claims = _load_id_token(id_token_wrong_iss)
    assert id_token is not None
    assert claims is not None
    assert not _validate_claims(mock_request(), claims)


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RP_LOGOUT)
def test_validate_claims(oidc_tokens):
    id_token, claims = _load_id_token(oidc_tokens.id_token)
    assert claims is not None
    assert _validate_claims(mock_request_for(oidc_tokens.user), claims)


@pytest.mark.django_db(databases="__all__")
@pytest.mark.parametrize("method", ["get", "post"])
def test_userinfo_endpoint(oidc_tokens, client, method):
    auth_header = "Bearer %s" % oidc_tokens.access_token
    rsp = getattr(client, method)(
        reverse("oauth2_provider:user-info"),
        HTTP_AUTHORIZATION=auth_header,
    )
    data = rsp.json()
    assert "sub" in data
    assert data["sub"] == str(oidc_tokens.user.pk)


@pytest.mark.django_db(databases="__all__")
def test_userinfo_endpoint_bad_token(oidc_tokens, client):
    # No access token
    rsp = client.get(reverse("oauth2_provider:user-info"))
    assert rsp.status_code == 401
    # Bad access token
    rsp = client.get(
        reverse("oauth2_provider:user-info"),
        HTTP_AUTHORIZATION="Bearer not-a-real-token",
    )
    assert rsp.status_code == 401


@pytest.mark.django_db(databases="__all__")
def test_token_deletion_on_logout(oidc_tokens, logged_in_client, rp_settings):
    AccessToken = get_access_token_model()
    IDToken = get_id_token_model()
    RefreshToken = get_refresh_token_model()
    assert AccessToken.objects.count() == 1
    assert IDToken.objects.count() == 1
    assert RefreshToken.objects.count() == 1
    rsp = logged_in_client.get(
        reverse("oauth2_provider:rp-initiated-logout"),
        data={
            "id_token_hint": oidc_tokens.id_token,
            "client_id": oidc_tokens.application.client_id,
        },
    )
    assert rsp.status_code == 302
    assert not is_logged_in(logged_in_client)
    # Check that all tokens have either been deleted or expired.
    assert all([token.is_expired() for token in AccessToken.objects.all()])
    assert all([token.is_expired() for token in IDToken.objects.all()])
    assert all([token.revoked <= timezone.now() for token in RefreshToken.objects.all()])


@pytest.mark.django_db(databases="__all__")
def test_token_deletion_on_logout_without_op_session_get(oidc_tokens, client, rp_settings):
    AccessToken = get_access_token_model()
    IDToken = get_id_token_model()
    RefreshToken = get_refresh_token_model()
    assert AccessToken.objects.count() == 1
    assert IDToken.objects.count() == 1
    assert RefreshToken.objects.count() == 1

    rsp = client.get(
        reverse("oauth2_provider:rp-initiated-logout"),
        data={
            "id_token_hint": oidc_tokens.id_token,
            "client_id": oidc_tokens.application.client_id,
        },
    )
    assert rsp.status_code == 302
    assert not is_logged_in(client)
    # Check that all tokens are active.
    assert AccessToken.objects.count() == 0
    assert IDToken.objects.count() == 0
    assert RefreshToken.objects.count() == 1

    with pytest.raises(AccessToken.DoesNotExist):
        AccessToken.objects.get()

    with pytest.raises(IDToken.DoesNotExist):
        IDToken.objects.get()

    refresh_token = RefreshToken.objects.get()
    assert refresh_token.revoked is not None


@pytest.mark.django_db(databases="__all__")
def test_token_deletion_on_logout_without_op_session_post(oidc_tokens, client, rp_settings):
    AccessToken = get_access_token_model()
    IDToken = get_id_token_model()
    RefreshToken = get_refresh_token_model()
    assert AccessToken.objects.count() == 1
    assert IDToken.objects.count() == 1
    assert RefreshToken.objects.count() == 1

    rsp = client.post(
        reverse("oauth2_provider:rp-initiated-logout"),
        data={
            "id_token_hint": oidc_tokens.id_token,
            "client_id": oidc_tokens.application.client_id,
            "allow": True,
        },
    )
    assertRedirects(rsp, "http://testserver/", fetch_redirect_response=False)
    assert not is_logged_in(client)
    # Check that all tokens have either been deleted or expired.
    assert all(token.is_expired() for token in AccessToken.objects.all())
    assert all(token.is_expired() for token in IDToken.objects.all())
    assert all(token.revoked <= timezone.now() for token in RefreshToken.objects.all())


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RP_LOGOUT_KEEP_TOKENS)
def test_token_deletion_on_logout_disabled(oidc_tokens, logged_in_client, rp_settings):
    rp_settings.OIDC_RP_INITIATED_LOGOUT_DELETE_TOKENS = False

    AccessToken = get_access_token_model()
    IDToken = get_id_token_model()
    RefreshToken = get_refresh_token_model()
    assert AccessToken.objects.count() == 1
    assert IDToken.objects.count() == 1
    assert RefreshToken.objects.count() == 1
    rsp = logged_in_client.get(
        reverse("oauth2_provider:rp-initiated-logout"),
        data={
            "id_token_hint": oidc_tokens.id_token,
            "client_id": oidc_tokens.application.client_id,
        },
    )
    assert rsp.status_code == 302
    assert not is_logged_in(logged_in_client)
    # Check that the tokens have not been expired or deleted.
    assert AccessToken.objects.count() == 1
    assert not any([token.is_expired() for token in AccessToken.objects.all()])
    assert IDToken.objects.count() == 1
    assert not any([token.is_expired() for token in IDToken.objects.all()])
    assert RefreshToken.objects.count() == 1
    assert not any([token.revoked is not None for token in RefreshToken.objects.all()])


EXAMPLE_EMAIL = "example.email@example.com"


def claim_user_email(request):
    return EXAMPLE_EMAIL


@pytest.mark.django_db(databases="__all__")
def test_userinfo_endpoint_custom_claims_callable(oidc_tokens, client, oauth2_settings):
    class CustomValidator(OAuth2Validator):
        oidc_claim_scope = None

        def get_additional_claims(self):
            return {
                "username": claim_user_email,
                "email": claim_user_email,
            }

    oidc_tokens.oauth2_settings.OAUTH2_VALIDATOR_CLASS = CustomValidator
    auth_header = "Bearer %s" % oidc_tokens.access_token
    rsp = client.get(
        reverse("oauth2_provider:user-info"),
        HTTP_AUTHORIZATION=auth_header,
    )
    data = rsp.json()
    assert "sub" in data
    assert data["sub"] == str(oidc_tokens.user.pk)

    assert "username" in data
    assert data["username"] == EXAMPLE_EMAIL

    assert "email" in data
    assert data["email"] == EXAMPLE_EMAIL


@pytest.mark.django_db(databases="__all__")
def test_userinfo_endpoint_custom_claims_email_scope_callable(
    oidc_email_scope_tokens, client, oauth2_settings
):
    class CustomValidator(OAuth2Validator):
        def get_additional_claims(self):
            return {
                "username": claim_user_email,
                "email": claim_user_email,
            }

    oidc_email_scope_tokens.oauth2_settings.OAUTH2_VALIDATOR_CLASS = CustomValidator
    auth_header = "Bearer %s" % oidc_email_scope_tokens.access_token
    rsp = client.get(
        reverse("oauth2_provider:user-info"),
        HTTP_AUTHORIZATION=auth_header,
    )
    data = rsp.json()
    assert "sub" in data
    assert data["sub"] == str(oidc_email_scope_tokens.user.pk)

    assert "username" not in data

    assert "email" in data
    assert data["email"] == EXAMPLE_EMAIL


@pytest.mark.django_db(databases="__all__")
def test_userinfo_endpoint_custom_claims_plain(oidc_tokens, client, oauth2_settings):
    class CustomValidator(OAuth2Validator):
        oidc_claim_scope = None

        def get_additional_claims(self, request):
            return {
                "username": EXAMPLE_EMAIL,
                "email": EXAMPLE_EMAIL,
            }

    oidc_tokens.oauth2_settings.OAUTH2_VALIDATOR_CLASS = CustomValidator
    auth_header = "Bearer %s" % oidc_tokens.access_token
    rsp = client.get(
        reverse("oauth2_provider:user-info"),
        HTTP_AUTHORIZATION=auth_header,
    )
    data = rsp.json()
    assert "sub" in data
    assert data["sub"] == str(oidc_tokens.user.pk)

    assert "username" in data
    assert data["username"] == EXAMPLE_EMAIL

    assert "email" in data
    assert data["email"] == EXAMPLE_EMAIL


@pytest.mark.django_db(databases="__all__")
def test_userinfo_endpoint_custom_claims_email_scopeplain(oidc_email_scope_tokens, client, oauth2_settings):
    class CustomValidator(OAuth2Validator):
        def get_additional_claims(self, request):
            return {
                "username": EXAMPLE_EMAIL,
                "email": EXAMPLE_EMAIL,
            }

    oidc_email_scope_tokens.oauth2_settings.OAUTH2_VALIDATOR_CLASS = CustomValidator
    auth_header = "Bearer %s" % oidc_email_scope_tokens.access_token
    rsp = client.get(
        reverse("oauth2_provider:user-info"),
        HTTP_AUTHORIZATION=auth_header,
    )
    data = rsp.json()
    assert "sub" in data
    assert data["sub"] == str(oidc_email_scope_tokens.user.pk)

    assert "username" not in data

    assert "email" in data
    assert data["email"] == EXAMPLE_EMAIL


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestOAuthServerMetadataView(TestCase):
    def test_get_oauth_server_metadata(self):
        expected_response = {
            "issuer": "http://localhost/o",
            "authorization_endpoint": "http://localhost/o/authorize/",
            "token_endpoint": "http://localhost/o/token/",
            "revocation_endpoint": "http://localhost/o/revoke_token/",
            "introspection_endpoint": "http://localhost/o/introspect/",
            "response_types_supported": ["code", "token"],
            "grant_types_supported": [
                "authorization_code",
                "implicit",
                "password",
                "client_credentials",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
            "scopes_supported": ["openid", "read", "write"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "revocation_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "introspection_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": ["plain", "S256"],
            "jwks_uri": "http://localhost/o/.well-known/jwks.json",
        }
        response = self.client.get(reverse("oauth2_provider:oauth-server-metadata"))
        self.assertEqual(response.status_code, 200)
        assert response.json() == expected_response

    def test_get_oauth_server_metadata_without_issuer_url(self):
        self.oauth2_settings.OIDC_ISS_ENDPOINT = None
        expected_response = {
            "issuer": "http://testserver/o",
            "authorization_endpoint": "http://testserver/o/authorize/",
            "token_endpoint": "http://testserver/o/token/",
            "revocation_endpoint": "http://testserver/o/revoke_token/",
            "introspection_endpoint": "http://testserver/o/introspect/",
            "response_types_supported": ["code", "token"],
            "grant_types_supported": [
                "authorization_code",
                "implicit",
                "password",
                "client_credentials",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
            "scopes_supported": ["openid", "read", "write"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "revocation_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "introspection_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": ["plain", "S256"],
            "jwks_uri": "http://testserver/o/.well-known/jwks.json",
        }
        response = self.client.get(reverse("oauth2_provider:oauth-server-metadata"))
        self.assertEqual(response.status_code, 200)
        assert response.json() == expected_response

    def test_get_oauth_server_metadata_no_rsa_key(self):
        self.oauth2_settings.OIDC_RSA_PRIVATE_KEY = None
        response = self.client.get(reverse("oauth2_provider:oauth-server-metadata"))
        self.assertEqual(response.status_code, 200)
        assert "jwks_uri" not in response.json()

    def test_get_oauth_server_metadata_cors_header(self):
        response = self.client.get(reverse("oauth2_provider:oauth-server-metadata"))
        self.assertEqual(response.status_code, 200)
        assert response["Access-Control-Allow-Origin"] == "*"

    def test_get_oauth_server_metadata_oidc_disabled(self):
        """RFC 8414 metadata endpoint is available even when OIDC is disabled."""
        self.oauth2_settings.OIDC_ENABLED = False
        response = self.client.get(reverse("oauth2_provider:oauth-server-metadata"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        assert "issuer" in data
        assert "authorization_endpoint" in data
        assert "token_endpoint" in data
        assert "jwks_uri" not in data

    @override_settings(ROOT_URLCONF="tests.urls_split_metadata")
    def test_get_oauth_server_metadata_root_mounted_with_prefixed_endpoints(self):
        """Documented deployment: metadata at the root, endpoints under /o/.

        The issuer is derived from the root-mounted metadata URL while the
        endpoint URLs keep their /o/ prefix from ``reverse()``.
        """
        self.oauth2_settings.OIDC_ISS_ENDPOINT = None
        response = self.client.get("/.well-known/oauth-authorization-server")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        assert data["issuer"] == "http://testserver"
        assert data["authorization_endpoint"] == "http://testserver/o/authorize/"
        assert data["token_endpoint"] == "http://testserver/o/token/"
        assert data["revocation_endpoint"] == "http://testserver/o/revoke_token/"
        assert data["introspection_endpoint"] == "http://testserver/o/introspect/"
        assert data["jwks_uri"] == "http://testserver/o/.well-known/jwks.json"

    @override_settings(ROOT_URLCONF="tests.urls_split_metadata")
    def test_get_oauth_server_metadata_rfc8414_path_component_issuer(self):
        """RFC 8414 path-component form: /.well-known/.../<issuer_path>.

        The issuer path after the well-known marker is preserved in the derived
        issuer, per RFC 8414 for issuers with a path component.
        """
        self.oauth2_settings.OIDC_ISS_ENDPOINT = None
        response = self.client.get("/.well-known/oauth-authorization-server/tenant1")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        assert data["issuer"] == "http://testserver/tenant1"
        # Endpoint URLs still come from where the toolkit is mounted (/o/).
        assert data["authorization_endpoint"] == "http://testserver/o/authorize/"
        assert data["token_endpoint"] == "http://testserver/o/token/"

    @override_settings(ROOT_URLCONF="tests.urls_split_metadata")
    def test_get_oauth_server_metadata_all_discovery_urls_for_prefixed_issuer(self):
        """An issuer under a path (http://host/o) is discoverable at all three URLs.

        1. OIDC discovery (issuer + /.well-known/openid-configuration),
        2. strict RFC 8414 (well-known at the root, issuer path appended), and
        3. the pragmatic fallback (issuer + /.well-known/oauth-authorization-server)
        must all resolve and agree on the issuer.
        """
        self.oauth2_settings.OIDC_ISS_ENDPOINT = None
        for url in [
            "/o/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server/o",
            "/o/.well-known/oauth-authorization-server",
        ]:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            assert response.json()["issuer"] == "http://testserver/o", url

    @override_settings(ROOT_URLCONF="tests.urls_metadata_only")
    def test_get_oauth_server_metadata_omits_unregistered_endpoints(self):
        """Endpoints whose URL name is not registered are omitted, not 500s."""
        response = self.client.get(reverse("oauth2_provider:oauth-server-metadata"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        # None of the endpoint routes exist in this URLconf, so they are dropped
        # along with the capability fields that describe them.
        for key in [
            "authorization_endpoint",
            "token_endpoint",
            "revocation_endpoint",
            "introspection_endpoint",
            "code_challenge_methods_supported",
            "token_endpoint_auth_methods_supported",
            "revocation_endpoint_auth_methods_supported",
            "introspection_endpoint_auth_methods_supported",
            "jwks_uri",
        ]:
            assert key not in data
        # Static metadata is still present.
        assert "issuer" in data
        assert data["scopes_supported"] == ["openid", "read", "write"]


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestOAuthProtectedResourceMetadataView(TestCase):
    def test_get_protected_resource_metadata(self):
        expected_response = {
            "resource": "http://testserver/o",
            "authorization_servers": ["http://localhost/o"],
            "scopes_supported": ["openid", "read", "write"],
            "bearer_methods_supported": ["header"],
        }
        response = self.client.get(reverse("oauth2_provider:oauth-resource-metadata"))
        self.assertEqual(response.status_code, 200)
        assert response.json() == expected_response

    def test_get_protected_resource_metadata_derives_authorization_server(self):
        """Without OIDC_ISS_ENDPOINT the AS issuer is derived from the RFC 8414 route."""
        self.oauth2_settings.OIDC_ISS_ENDPOINT = None
        response = self.client.get(reverse("oauth2_provider:oauth-resource-metadata"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        assert data["resource"] == "http://testserver/o"
        assert data["authorization_servers"] == ["http://testserver/o"]

    def test_get_protected_resource_metadata_explicit_settings(self):
        self.oauth2_settings.OAUTH2_PROTECTED_RESOURCE_IDENTIFIER = "https://api.example.com"
        self.oauth2_settings.OAUTH2_PROTECTED_RESOURCE_AUTHORIZATION_SERVERS = ["https://as.example.com"]
        response = self.client.get(reverse("oauth2_provider:oauth-resource-metadata"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        assert data["resource"] == "https://api.example.com"
        assert data["authorization_servers"] == ["https://as.example.com"]

    def test_get_protected_resource_metadata_optional_fields_omitted(self):
        response = self.client.get(reverse("oauth2_provider:oauth-resource-metadata"))
        data = response.json()
        for key in ["resource_name", "resource_documentation", "resource_policy_uri", "resource_tos_uri"]:
            assert key not in data

    def test_get_protected_resource_metadata_optional_fields_present(self):
        self.oauth2_settings.OAUTH2_PROTECTED_RESOURCE_NAME = "Example API"
        self.oauth2_settings.OAUTH2_PROTECTED_RESOURCE_DOCUMENTATION = "https://docs.example.com"
        self.oauth2_settings.OAUTH2_PROTECTED_RESOURCE_POLICY_URI = "https://example.com/policy"
        self.oauth2_settings.OAUTH2_PROTECTED_RESOURCE_TOS_URI = "https://example.com/tos"
        response = self.client.get(reverse("oauth2_provider:oauth-resource-metadata"))
        data = response.json()
        assert data["resource_name"] == "Example API"
        assert data["resource_documentation"] == "https://docs.example.com"
        assert data["resource_policy_uri"] == "https://example.com/policy"
        assert data["resource_tos_uri"] == "https://example.com/tos"

    def test_get_protected_resource_metadata_custom_bearer_methods(self):
        self.oauth2_settings.OAUTH2_PROTECTED_RESOURCE_BEARER_METHODS_SUPPORTED = ["header", "body"]
        response = self.client.get(reverse("oauth2_provider:oauth-resource-metadata"))
        assert response.json()["bearer_methods_supported"] == ["header", "body"]

    def test_get_protected_resource_metadata_cors_header(self):
        response = self.client.get(reverse("oauth2_provider:oauth-resource-metadata"))
        self.assertEqual(response.status_code, 200)
        assert response["Access-Control-Allow-Origin"] == "*"

    def test_get_protected_resource_metadata_available_when_oidc_disabled(self):
        self.oauth2_settings.OIDC_ENABLED = False
        response = self.client.get(reverse("oauth2_provider:oauth-resource-metadata"))
        self.assertEqual(response.status_code, 200)
        assert "resource" in response.json()

    @override_settings(ROOT_URLCONF="tests.urls_split_metadata")
    def test_get_protected_resource_metadata_rfc9728_path_component(self):
        """RFC 9728 path-component form: /.well-known/oauth-protected-resource/<path>."""
        self.oauth2_settings.OIDC_ISS_ENDPOINT = None
        response = self.client.get("/.well-known/oauth-protected-resource/tenant1")
        self.assertEqual(response.status_code, 200)
        assert response.json()["resource"] == "http://testserver/tenant1"
