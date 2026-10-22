"""
Tests for Dynamic Client Registration views (RFC 7591 / RFC 7592).
"""

import hashlib
import json
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from jwcrypto import jwk, jwt

from oauth2_provider.models import get_access_token_model, get_application_model

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header, post_form


UserModel = get_user_model()
Application = get_application_model()
AccessToken = get_access_token_model()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _register_url():
    return reverse("oauth2_provider:dcr-register")


def _post_register(client, data, **kwargs):
    return client.post(
        _register_url(),
        data=json.dumps(data),
        content_type="application/json",
        **kwargs,
    )


def _management_url(client_id):
    return reverse("oauth2_provider:dcr-register-management", kwargs={"client_id": client_id})


def _bearer(token):
    return {"HTTP_AUTHORIZATION": f"Bearer {token}"}


def _enable_rs256(oauth2_settings):
    """Make the server an OpenID Provider able to sign RS256 ID Tokens."""
    oauth2_settings.OIDC_ENABLED = True
    oauth2_settings.OIDC_RSA_PRIVATE_KEY = presets.OIDC_SETTINGS_RW["OIDC_RSA_PRIVATE_KEY"]


# ---------------------------------------------------------------------------
# RFC 7591 — Registration endpoint tests
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.DCR_SETTINGS)
class TestDynamicClientRegistration(TestCase):
    def setUp(self):
        self.user = UserModel.objects.create_user("dcr_user", "dcr@example.com", "pass")

    # -- success cases -------------------------------------------------------

    def test_register_minimal_authenticated(self):
        """POST with minimal valid metadata by an authenticated user → 201."""
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201
        body = response.json()
        assert "client_id" in body
        assert "registration_access_token" in body
        assert "registration_client_uri" in body
        assert body["grant_types"] == ["authorization_code", "refresh_token"]
        app = Application.objects.get(client_id=body["client_id"])
        assert app.registration_source == Application.RegistrationSource.DCR

    def test_registered_client_can_introspect(self):
        """#1451: a DCR client keeps the can_introspect default, so a confidential one
        can introspect with its own credentials. The capability is not client
        metadata: a registration request can neither set nor clear it."""
        from datetime import timedelta

        from django.utils import timezone

        self.client.force_login(self.user)
        data = {
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_basic",
            "can_introspect": False,
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201
        body = response.json()
        assert "can_introspect" not in body
        app = Application.objects.get(client_id=body["client_id"])
        assert app.client_type == Application.CLIENT_CONFIDENTIAL
        assert app.can_introspect is True

        token = AccessToken.objects.create(
            token="dcr-introspected-token",
            application=app,
            expires=timezone.now() + timedelta(hours=1),
            scope="read",
        )
        self.client.logout()
        response = post_form(
            self.client,
            reverse("oauth2_provider:introspect"),
            {"token": token.token},
            **get_basic_auth_header(body["client_id"], body["client_secret"]),
        )
        assert response.status_code == 200, response.content
        assert response.json()["active"] is True

    def test_manually_created_application_registration_source_is_manual(self):
        """Applications created outside DCR default to registration_source="manual"."""
        app = Application.objects.create(
            name="Manual App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="https://example.com/cb",
        )
        assert app.registration_source == Application.RegistrationSource.MANUAL

    def test_registration_source_is_readonly_in_admin(self):
        """registration_source is a security boundary and must be read-only in the admin.

        The RFC 7592 management endpoint only operates on applications whose
        registration_source is "dcr"; an editable admin field would let it be
        flipped on a manually provisioned client and defeat that protection.
        """
        from django.contrib.admin.sites import AdminSite

        from oauth2_provider.authorization_server.admin import ApplicationAdmin

        model_admin = ApplicationAdmin(Application, AdminSite())
        assert "registration_source" in model_admin.get_readonly_fields(request=None)

    def test_register_with_client_name(self):
        """client_name is mapped to Application.name."""
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "client_name": "My Test App",
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201
        body = response.json()
        assert body["client_name"] == "My Test App"
        app = Application.objects.get(client_id=body["client_id"])
        assert app.name == "My Test App"

    def test_register_public_client(self):
        """token_endpoint_auth_method=none → client_type=public."""
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "none",
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201
        body = response.json()
        assert body["token_endpoint_auth_method"] == "none"
        # No secret is issued, so there is no expiry to report either.
        assert "client_secret" not in body
        assert "client_secret_expires_at" not in body
        app = Application.objects.get(client_id=body["client_id"])
        assert app.client_type == Application.CLIENT_PUBLIC
        assert body["client_id_issued_at"] == int(app.created.timestamp())

    def test_register_confidential_client(self):
        """token_endpoint_auth_method=client_secret_basic → client_type=confidential."""
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "client_secret_basic",
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201
        body = response.json()
        assert body["token_endpoint_auth_method"] == "client_secret_basic"
        assert "client_secret" in body
        # RFC 7591 section 3.2.1: REQUIRED alongside client_secret; 0 = never expires.
        assert body["client_secret_expires_at"] == 0
        app = Application.objects.get(client_id=body["client_id"])
        assert app.client_type == Application.CLIENT_CONFIDENTIAL
        assert body["client_id_issued_at"] == int(app.created.timestamp())

    # -- id_token_signed_response_alg (OIDC Dynamic Client Registration 1.0 §2)

    def test_register_defaults_to_rs256_when_server_can_sign(self):
        """Omitted id_token_signed_response_alg → RS256 once the server has an RSA key.

        Regression for #1853: a registered client is provisioned to receive ID
        Tokens without any manual step, and the response reports the value the
        server provisioned (OIDC Registration 1.0 §3.2).
        """
        _enable_rs256(self.oauth2_settings)
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "none",
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201
        body = response.json()
        assert body["id_token_signed_response_alg"] == "RS256"
        app = Application.objects.get(client_id=body["client_id"])
        assert app.algorithm == Application.RS256_ALGORITHM

    def test_register_explicit_rs256_is_honoured(self):
        _enable_rs256(self.oauth2_settings)
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "id_token_signed_response_alg": "RS256",
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201
        assert response.json()["id_token_signed_response_alg"] == "RS256"

    def test_register_null_id_token_alg_means_default(self):
        """JSON null is not a value the spec defines; it counts as omitted."""
        _enable_rs256(self.oauth2_settings)
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "id_token_signed_response_alg": None,
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201
        assert response.json()["id_token_signed_response_alg"] == "RS256"

    def test_register_with_oidc_disabled_leaves_algorithm_unset(self):
        """A key alone is not enough: with OIDC off no ID Token is ever issued."""
        self.oauth2_settings.OIDC_RSA_PRIVATE_KEY = presets.OIDC_SETTINGS_RW["OIDC_RSA_PRIVATE_KEY"]
        assert not self.oauth2_settings.OIDC_ENABLED
        self.client.force_login(self.user)
        data = {"redirect_uris": ["https://example.com/cb"], "grant_types": ["authorization_code"]}
        response = _post_register(self.client, data)
        assert response.status_code == 201
        body = response.json()
        assert "id_token_signed_response_alg" not in body
        assert Application.objects.get(client_id=body["client_id"]).algorithm == Application.NO_ALGORITHM

    def test_register_without_server_key_leaves_algorithm_unset(self):
        """No RSA key → registration succeeds with no signing algorithm, none reported."""
        assert not self.oauth2_settings.OIDC_RSA_PRIVATE_KEY
        self.client.force_login(self.user)
        data = {"redirect_uris": ["https://example.com/cb"], "grant_types": ["authorization_code"]}
        response = _post_register(self.client, data)
        assert response.status_code == 201
        body = response.json()
        assert "id_token_signed_response_alg" not in body
        app = Application.objects.get(client_id=body["client_id"])
        assert app.algorithm == Application.NO_ALGORITHM

    def test_register_explicit_rs256_without_server_key_is_400(self):
        """A requested algorithm the server cannot sign with is refused, not substituted."""
        assert not self.oauth2_settings.OIDC_RSA_PRIVATE_KEY
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "id_token_signed_response_alg": "RS256",
        }
        response = _post_register(self.client, data)
        assert response.status_code == 400
        body = response.json()
        assert body["error"] == "invalid_client_metadata"
        assert "id_token_signed_response_alg" in body["error_description"]

    def test_register_unsupported_id_token_alg_is_400(self):
        """Only RS256 is implemented: HS256 would sign with the hashed-at-rest secret."""
        _enable_rs256(self.oauth2_settings)
        self.client.force_login(self.user)
        for requested in ("HS256", "ES256", "none", "", 256):
            with self.subTest(requested=requested):
                data = {
                    "redirect_uris": ["https://example.com/cb"],
                    "grant_types": ["authorization_code"],
                    "id_token_signed_response_alg": requested,
                }
                response = _post_register(self.client, data)
                assert response.status_code == 400
                body = response.json()
                assert body["error"] == "invalid_client_metadata"
                assert "id_token_signed_response_alg" in body["error_description"]

    def test_register_hs256_is_400_for_every_client(self):
        """HS256 is not offered at registration, even to a client_secret_jwt client.

        HS256 would make the client secret the ID Token signing key, and RS256
        is the algorithm OpenID Connect Core 1.0 section 15.1 requires of an
        OpenID Provider that signs its ID Tokens. The refusal holds whatever the
        server can sign with; its advice follows what the server can do.
        """
        servers = (
            ("rs256-key", True, presets.OIDC_SETTINGS_RW["OIDC_RSA_PRIVATE_KEY"]),
            ("no-rsa-key", True, ""),
            ("oidc-disabled", False, ""),
        )
        clients = (
            {"token_endpoint_auth_method": "client_secret_jwt"},
            {"token_endpoint_auth_method": "client_secret_basic"},
            {"token_endpoint_auth_method": "client_secret_post"},
            {"token_endpoint_auth_method": "private_key_jwt", "jwks": _public_jwks()},
            {"token_endpoint_auth_method": "none"},
            {"token_endpoint_auth_method": "client_secret_jwt", "grant_types": ["implicit"]},
        )
        self.client.force_login(self.user)
        for server, oidc_enabled, rsa_key in servers:
            self.oauth2_settings.OIDC_ENABLED = oidc_enabled
            self.oauth2_settings.OIDC_RSA_PRIVATE_KEY = rsa_key
            for metadata in clients:
                with self.subTest(server=server, metadata=metadata):
                    data = {
                        "redirect_uris": ["https://example.com/cb"],
                        "grant_types": ["authorization_code"],
                        "id_token_signed_response_alg": "HS256",
                        **metadata,
                    }
                    response = _post_register(self.client, data)
                    assert response.status_code == 400, response.content
                    body = response.json()
                    assert body["error"] == "invalid_client_metadata"
                    description = body["error_description"]
                    assert description.startswith("Unsupported id_token_signed_response_alg: 'HS256'.")
                    assert "not offered to self-registered clients" in description
                    if server == "rs256-key":
                        assert "use RS256" in description
                    else:
                        assert "use RS256" not in description
                        assert "omit id_token_signed_response_alg" in description
        assert not Application.objects.exists()

    def test_register_authorization_code_with_refresh_token(self):
        """[authorization_code, refresh_token] → maps cleanly, refresh_token ignored."""
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code", "refresh_token"],
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201
        body = response.json()
        app = Application.objects.get(client_id=body["client_id"])
        assert app.authorization_grant_type == Application.GRANT_AUTHORIZATION_CODE

    def test_register_client_credentials(self):
        """client_credentials grant type."""
        self.client.force_login(self.user)
        data = {
            "grant_types": ["client_credentials"],
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201
        body = response.json()
        app = Application.objects.get(client_id=body["client_id"])
        assert app.authorization_grant_type == Application.GRANT_CLIENT_CREDENTIALS

    def test_register_jwt_bearer(self):
        """jwt-bearer (RFC 7523) grant type round-trips through registration."""
        self.client.force_login(self.user)
        data = {
            "grant_types": ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201
        body = response.json()
        app = Application.objects.get(client_id=body["client_id"])
        assert app.authorization_grant_type == Application.GRANT_JWT_BEARER
        assert body["grant_types"] == ["urn:ietf:params:oauth:grant-type:jwt-bearer"]

    def test_response_includes_registration_token_and_uri(self):
        """Registration response includes registration_access_token and registration_client_uri."""
        self.client.force_login(self.user)
        data = {"redirect_uris": ["https://example.com/cb"], "grant_types": ["authorization_code"]}
        response = _post_register(self.client, data)
        assert response.status_code == 201
        body = response.json()
        assert body["registration_access_token"]
        assert body["registration_client_uri"].endswith(f"/o/register/{body['client_id']}/")

    # -- auth failures -------------------------------------------------------

    def test_register_unauthenticated_is_401(self):
        """Unauthenticated POST when IsAuthenticatedDCRPermission is active → 401."""
        data = {"redirect_uris": ["https://example.com/cb"], "grant_types": ["authorization_code"]}
        response = _post_register(self.client, data)
        assert response.status_code == 401
        assert response.json()["error"] == "access_denied"
        # RFC 6750 §3: 401 must carry a WWW-Authenticate: Bearer challenge;
        # no error code since no Bearer credentials were attempted (§3.1).
        assert response["WWW-Authenticate"] == "Bearer"

    # -- validation failures -------------------------------------------------

    def test_register_hybrid_client(self):
        """#1895: authorization_code + implicit registers an OpenID Connect hybrid client.

        The hybrid client's response types need both grants (OpenID Connect
        Registration 1.0 section 2), which the toolkit's single hybrid grant
        serves. The response reports them in RFC 7591 terms.
        """
        self.oauth2_settings.OIDC_ENABLED = True
        self.client.force_login(self.user)
        cases = (
            (["authorization_code", "implicit"], None),
            (["authorization_code", "implicit", "refresh_token"], None),
            (["implicit", "authorization_code"], ["code id_token"]),
            (["authorization_code", "implicit", "refresh_token"], ["code token"]),
            (["authorization_code", "implicit"], ["code id_token token"]),
            (["authorization_code", "implicit"], ["code id_token", "code token", "code id_token token"]),
            # Response type values are unordered space-delimited lists.
            (["authorization_code", "implicit"], ["id_token code"]),
        )
        for grant_types, response_types in cases:
            with self.subTest(grant_types=grant_types, response_types=response_types):
                data = {"redirect_uris": ["https://example.com/cb"], "grant_types": grant_types}
                if response_types is not None:
                    data["response_types"] = response_types
                response = _post_register(self.client, data)
                assert response.status_code == 201, response.content
                body = response.json()
                assert body["grant_types"] == ["authorization_code", "implicit", "refresh_token"]
                # The response reports what the client can use, canonically ordered, also
                # when it sent no response_types (RFC 7591 section 3.2.1).
                assert body["response_types"] == ["code id_token", "code token", "code id_token token"]
                app = Application.objects.get(client_id=body["client_id"])
                assert app.authorization_grant_type == Application.GRANT_OPENID_HYBRID

    def test_register_hybrid_missing_redirect_uris_is_400_with_rfc_terms(self):
        """A hybrid client needs redirect_uris; the refusal names RFC 7591 grant types."""
        self.oauth2_settings.OIDC_ENABLED = True
        self.client.force_login(self.user)
        response = _post_register(self.client, {"grant_types": ["authorization_code", "implicit"]})
        assert response.status_code == 400
        body = response.json()
        assert body["error"] == "invalid_client_metadata"
        assert "redirect_uris" in body["error_description"]
        assert "openid-hybrid" not in body["error_description"]

    def test_register_hybrid_without_hybrid_response_types_is_400(self):
        """The hybrid pair is refused when the server serves no hybrid response type.

        Without OpenID Connect the server dispatches none of them, so the client
        could not use the grants it registers (RFC 7591 section 2.1); the same
        holds when they are left out of OIDC_RESPONSE_TYPES_SUPPORTED.
        """
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code", "implicit"],
        }
        for oidc_enabled in (False, True):
            with self.subTest(oidc_enabled=oidc_enabled):
                self.oauth2_settings.OIDC_ENABLED = oidc_enabled
                if oidc_enabled:
                    self.oauth2_settings.OIDC_RESPONSE_TYPES_SUPPORTED = ["code", "id_token"]
                response = _post_register(self.client, data)
                assert response.status_code == 400, response.content
                body = response.json()
                assert body["error"] == "invalid_client_metadata"
                assert "hybrid" in body["error_description"]
                assert "openid-hybrid" not in body["error_description"]
        assert not Application.objects.exists()

    def test_register_multiple_grant_types_is_400(self):
        """Multiple non-refresh_token grant types other than the hybrid pair → 400."""
        self.client.force_login(self.user)
        for grant_types in (
            ["authorization_code", "client_credentials"],
            ["authorization_code", "implicit", "password"],
        ):
            with self.subTest(grant_types=grant_types):
                data = {"redirect_uris": ["https://example.com/cb"], "grant_types": grant_types}
                response = _post_register(self.client, data)
                assert response.status_code == 400
                assert response.json()["error"] == "invalid_client_metadata"

    def test_register_reports_response_types(self):
        """Responses report the response types the registered grant serves here.

        response_types is not stored, so the server provisions these whether or
        not the client sent the field, and the response says so (RFC 7591
        sections 2 and 3.2.1). They are the grant's own response types less
        those the server does not advertise: without OpenID Connect none with
        id_token, and none of the implicit ones once
        COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT refuses them. A grant with no
        authorization endpoint flow reports an explicit empty list, since an
        omitted field means "code".
        """
        self.client.force_login(self.user)
        hybrid = ["code id_token", "code token", "code id_token token"]
        cases = (
            # (OIDC_ENABLED, COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT, grant_types, expected)
            (False, False, ["authorization_code"], ["code"]),
            (False, False, ["implicit"], ["token"]),
            (False, False, ["client_credentials"], []),
            (False, False, ["password"], []),
            (True, False, ["authorization_code"], ["code"]),
            (True, False, ["implicit"], ["id_token", "id_token token", "token"]),
            (True, False, ["authorization_code", "implicit"], hybrid),
            (True, True, ["implicit"], []),
            (True, True, ["authorization_code", "implicit"], hybrid),
        )
        for oidc_enabled, implicit_gate, grant_types, expected in cases:
            with self.subTest(
                oidc_enabled=oidc_enabled, implicit_gate=implicit_gate, grant_types=grant_types
            ):
                self.oauth2_settings.OIDC_ENABLED = oidc_enabled
                self.oauth2_settings.COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT = implicit_gate
                data = {"redirect_uris": ["https://example.com/cb"], "grant_types": grant_types}
                response = _post_register(self.client, data)
                assert response.status_code == 201, response.content
                body = response.json()
                assert body["response_types"] == expected
                response = self.client.get(
                    _management_url(body["client_id"]), **_bearer(body["registration_access_token"])
                )
                assert response.status_code == 200
                assert response.json()["response_types"] == expected

    def test_register_consistent_response_types(self):
        """response_types the registered grant serves are accepted (RFC 7591 section 2.1)."""
        self.oauth2_settings.OIDC_ENABLED = True
        self.client.force_login(self.user)
        cases = (
            (["authorization_code"], ["code"]),
            (["authorization_code", "refresh_token"], ["code"]),
            (["implicit"], ["id_token"]),
            (["implicit"], ["id_token token", "token"]),
            (["client_credentials"], []),
        )
        for grant_types, response_types in cases:
            with self.subTest(grant_types=grant_types, response_types=response_types):
                data = {
                    "redirect_uris": ["https://example.com/cb"],
                    "grant_types": grant_types,
                    "response_types": response_types,
                }
                response = _post_register(self.client, data)
                assert response.status_code == 201, response.content

    def test_register_inconsistent_response_types_is_400(self):
        """RFC 7591 section 2.1: a client cannot register itself into an inconsistent state.

        Each response type must be one the registered grant serves: OpenID
        Connect Registration 1.0 section 2 lists the grant types each needs,
        and a hybrid client's grant does not serve the plain code flow. A
        repeated value is never served either.
        """
        self.oauth2_settings.OIDC_ENABLED = True
        self.client.force_login(self.user)
        cases = (
            (["authorization_code"], ["code id_token"]),
            (["authorization_code"], ["token"]),
            (["implicit"], ["code"]),
            (["authorization_code", "implicit"], ["code"]),
            (["authorization_code", "implicit"], ["code id_token", "id_token"]),
            (["client_credentials"], ["code"]),
            (["authorization_code"], ["code", "magic"]),
            (["authorization_code"], [""]),
            (["authorization_code"], ["code code"]),
            (["implicit"], ["token id_token token"]),
        )
        for grant_types, response_types in cases:
            with self.subTest(grant_types=grant_types, response_types=response_types):
                data = {
                    "redirect_uris": ["https://example.com/cb"],
                    "grant_types": grant_types,
                    "response_types": response_types,
                }
                response = _post_register(self.client, data)
                assert response.status_code == 400, response.content
                body = response.json()
                assert body["error"] == "invalid_client_metadata"
                description = body["error_description"]
                assert description.startswith(f"response_type {response_types[-1]!r} ")
                if len(set(response_types[-1].split())) != len(response_types[-1].split()):
                    assert description.endswith("repeats a value")
                else:
                    assert "is inconsistent with grant_types [" in description
                # Refusals speak RFC 7591, never DOT's internal grant constants.
                assert "openid-hybrid" not in body["error_description"]
                assert "authorization-code" not in body["error_description"]

    def test_register_response_types_the_server_does_not_serve_is_400(self):
        """A response type the grant would serve but this server does not is refused.

        Without OpenID Connect no response type with id_token is dispatched, and
        COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT makes the authorization endpoint
        refuse the implicit ones, as discovery reflects.
        """
        self.client.force_login(self.user)
        cases = (
            (False, False, ["id_token"]),
            (False, False, ["id_token token"]),
            (True, True, ["token"]),
            (True, True, ["id_token"]),
        )
        for oidc_enabled, implicit_gate, response_types in cases:
            with self.subTest(
                oidc_enabled=oidc_enabled, implicit_gate=implicit_gate, response_types=response_types
            ):
                self.oauth2_settings.OIDC_ENABLED = oidc_enabled
                self.oauth2_settings.COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT = implicit_gate
                data = {
                    "redirect_uris": ["https://example.com/cb"],
                    "grant_types": ["implicit"],
                    "response_types": response_types,
                }
                response = _post_register(self.client, data)
                assert response.status_code == 400, response.content
                body = response.json()
                assert body["error"] == "invalid_client_metadata"
                assert body["error_description"] == (
                    f"response_type {response_types[0]!r} is not supported by this server"
                )

    def test_non_string_supported_response_type_is_ignored(self):
        """A non-string entry in the advertised list is never served, and does not
        break registration, also with COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT
        filtering the list."""
        self.oauth2_settings.OIDC_ENABLED = True
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT = True
        self.oauth2_settings.OIDC_RESPONSE_TYPES_SUPPORTED = ["code", None, "code id_token"]
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code", "implicit"],
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201, response.content
        assert response.json()["response_types"] == ["code id_token"]

    def test_register_malformed_response_types_is_400(self):
        """response_types must be an array of strings."""
        self.client.force_login(self.user)
        for response_types in ("code", ["code", 1], {"code": True}):
            with self.subTest(response_types=response_types):
                data = {
                    "redirect_uris": ["https://example.com/cb"],
                    "grant_types": ["authorization_code"],
                    "response_types": response_types,
                }
                response = _post_register(self.client, data)
                assert response.status_code == 400
                body = response.json()
                assert body["error"] == "invalid_client_metadata"
                assert "response_type" in body["error_description"]

    def test_register_only_refresh_token_is_400(self):
        """grant_types=[refresh_token] only → 400."""
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["refresh_token"],
        }
        response = _post_register(self.client, data)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_register_missing_redirect_uris_is_400_with_rfc_terms(self):
        """Omitted redirect_uris with authorization_code → 400 using RFC names.

        The early check must speak RFC 7591 ("authorization_code"), not leak
        DOT's internal grant constant ("authorization-code") from
        Application.clean().
        """
        self.client.force_login(self.user)
        data = {"grant_types": ["authorization_code"]}
        response = _post_register(self.client, data)
        assert response.status_code == 400
        body = response.json()
        assert body["error"] == "invalid_client_metadata"
        assert "authorization_code" in body["error_description"]
        assert "authorization-code" not in body["error_description"]

    def test_register_invalid_redirect_uri_is_400(self):
        """Invalid redirect_uri → 400."""
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["not-a-valid-uri!"],
            "grant_types": ["authorization_code"],
        }
        response = _post_register(self.client, data)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_register_post_logout_redirect_uris_are_stored_and_echoed(self):
        """post_logout_redirect_uris (RP-Initiated Logout 1.0 §3.1) are stored and returned."""
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "post_logout_redirect_uris": ["https://example.com/logged-out", "https://example.com/bye"],
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201
        assert response.json()["post_logout_redirect_uris"] == data["post_logout_redirect_uris"]
        app = Application.objects.get(client_id=response.json()["client_id"])
        assert app.post_logout_redirect_uris == "https://example.com/logged-out https://example.com/bye"
        assert app.post_logout_redirect_uri_allowed("https://example.com/bye")

    def test_register_without_post_logout_redirect_uris_echoes_empty_list(self):
        self.client.force_login(self.user)
        data = {"redirect_uris": ["https://example.com/cb"], "grant_types": ["authorization_code"]}
        response = _post_register(self.client, data)
        assert response.status_code == 201
        assert response.json()["post_logout_redirect_uris"] == []

    def test_register_post_logout_redirect_uris_not_array_is_400(self):
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "post_logout_redirect_uris": "https://example.com/logged-out",
        }
        response = _post_register(self.client, data)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"
        assert "post_logout_redirect_uris" in response.json()["error_description"]

    def test_register_non_string_post_logout_redirect_uri_is_400(self):
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "post_logout_redirect_uris": [1],
        }
        response = _post_register(self.client, data)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_register_invalid_post_logout_redirect_uri_is_400(self):
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "post_logout_redirect_uris": ["not-a-valid-uri!"],
        }
        response = _post_register(self.client, data)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"
        assert Application.objects.count() == 0
        assert response.json()["error_description"].startswith("post_logout_redirect_uris: ")

    def test_register_post_logout_redirect_uri_must_be_a_single_uri(self):
        """The list is stored space-joined and read back split, so an entry must be exactly one URI.

        Otherwise an entry such as "https://example.com/bye javascript:alert(1)" would register a
        second URI the client never listed on its own.
        """
        self.client.force_login(self.user)
        for entry in (
            "https://example.com/bye javascript:alert(1)",
            "https://example.com/bye\thttps://evil.example/x",
            "https://example.com/bye\nhttps://evil.example/x",
            " https://example.com/bye",
            "",
            "   ",
        ):
            data = {
                "redirect_uris": ["https://example.com/cb"],
                "grant_types": ["authorization_code"],
                "post_logout_redirect_uris": [entry],
            }
            response = _post_register(self.client, data)
            assert response.status_code == 400, entry
            assert response.json()["error"] == "invalid_client_metadata"
            assert "post_logout_redirect_uri" in response.json()["error_description"]
        assert Application.objects.count() == 0

    def test_register_malformed_redirect_uri_port_is_400(self):
        """A non-numeric or out-of-range port is refused, even before a valid URI (#1918)."""
        self.client.force_login(self.user)
        for field in ("redirect_uris", "post_logout_redirect_uris"):
            for bad_uri in ("https://rp.example.com:abc/bye", "https://rp.example.com:99999/bye"):
                data = {
                    "redirect_uris": ["https://rp.example.com/cb"],
                    "grant_types": ["authorization_code"],
                    "post_logout_redirect_uris": ["https://rp.example.com/bye"],
                }
                data[field] = [bad_uri, "https://rp.example.com/bye"]
                response = _post_register(self.client, data)
                assert response.status_code == 400, (field, bad_uri)
                assert response.json()["error"] == "invalid_client_metadata"
                assert field in response.json()["error_description"], (field, bad_uri)
        assert Application.objects.count() == 0

    def test_register_public_client_http_post_logout_redirect_uri_strict_is_400(self):
        """Strict RP-Initiated Logout refuses http for a public client, so registration does too."""
        self.oauth2_settings.OIDC_ENABLED = True
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED = True
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_STRICT_REDIRECT_URIS = True
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "none",
            "post_logout_redirect_uris": ["https://example.com/bye", "http://example.com/bye"],
        }
        response = _post_register(self.client, data)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"
        assert response.json()["error_description"] == (
            "post_logout_redirect_uris: http is only allowed with confidential clients: http://example.com/bye"
        )
        assert Application.objects.count() == 0

    def test_register_malformed_post_logout_redirect_uri_strict_is_400(self):
        """A URI urlsplit() cannot parse is refused as invalid metadata (by the validator), not a 500."""
        self.oauth2_settings.OIDC_ENABLED = True
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED = True
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_STRICT_REDIRECT_URIS = True
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "none",
            "post_logout_redirect_uris": ["http://[bad/bye"],
        }
        response = _post_register(self.client, data)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_register_http_post_logout_redirect_uri_strict_allowed_when_usable(self):
        """Strict mode still accepts https for a public client and http for a confidential one."""
        self.oauth2_settings.OIDC_ENABLED = True
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED = True
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_STRICT_REDIRECT_URIS = True
        self.client.force_login(self.user)
        for auth_method, uri in (
            ("none", "https://example.com/bye"),
            ("client_secret_basic", "http://example.com/bye"),
        ):
            data = {
                "redirect_uris": ["https://example.com/cb"],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": auth_method,
                "post_logout_redirect_uris": [uri],
            }
            response = _post_register(self.client, data)
            assert response.status_code == 201, auth_method
            assert response.json()["post_logout_redirect_uris"] == [uri]

    def test_register_public_client_http_post_logout_redirect_uri_not_strict(self):
        """Without strict mode, logout and registration both accept http for a public client."""
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "none",
            "post_logout_redirect_uris": ["http://example.com/bye"],
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201
        assert response.json()["post_logout_redirect_uris"] == ["http://example.com/bye"]

    def test_register_invalid_json_is_400(self):
        """Non-JSON body → 400."""
        self.client.force_login(self.user)
        response = self.client.post(_register_url(), data="not-json", content_type="application/json")
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_register_invalid_utf8_body_is_400(self):
        """A body with invalid UTF-8 bytes → 400, not a 500.

        json.loads() on such bytes raises UnicodeDecodeError, which is a
        subclass of ValueError and is caught by _parse_metadata.
        """
        self.client.force_login(self.user)
        response = self.client.post(
            _register_url(), data=b'{"client_name": "\xff\xfe"}', content_type="application/json"
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_register_empty_grant_types_is_400(self):
        """grant_types=[] → 400."""
        self.client.force_login(self.user)
        data = {"redirect_uris": ["https://example.com/cb"], "grant_types": []}
        response = _post_register(self.client, data)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_register_grant_types_not_array_is_400(self):
        """grant_types as a string instead of an array → 400."""
        self.client.force_login(self.user)
        data = {"redirect_uris": ["https://example.com/cb"], "grant_types": "authorization_code"}
        response = _post_register(self.client, data)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_register_non_string_grant_type_is_400(self):
        """A non-string grant_types element → 400."""
        self.client.force_login(self.user)
        data = {"redirect_uris": ["https://example.com/cb"], "grant_types": [123]}
        response = _post_register(self.client, data)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_register_non_object_json_is_400(self):
        """A JSON body that is not an object → 400."""
        self.client.force_login(self.user)
        response = self.client.post(_register_url(), data="[1, 2]", content_type="application/json")
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_register_unsupported_grant_type_is_400(self):
        """An unknown grant_type value → 400."""
        self.client.force_login(self.user)
        data = {"redirect_uris": ["https://example.com/cb"], "grant_types": ["magic_link"]}
        response = _post_register(self.client, data)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_register_redirect_uris_not_array_is_400(self):
        """redirect_uris as a string instead of an array → 400."""
        self.client.force_login(self.user)
        data = {"redirect_uris": "https://example.com/cb", "grant_types": ["authorization_code"]}
        response = _post_register(self.client, data)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_register_non_string_redirect_uri_is_400(self):
        """A non-string redirect_uris element → 400."""
        self.client.force_login(self.user)
        data = {"redirect_uris": [123], "grant_types": ["authorization_code"]}
        response = _post_register(self.client, data)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_register_unsupported_auth_method_is_400(self):
        """An unsupported token_endpoint_auth_method → 400."""
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "private_key_jwt",
        }
        response = _post_register(self.client, data)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_validation_error_description_without_message_dict(self):
        """Non-field ValidationErrors serialize via their messages list."""
        from django.core.exceptions import ValidationError

        from oauth2_provider.authorization_server.views.dynamic_client_registration import (
            _validation_error_description,
        )

        assert _validation_error_description(ValidationError("plain message")) == "plain message"

    # -- userinfo_signed_response_alg (OIDC Dynamic Client Registration 1.0 §2)

    def test_register_userinfo_rs256_is_stored_and_reported(self):
        _enable_rs256(self.oauth2_settings)
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "userinfo_signed_response_alg": "RS256",
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201
        body = response.json()
        assert body["userinfo_signed_response_alg"] == "RS256"
        app = Application.objects.get(client_id=body["client_id"])
        assert app.userinfo_signed_response_alg == Application.RS256_ALGORITHM

    def test_register_without_userinfo_alg_keeps_json(self):
        """Omitted → plain JSON UserInfo, and the parameter is not reported."""
        _enable_rs256(self.oauth2_settings)
        self.client.force_login(self.user)
        data = {"redirect_uris": ["https://example.com/cb"], "grant_types": ["authorization_code"]}
        response = _post_register(self.client, data)
        assert response.status_code == 201
        body = response.json()
        assert "userinfo_signed_response_alg" not in body
        app = Application.objects.get(client_id=body["client_id"])
        assert app.userinfo_signed_response_alg == Application.NO_ALGORITHM

    def test_register_unsupported_userinfo_alg_is_400(self):
        _enable_rs256(self.oauth2_settings)
        self.client.force_login(self.user)
        for requested in ("HS256", "ES256", "none", "", 256):
            with self.subTest(requested=requested):
                data = {
                    "redirect_uris": ["https://example.com/cb"],
                    "grant_types": ["authorization_code"],
                    "userinfo_signed_response_alg": requested,
                }
                response = _post_register(self.client, data)
                assert response.status_code == 400
                body = response.json()
                assert body["error"] == "invalid_client_metadata"
                assert "userinfo_signed_response_alg" in body["error_description"]

    def test_register_userinfo_rs256_without_server_key_is_400(self):
        """A signed UserInfo response the server cannot produce is refused, not dropped."""
        self.oauth2_settings.OIDC_ENABLED = True
        assert not self.oauth2_settings.OIDC_RSA_PRIVATE_KEY
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "userinfo_signed_response_alg": "RS256",
        }
        response = _post_register(self.client, data)
        assert response.status_code == 400
        body = response.json()
        assert body["error"] == "invalid_client_metadata"
        assert "userinfo_signed_response_alg" in body["error_description"]

    def test_register_userinfo_alg_is_ignored_without_oidc(self):
        """No OpenID Connect, no UserInfo endpoint: the parameter is ignored (RFC 7591 §2)."""
        assert not self.oauth2_settings.OIDC_ENABLED
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "userinfo_signed_response_alg": "RS256",
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201
        body = response.json()
        assert "userinfo_signed_response_alg" not in body
        app = Application.objects.get(client_id=body["client_id"])
        assert app.userinfo_signed_response_alg == Application.NO_ALGORITHM


# ---------------------------------------------------------------------------
# Open registration (AllowAllDCRPermission)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings({**presets.OIDC_SETTINGS_RP_LOGOUT, **presets.DCR_SETTINGS})
class TestDCRRegisteredClientRPInitiatedLogout(TestCase):
    """A client registered through DCR can use its post_logout_redirect_uris (#1896)."""

    def setUp(self):
        self.user = UserModel.objects.create_user("dcr_logout_user", "dcr-logout@example.com", "pass")
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://rp.example.com/cb"],
            "grant_types": ["authorization_code"],
            "post_logout_redirect_uris": ["https://rp.example.com/logged-out"],
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201
        self.client_id = response.json()["client_id"]

    def _logout(self, post_logout_redirect_uri):
        return self.client.post(
            reverse("oauth2_provider:rp-initiated-logout"),
            {
                "client_id": self.client_id,
                "post_logout_redirect_uri": post_logout_redirect_uri,
                "state": "xyz",
                "allow": True,
            },
        )

    def test_logout_redirects_to_registered_post_logout_redirect_uri(self):
        response = self._logout("https://rp.example.com/logged-out")
        assert response.status_code == 302
        assert response["Location"] == "https://rp.example.com/logged-out?state=xyz"
        assert "_auth_user_id" not in self.client.session

    def test_logout_refuses_unregistered_post_logout_redirect_uri(self):
        response = self._logout("https://rp.example.com/elsewhere")
        assert response.status_code == 400
        assert "_auth_user_id" in self.client.session


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(
    {
        **presets.DCR_SETTINGS,
        "DCR_REGISTRATION_PERMISSION_CLASSES": (
            "oauth2_provider.authorization_server.dcr.AllowAllDCRPermission",
        ),
    }
)
class TestOpenRegistration(TestCase):
    def test_register_without_auth_succeeds(self):
        """AllowAllDCRPermission → unauthenticated POST → 201."""
        data = {"redirect_uris": ["https://example.com/cb"], "grant_types": ["authorization_code"]}
        response = _post_register(self.client, data)
        assert response.status_code == 201
        body = response.json()
        assert "client_id" in body
        # user should be None on the application
        app = Application.objects.get(client_id=body["client_id"])
        assert app.user is None


# ---------------------------------------------------------------------------
# CSRF enforcement (with enforce_csrf_checks=True, unlike the default test
# client which bypasses CSRF validation entirely)
# ---------------------------------------------------------------------------


CSRF_SECRET = "0123456789abcdef0123456789abcdef"


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.DCR_SETTINGS)
class TestDCRCsrfSessionAuthenticated(TestCase):
    """Session-cookie-authenticated registration requires a valid CSRF token."""

    def setUp(self):
        self.user = UserModel.objects.create_user("csrf_user", "csrf@example.com", "pass")
        self.csrf_client = self.client_class(enforce_csrf_checks=True)
        self.csrf_client.force_login(self.user)
        self.data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
        }

    def test_session_auth_without_csrf_token_is_rejected(self):
        """Session-authenticated POST without a CSRF token → 401."""
        response = _post_register(self.csrf_client, self.data)
        assert response.status_code == 401
        assert response.json()["error"] == "access_denied"

    def test_session_auth_with_csrf_token_succeeds(self):
        """Session-authenticated POST with a valid CSRF token → 201."""
        self.csrf_client.cookies["csrftoken"] = CSRF_SECRET
        response = _post_register(self.csrf_client, self.data, HTTP_X_CSRFTOKEN=CSRF_SECRET)
        assert response.status_code == 201
        assert "client_id" in response.json()

    def test_non_bearer_authorization_header_does_not_bypass_csrf(self):
        """A Basic Authorization header must not exempt a session-authenticated request from CSRF."""
        response = _post_register(
            self.csrf_client,
            self.data,
            HTTP_AUTHORIZATION="Basic dXNlcjpwYXNz",
        )
        assert response.status_code == 401
        assert response.json()["error"] == "access_denied"

    def test_bearer_authorization_header_bypasses_csrf(self):
        """A Bearer Authorization header exempts a session-authenticated request from CSRF."""
        response = _post_register(
            self.csrf_client,
            self.data,
            HTTP_AUTHORIZATION="Bearer some-initial-access-token",
        )
        assert response.status_code == 201


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(
    {
        **presets.DCR_SETTINGS,
        "DCR_REGISTRATION_PERMISSION_CLASSES": (
            "oauth2_provider.authorization_server.dcr.AllowAllDCRPermission",
        ),
    }
)
class TestDCRCsrfOpenRegistration(TestCase):
    """Open (anonymous) registration works without any CSRF token."""

    def test_anonymous_registration_without_csrf_token_succeeds(self):
        csrf_client = self.client_class(enforce_csrf_checks=True)
        data = {"redirect_uris": ["https://example.com/cb"], "grant_types": ["authorization_code"]}
        response = _post_register(csrf_client, data)
        assert response.status_code == 201
        assert "client_id" in response.json()


# ---------------------------------------------------------------------------
# RFC 7592 — Management endpoint tests
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.DCR_SETTINGS)
class TestDynamicClientRegistrationManagement(TestCase):
    def setUp(self):
        self.user = UserModel.objects.create_user("mgmt_user", "mgmt@example.com", "pass")
        self.client.force_login(self.user)
        # Register a client to use in management tests
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "client_name": "Managed App",
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201
        body = response.json()
        self.client_id = body["client_id"]
        self.client_id_issued_at = body["client_id_issued_at"]
        self.registration_token = body["registration_access_token"]
        self.management_url = _management_url(self.client_id)
        self.client.logout()

    # -- GET -----------------------------------------------------------------

    def test_get_returns_current_config(self):
        """GET with valid token → 200 with current config."""
        response = self.client.get(self.management_url, **_bearer(self.registration_token))
        assert response.status_code == 200
        body = response.json()
        assert body["client_id"] == self.client_id
        assert body["client_name"] == "Managed App"
        assert "https://example.com/cb" in body["redirect_uris"]
        assert body["client_id_issued_at"] == self.client_id_issued_at
        # The secret is only returned at registration, and its expiry with it.
        assert "client_secret" not in body
        assert "client_secret_expires_at" not in body

    def test_get_reports_algorithm_set_outside_registration(self):
        """An administrator-chosen HS256 is reported too (OIDC Registration 1.0 §3.2)."""
        Application.objects.filter(client_id=self.client_id).update(algorithm=Application.HS256_ALGORITHM)
        response = self.client.get(self.management_url, **_bearer(self.registration_token))
        assert response.status_code == 200
        assert response.json()["id_token_signed_response_alg"] == "HS256"

    def test_get_missing_token_is_401(self):
        """GET without token → 401 with a WWW-Authenticate Bearer challenge (RFC 6750 §3)."""
        response = self.client.get(self.management_url)
        assert response.status_code == 401
        assert response["WWW-Authenticate"].startswith('Bearer error="invalid_token"')

    def test_registration_scoped_token_for_manual_application_is_401(self):
        """A registration-scoped token can't manage a manually created application.

        RFC 7592 management only applies to dynamically registered clients: a
        regular access token that carries DCR_REGISTRATION_SCOPE (e.g. through
        scope misconfiguration) must not allow a manually provisioned
        application to be reconfigured or deleted.
        """
        from datetime import timedelta

        from django.utils import timezone

        manual_app = Application.objects.create(
            name="Manual App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="https://manual.example.com/cb",
        )
        stray_token = AccessToken.objects.create(
            application=manual_app,
            user=self.user,
            token="stray-registration-scoped-token",
            expires=timezone.now() + timedelta(hours=1),
            scope=self.oauth2_settings.DCR_REGISTRATION_SCOPE,
        )
        response = self.client.get(_management_url(manual_app.client_id), **_bearer(stray_token.token))
        assert response.status_code == 401
        assert response.json()["error"] == "invalid_token"
        # The application must remain untouched and undeletable through DCR
        response = self.client.delete(_management_url(manual_app.client_id), **_bearer(stray_token.token))
        assert response.status_code == 401
        assert Application.objects.filter(pk=manual_app.pk).exists()

    def test_non_dcr_registration_source_is_rejected_by_management_endpoint(self):
        """Only registration_source="dcr" applications are manageable via RFC 7592.

        The management gate is an equality check against DCR, not a truthiness
        test: "manual" and "cimd" are non-empty strings, so a
        ``not application.registration_source`` guard would wrongly let both
        through. Every non-DCR source must be rejected (401) on GET, PUT and
        DELETE even when the presented token carries DCR_REGISTRATION_SCOPE.
        """
        from datetime import timedelta

        from django.utils import timezone

        for source in (
            Application.RegistrationSource.MANUAL,
            Application.RegistrationSource.CIMD,
        ):
            app = Application.objects.create(
                name=f"{source} App",
                user=self.user,
                client_type=Application.CLIENT_CONFIDENTIAL,
                authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
                redirect_uris="https://example.com/cb",
                registration_source=source,
            )
            token = AccessToken.objects.create(
                application=app,
                user=self.user,
                token=f"stray-token-{source}",
                expires=timezone.now() + timedelta(hours=1),
                scope=self.oauth2_settings.DCR_REGISTRATION_SCOPE,
            )
            url = _management_url(app.client_id)

            get_response = self.client.get(url, **_bearer(token.token))
            assert get_response.status_code == 401, source
            assert get_response.json()["error"] == "invalid_token"

            put_response = self.client.put(
                url,
                data=json.dumps(
                    {"redirect_uris": ["https://example.com/new"], "grant_types": ["authorization_code"]}
                ),
                content_type="application/json",
                **_bearer(token.token),
            )
            assert put_response.status_code == 401, source

            delete_response = self.client.delete(url, **_bearer(token.token))
            assert delete_response.status_code == 401, source
            # The application must survive every rejected management call.
            assert Application.objects.filter(pk=app.pk).exists()

    def test_get_tolerates_extra_whitespace_in_authorization_header(self):
        """Bearer parsing tolerates any whitespace run between scheme and token."""
        response = self.client.get(
            self.management_url,
            HTTP_AUTHORIZATION=f"Bearer   {self.registration_token}",
        )
        assert response.status_code == 200

    def test_get_accepts_case_insensitive_bearer_scheme(self):
        """RFC 7235: auth scheme names are case-insensitive."""
        response = self.client.get(
            self.management_url,
            HTTP_AUTHORIZATION=f"bearer {self.registration_token}",
        )
        assert response.status_code == 200

    def test_get_rejects_non_bearer_scheme(self):
        """A scheme that merely starts with 'Bearer' (e.g. 'BearerX') → 401."""
        response = self.client.get(
            self.management_url,
            HTTP_AUTHORIZATION=f"BearerX {self.registration_token}",
        )
        assert response.status_code == 401

    def test_get_unknown_token_is_401(self):
        """GET with a Bearer token that matches no AccessToken → 401."""
        response = self.client.get(self.management_url, **_bearer("no-such-token"))
        assert response.status_code == 401

    def test_get_expired_token_is_401(self):
        """GET with an expired registration token → 401."""
        from datetime import timedelta

        from django.utils import timezone

        token = AccessToken.objects.get(token=self.registration_token)
        token.expires = timezone.now() - timedelta(seconds=1)
        token.save()
        response = self.client.get(self.management_url, **_bearer(self.registration_token))
        assert response.status_code == 401

    def test_get_token_wrong_client_is_401(self):
        """GET with token for a different client → 401 invalid_token (RFC 6750)."""
        # Create a second application with its own token
        self.client.force_login(self.user)
        data2 = {"redirect_uris": ["https://other.com/cb"], "grant_types": ["authorization_code"]}
        r2 = _post_register(self.client, data2)
        other_token = r2.json()["registration_access_token"]
        self.client.logout()

        response = self.client.get(self.management_url, **_bearer(other_token))
        assert response.status_code == 401
        assert response.json()["error"] == "invalid_token"
        assert response["WWW-Authenticate"].startswith('Bearer error="invalid_token"')

    # -- PUT -----------------------------------------------------------------

    def test_put_updates_application(self):
        """PUT → updates Application fields."""
        update_data = {
            "redirect_uris": ["https://updated.example.com/cb"],
            "grant_types": ["authorization_code"],
            "client_name": "Updated App",
        }
        response = self.client.put(
            self.management_url,
            data=json.dumps(update_data),
            content_type="application/json",
            **_bearer(self.registration_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["client_name"] == "Updated App"
        assert "https://updated.example.com/cb" in body["redirect_uris"]
        assert body["client_id_issued_at"] == self.client_id_issued_at
        app = Application.objects.get(client_id=self.client_id)
        assert app.name == "Updated App"

    def test_put_is_full_replacement_and_resets_omitted_fields(self):
        """PUT is a full replacement (RFC 7592 §2.2): omitted metadata resets.

        The client was registered with a name; a PUT that omits client_name
        clears Application.name rather than preserving it.
        """
        update_data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            # client_name intentionally omitted
        }
        response = self.client.put(
            self.management_url,
            data=json.dumps(update_data),
            content_type="application/json",
            **_bearer(self.registration_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert "client_name" not in body
        app = Application.objects.get(client_id=self.client_id)
        assert app.name == ""

    def test_put_updates_and_clears_post_logout_redirect_uris(self):
        """PUT replaces post_logout_redirect_uris, and omitting it clears them (RFC 7592 §2.2)."""
        update_data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "post_logout_redirect_uris": ["https://example.com/logged-out"],
        }
        response = self.client.put(
            self.management_url,
            data=json.dumps(update_data),
            content_type="application/json",
            **_bearer(self.registration_token),
        )
        assert response.status_code == 200
        assert response.json()["post_logout_redirect_uris"] == ["https://example.com/logged-out"]
        app = Application.objects.get(client_id=self.client_id)
        assert app.post_logout_redirect_uris == "https://example.com/logged-out"
        get_response = self.client.get(
            self.management_url, **_bearer(response.json()["registration_access_token"])
        )
        assert get_response.json()["post_logout_redirect_uris"] == ["https://example.com/logged-out"]

        del update_data["post_logout_redirect_uris"]
        response = self.client.put(
            self.management_url,
            data=json.dumps(update_data),
            content_type="application/json",
            **_bearer(response.json()["registration_access_token"]),
        )
        assert response.status_code == 200
        assert response.json()["post_logout_redirect_uris"] == []
        app.refresh_from_db()
        assert app.post_logout_redirect_uris == ""

    def test_put_without_userinfo_alg_resets_to_json(self):
        """userinfo_signed_response_alg follows PUT full-replacement (RFC 7592 §2.2)."""
        _enable_rs256(self.oauth2_settings)
        Application.objects.filter(client_id=self.client_id).update(
            algorithm=Application.RS256_ALGORITHM,
            userinfo_signed_response_alg=Application.RS256_ALGORITHM,
        )
        response = self.client.get(self.management_url, **_bearer(self.registration_token))
        assert response.json()["userinfo_signed_response_alg"] == "RS256"

        update_data = {"redirect_uris": ["https://example.com/cb"], "grant_types": ["authorization_code"]}
        response = self.client.put(
            self.management_url,
            data=json.dumps(update_data),
            content_type="application/json",
            **_bearer(self.registration_token),
        )
        assert response.status_code == 200
        assert "userinfo_signed_response_alg" not in response.json()
        app = Application.objects.get(client_id=self.client_id)
        assert app.userinfo_signed_response_alg == Application.NO_ALGORITHM

    def test_userinfo_alg_is_not_reported_while_the_server_cannot_sign(self):
        """A stored RS256 the server no longer honours is not reported, and an echoing PUT resets it."""
        Application.objects.filter(client_id=self.client_id).update(
            algorithm=Application.RS256_ALGORITHM,
            userinfo_signed_response_alg=Application.RS256_ALGORITHM,
        )
        assert not self.oauth2_settings.OIDC_ENABLED
        response = self.client.get(self.management_url, **_bearer(self.registration_token))
        assert response.status_code == 200
        body = response.json()
        assert "userinfo_signed_response_alg" not in body

        echoed = {
            key: body[key]
            for key in ("redirect_uris", "grant_types", "client_name", "token_endpoint_auth_method")
            if key in body
        }
        response = self.client.put(
            self.management_url,
            data=json.dumps(echoed),
            content_type="application/json",
            **_bearer(self.registration_token),
        )
        assert response.status_code == 200, response.content
        assert "userinfo_signed_response_alg" not in response.json()
        app = Application.objects.get(client_id=self.client_id)
        assert app.userinfo_signed_response_alg == Application.NO_ALGORITHM

    def test_put_leaves_can_introspect_to_the_administrator(self):
        """#1451: can_introspect is not client metadata. A PUT can neither turn on a
        value an administrator turned off nor turn off one left on."""
        Application.objects.filter(client_id=self.client_id).update(can_introspect=False)
        update_data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "can_introspect": True,
        }
        response = self.client.put(
            self.management_url,
            data=json.dumps(update_data),
            content_type="application/json",
            **_bearer(self.registration_token),
        )
        assert response.status_code == 200
        assert "can_introspect" not in response.json()
        assert Application.objects.get(client_id=self.client_id).can_introspect is False

        Application.objects.filter(client_id=self.client_id).update(can_introspect=True)
        update_data["can_introspect"] = False
        response = self.client.put(
            self.management_url,
            data=json.dumps(update_data),
            content_type="application/json",
            **_bearer(response.json()["registration_access_token"]),
        )
        assert response.status_code == 200
        assert Application.objects.get(client_id=self.client_id).can_introspect is True

    def test_put_keeps_algorithm_echoed_from_get(self):
        """A PUT sending back what GET reported is not refused (RFC 7592 §2.2).

        The management response reports an algorithm set outside registration
        too, so a client echoing it must not be locked out of updates, and the
        value must survive the round trip rather than be reset to the default.
        """
        self.client.force_login(self.user)
        response = _post_register(
            self.client,
            {
                "redirect_uris": ["https://example.com/cb"],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "client_secret_jwt",  # plaintext secret: HS256-eligible
            },
        )
        assert response.status_code == 201, response.content
        registered = response.json()
        self.client.logout()
        url = _management_url(registered["client_id"])
        token = registered["registration_access_token"]
        Application.objects.filter(client_id=registered["client_id"]).update(
            algorithm=Application.HS256_ALGORITHM
        )

        reported = self.client.get(url, **_bearer(token)).json()
        assert reported["id_token_signed_response_alg"] == "HS256"
        echo = {
            key: reported[key]
            for key in (
                "redirect_uris",
                "grant_types",
                "token_endpoint_auth_method",
                "id_token_signed_response_alg",
            )
        }
        response = self.client.put(
            url, data=json.dumps(echo), content_type="application/json", **_bearer(token)
        )
        assert response.status_code == 200, response.content
        assert response.json()["id_token_signed_response_alg"] == "HS256"
        assert (
            Application.objects.get(client_id=registered["client_id"]).algorithm
            == Application.HS256_ALGORITHM
        )

        # Omitting the parameter is a full replacement: back to the default.
        echo.pop("id_token_signed_response_alg")
        token = response.json()["registration_access_token"]
        response = self.client.put(
            url, data=json.dumps(echo), content_type="application/json", **_bearer(token)
        )
        assert response.status_code == 200, response.content
        assert "id_token_signed_response_alg" not in response.json()
        assert (
            Application.objects.get(client_id=registered["client_id"]).algorithm == Application.NO_ALGORITHM
        )

    def test_put_echoing_hs256_while_dropping_its_preconditions_is_400(self):
        """An echoed HS256 is refused, by its RFC name, once the same PUT invalidates it."""
        self.client.force_login(self.user)
        response = _post_register(
            self.client,
            {
                "redirect_uris": ["https://example.com/cb"],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "client_secret_jwt",
            },
        )
        assert response.status_code == 201, response.content
        registered = response.json()
        self.client.logout()
        url = _management_url(registered["client_id"])
        Application.objects.filter(client_id=registered["client_id"]).update(
            algorithm=Application.HS256_ALGORITHM
        )

        response = self.client.put(
            url,
            data=json.dumps(
                {
                    "redirect_uris": ["https://example.com/cb"],
                    "grant_types": ["authorization_code"],
                    "token_endpoint_auth_method": "client_secret_basic",  # secret would be hashed
                    "id_token_signed_response_alg": "HS256",
                }
            ),
            content_type="application/json",
            **_bearer(registered["registration_access_token"]),
        )
        assert response.status_code == 400, response.content
        body = response.json()
        assert body["error"] == "invalid_client_metadata"
        assert "id_token_signed_response_alg" in body["error_description"]
        assert "hash_client_secret" not in body["error_description"]
        app = Application.objects.get(client_id=registered["client_id"])
        assert app.algorithm == Application.HS256_ALGORITHM
        assert app.token_endpoint_auth_method == "client_secret_jwt"
        assert app.client_secret == registered["client_secret"]  # still plaintext, untouched

    def test_put_echoing_rs256_after_key_removal_is_400(self):
        """Echoing RS256 once the server can no longer sign with it is refused, by name."""
        _enable_rs256(self.oauth2_settings)
        update_data = {"redirect_uris": ["https://example.com/cb"], "grant_types": ["authorization_code"]}
        response = self.client.put(
            self.management_url,
            data=json.dumps(update_data),
            content_type="application/json",
            **_bearer(self.registration_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["id_token_signed_response_alg"] == "RS256"

        self.oauth2_settings.OIDC_RSA_PRIVATE_KEY = ""
        response = self.client.put(
            self.management_url,
            data=json.dumps({**update_data, "id_token_signed_response_alg": "RS256"}),
            content_type="application/json",
            **_bearer(body["registration_access_token"]),
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"
        assert "id_token_signed_response_alg" in response.json()["error_description"]

    def test_put_and_get_track_server_signing_capability(self):
        """PUT re-derives the signing algorithm like every other field (RFC 7592 §2.2).

        A client registered before the server could sign gains RS256 on its
        next update and GET reports it; once the key is gone the next PUT drops
        it again instead of failing validation over a stale RS256.
        """
        update_data = {"redirect_uris": ["https://example.com/cb"], "grant_types": ["authorization_code"]}
        assert Application.objects.get(client_id=self.client_id).algorithm == Application.NO_ALGORITHM

        _enable_rs256(self.oauth2_settings)
        response = self.client.put(
            self.management_url,
            data=json.dumps(update_data),
            content_type="application/json",
            **_bearer(self.registration_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["id_token_signed_response_alg"] == "RS256"
        assert Application.objects.get(client_id=self.client_id).algorithm == Application.RS256_ALGORITHM
        token = body["registration_access_token"]  # rotated by the PUT

        response = self.client.get(self.management_url, **_bearer(token))
        assert response.status_code == 200
        assert response.json()["id_token_signed_response_alg"] == "RS256"

        self.oauth2_settings.OIDC_RSA_PRIVATE_KEY = ""
        response = self.client.put(
            self.management_url,
            data=json.dumps(update_data),
            content_type="application/json",
            **_bearer(token),
        )
        assert response.status_code == 200
        assert "id_token_signed_response_alg" not in response.json()
        assert Application.objects.get(client_id=self.client_id).algorithm == Application.NO_ALGORITHM

    def _register_client_secret_jwt(self):
        self.client.force_login(self.user)
        response = _post_register(
            self.client,
            {
                "redirect_uris": ["https://example.com/cb"],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "client_secret_jwt",
            },
        )
        self.client.logout()
        assert response.status_code == 201, response.content
        return response.json()

    def _register_client_secret_jwt_with_admin_hs256(self):
        """Register a client_secret_jwt client, then set HS256 as an administrator would."""
        registered = self._register_client_secret_jwt()
        Application.objects.filter(client_id=registered["client_id"]).update(
            algorithm=Application.HS256_ALGORITHM
        )
        return registered

    def _put_hs256(self, registered, **metadata):
        return self.client.put(
            _management_url(registered["client_id"]),
            data=json.dumps(
                {
                    "redirect_uris": ["https://updated.example.com/cb"],
                    "grant_types": ["authorization_code"],
                    "token_endpoint_auth_method": "client_secret_jwt",
                    "id_token_signed_response_alg": "HS256",
                    **metadata,
                }
            ),
            content_type="application/json",
            **_bearer(registered["registration_access_token"]),
        )

    def test_put_echoing_hs256_with_rs256_available_is_200(self):
        """An echoed administrator-set HS256 is kept, not replaced by the RS256 default."""
        _enable_rs256(self.oauth2_settings)
        registered = self._register_client_secret_jwt_with_admin_hs256()
        response = self._put_hs256(registered)
        assert response.status_code == 200, response.content
        assert response.json()["id_token_signed_response_alg"] == "HS256"
        app = Application.objects.get(client_id=registered["client_id"])
        assert app.algorithm == Application.HS256_ALGORITHM
        assert app.redirect_uris == "https://updated.example.com/cb"
        assert app.client_secret == registered["client_secret"]

    def test_put_echoing_hs256_for_ineligible_client_is_400(self):
        """An echoed HS256 is refused with the reason once the PUT makes the client ineligible.

        The row is left unchanged, the plaintext secret included.
        """
        self.oauth2_settings.OIDC_ENABLED = True
        registered = self._register_client_secret_jwt_with_admin_hs256()
        # client_secret_basic is covered by test_put_echoing_hs256_while_dropping_its_preconditions_is_400.
        cases = (
            ({"token_endpoint_auth_method": "none"}, "public client"),
            ({"grant_types": ["implicit"]}, "implicit"),
        )
        for metadata, reason in cases:
            with self.subTest(metadata=metadata):
                response = self._put_hs256(registered, **metadata)
                assert response.status_code == 400, response.content
                body = response.json()
                assert body["error"] == "invalid_client_metadata"
                description = body["error_description"]
                assert description.startswith("id_token_signed_response_alg 'HS256' is not available")
                assert reason in description
                assert "hash_client_secret" not in description
                app = Application.objects.get(client_id=registered["client_id"])
                assert app.token_endpoint_auth_method == Application.TOKEN_AUTH_METHOD_CLIENT_SECRET_JWT
                assert app.authorization_grant_type == Application.GRANT_AUTHORIZATION_CODE
                assert app.algorithm == Application.HS256_ALGORITHM
                assert app.hash_client_secret is False
                assert app.redirect_uris == "https://example.com/cb"
                assert app.client_secret == registered["client_secret"]

    def test_put_new_hs256_is_400(self):
        """A PUT cannot ask for HS256 afresh, even for an otherwise eligible client.

        Only an HS256 already stored (an administrator's choice) is kept when
        echoed; anything else is refused as at registration, row unchanged.
        """
        for oidc_enabled, rsa_key, stored in (
            (False, "", Application.NO_ALGORITHM),
            (True, presets.OIDC_SETTINGS_RW["OIDC_RSA_PRIVATE_KEY"], Application.RS256_ALGORITHM),
        ):
            with self.subTest(stored=stored):
                self.oauth2_settings.OIDC_ENABLED = oidc_enabled
                self.oauth2_settings.OIDC_RSA_PRIVATE_KEY = rsa_key
                registered = self._register_client_secret_jwt()
                assert registered.get("id_token_signed_response_alg", "") == stored
                response = self._put_hs256(registered)
                assert response.status_code == 400, response.content
                body = response.json()
                assert body["error"] == "invalid_client_metadata"
                description = body["error_description"]
                assert description.startswith("Unsupported id_token_signed_response_alg: 'HS256'.")
                assert "not offered to self-registered clients" in description
                app = Application.objects.get(client_id=registered["client_id"])
                assert app.algorithm == stored
                assert app.redirect_uris == "https://example.com/cb"

    def _assert_switch_to_client_secret_jwt_refused(self, extra_metadata):
        """A hashed secret cannot become the HMAC key, so the PUT is refused with RFC names."""
        self.oauth2_settings.OIDC_ENABLED = True
        before = Application.objects.get(client_id=self.client_id)
        assert before.token_endpoint_auth_method == "client_secret_basic"
        assert Application._client_secret_is_hashed(before.client_secret)
        response = self.client.put(
            self.management_url,
            data=json.dumps(
                {
                    "redirect_uris": ["https://example.com/cb"],
                    "grant_types": ["authorization_code"],
                    "client_name": "Managed App",
                    "token_endpoint_auth_method": "client_secret_jwt",
                    **extra_metadata,
                }
            ),
            content_type="application/json",
            **_bearer(self.registration_token),
        )
        assert response.status_code == 400, response.content
        body = response.json()
        assert body["error"] == "invalid_client_metadata"
        description = body["error_description"]
        assert "token_endpoint_auth_method 'client_secret_jwt'" in description
        assert "stored hashed" in description
        assert "register a new client" in description
        assert "hash_client_secret" not in description
        assert "client_secret:" not in description
        after = Application.objects.get(client_id=self.client_id)
        assert after.token_endpoint_auth_method == before.token_endpoint_auth_method
        assert after.hash_client_secret is True
        assert after.client_secret == before.client_secret
        assert after.algorithm == before.algorithm

    def test_put_switch_hashed_secret_client_to_client_secret_jwt_is_400(self):
        """client_secret_jwt needs the plaintext secret, which a hashed row lost."""
        self._assert_switch_to_client_secret_jwt_refused({})

    def test_put_switch_hashed_secret_client_to_client_secret_jwt_hs256_is_400(self):
        """Asking for HS256 in the same PUT is refused for the same reason."""
        self._assert_switch_to_client_secret_jwt_refused({"id_token_signed_response_alg": "HS256"})

    def test_hashed_secret_check_asks_the_application_instance(self):
        """The hashed-secret check goes through the application, as clean() does.

        A swapped model may redefine ``_client_secret_is_hashed`` as an
        ordinary method. On registration the view does not ask it (a fresh
        secret is never hashed) and only Application.clean() does, so a faithful
        override must leave registration working. An update must honour the
        model's answer with the RFC-worded refusal rather than
        Application.clean()'s model-field wording.
        """
        from unittest import mock

        from oauth2_provider.models import AbstractApplication

        def faithful_instance_override(self, client_secret):
            return AbstractApplication._client_secret_is_hashed(client_secret)

        def always_hashed_instance_override(self, client_secret):
            return True

        with mock.patch.object(Application, "_client_secret_is_hashed", faithful_instance_override):
            registered = self._register_client_secret_jwt()
        with mock.patch.object(Application, "_client_secret_is_hashed", always_hashed_instance_override):
            response = self.client.put(
                _management_url(registered["client_id"]),
                data=json.dumps(
                    {
                        "redirect_uris": ["https://example.com/cb"],
                        "grant_types": ["authorization_code"],
                        "token_endpoint_auth_method": "client_secret_jwt",
                    }
                ),
                content_type="application/json",
                **_bearer(registered["registration_access_token"]),
            )
        assert response.status_code == 400, response.content
        description = response.json()["error_description"]
        assert "stored hashed" in description
        assert "hash_client_secret" not in description

    def test_put_echoing_hs256_needs_a_stored_client_secret_of_32_octets(self):
        """OIDC Core 1.0 §16.19: an HS256 client secret must hold at least 32 octets.

        An administrator-set HS256 echoed back is refused when the stored
        secret is one octet short of an HMAC key, leaving the row unchanged,
        and kept at exactly 32. The pair also proves the PUT checks the stored
        secret rather than an empty default, which would fail both.
        """
        self.oauth2_settings.OIDC_ENABLED = True
        self.oauth2_settings.CLIENT_SECRET_GENERATOR_LENGTH = 31
        short = self._register_client_secret_jwt_with_admin_hs256()
        assert len(short["client_secret"]) == 31
        response = self._put_hs256(short)
        assert response.status_code == 400, response.content
        body = response.json()
        assert body["error"] == "invalid_client_metadata"
        assert "id_token_signed_response_alg 'HS256'" in body["error_description"]
        assert "at least 32 octets" in body["error_description"]
        assert "OpenID Connect Core 1.0 section 16.19" in body["error_description"]
        app = Application.objects.get(client_id=short["client_id"])
        assert app.algorithm == Application.HS256_ALGORITHM
        assert app.redirect_uris == "https://example.com/cb"
        assert app.client_secret == short["client_secret"]

        self.oauth2_settings.CLIENT_SECRET_GENERATOR_LENGTH = 32
        exact = self._register_client_secret_jwt_with_admin_hs256()
        assert len(exact["client_secret"]) == 32
        response = self._put_hs256(exact)
        assert response.status_code == 200, response.content
        assert response.json()["id_token_signed_response_alg"] == "HS256"

    def test_put_rotates_token_by_default(self):
        """PUT with DCR_ROTATE_REGISTRATION_TOKEN_ON_UPDATE=True → new token issued."""
        update_data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
        }
        response = self.client.put(
            self.management_url,
            data=json.dumps(update_data),
            content_type="application/json",
            **_bearer(self.registration_token),
        )
        assert response.status_code == 200
        body = response.json()
        new_token = body["registration_access_token"]
        assert new_token != self.registration_token
        # Old token should be gone
        assert not AccessToken.objects.filter(token=self.registration_token).exists()
        # New token should exist
        assert AccessToken.objects.filter(token=new_token).exists()

    def test_put_no_rotate_keeps_token(self):
        """PUT with DCR_ROTATE_REGISTRATION_TOKEN_ON_UPDATE=False → same token."""
        self.oauth2_settings.DCR_ROTATE_REGISTRATION_TOKEN_ON_UPDATE = False
        update_data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
        }
        response = self.client.put(
            self.management_url,
            data=json.dumps(update_data),
            content_type="application/json",
            **_bearer(self.registration_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["registration_access_token"] == self.registration_token

    def test_put_without_token_is_401(self):
        """PUT without a registration token → 401."""
        response = self.client.put(
            self.management_url,
            data=json.dumps({"redirect_uris": ["https://example.com/cb"]}),
            content_type="application/json",
        )
        assert response.status_code == 401

    def test_put_invalid_json_is_400(self):
        """PUT with a non-JSON body → 400."""
        response = self.client.put(
            self.management_url,
            data="not-json",
            content_type="application/json",
            **_bearer(self.registration_token),
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_put_multiple_grant_types_is_400(self):
        """PUT with multiple non-refresh_token grant types other than the hybrid pair → 400."""
        update_data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code", "client_credentials"],
        }
        response = self.client.put(
            self.management_url,
            data=json.dumps(update_data),
            content_type="application/json",
            **_bearer(self.registration_token),
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_put_to_hybrid_and_read_back(self):
        """#1895: a PUT can make the client hybrid, and GET reports it in RFC 7591 terms."""
        self.oauth2_settings.OIDC_ENABLED = True
        update_data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code", "implicit", "refresh_token"],
            "response_types": ["code id_token"],
            "client_name": "Managed App",
        }
        response = self.client.put(
            self.management_url,
            data=json.dumps(update_data),
            content_type="application/json",
            **_bearer(self.registration_token),
        )
        assert response.status_code == 200, response.content
        hybrid_grant_types = ["authorization_code", "implicit", "refresh_token"]
        hybrid_response_types = ["code id_token", "code token", "code id_token token"]
        assert response.json()["grant_types"] == hybrid_grant_types
        assert response.json()["response_types"] == hybrid_response_types
        app = Application.objects.get(client_id=self.client_id)
        assert app.authorization_grant_type == Application.GRANT_OPENID_HYBRID

        token = response.json()["registration_access_token"]
        response = self.client.get(self.management_url, **_bearer(token))
        assert response.status_code == 200
        assert response.json()["grant_types"] == hybrid_grant_types
        assert response.json()["response_types"] == hybrid_response_types

    def test_put_echoing_read_response_is_200(self):
        """RFC 7592 section 2.2: a client can PUT back the metadata a read returned.

        The response_types reported are ones the registered grant serves, so
        echoing them passes the consistency check and changes nothing.
        """
        response = self.client.get(self.management_url, **_bearer(self.registration_token))
        assert response.status_code == 200
        metadata = response.json()
        # RFC 7592 section 2.2: these must not be sent in an update request.
        for field in ("registration_access_token", "registration_client_uri", "client_id_issued_at"):
            metadata.pop(field)
        response = self.client.put(
            self.management_url,
            data=json.dumps(metadata),
            content_type="application/json",
            **_bearer(self.registration_token),
        )
        assert response.status_code == 200, response.content
        body = response.json()
        assert body["grant_types"] == metadata["grant_types"]
        assert body["response_types"] == metadata["response_types"] == ["code"]

    def test_put_inconsistent_response_types_is_400(self):
        """A PUT is checked like a registration; the row is left unchanged."""
        self.oauth2_settings.OIDC_ENABLED = True
        update_data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code", "implicit"],
            "response_types": ["code"],
        }
        response = self.client.put(
            self.management_url,
            data=json.dumps(update_data),
            content_type="application/json",
            **_bearer(self.registration_token),
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"
        app = Application.objects.get(client_id=self.client_id)
        assert app.authorization_grant_type == Application.GRANT_AUTHORIZATION_CODE

    def test_put_invalid_metadata_is_400(self):
        """PUT with an invalid redirect_uri → 400 with validation message."""
        update_data = {
            "redirect_uris": ["not-a-valid-uri!"],
            "grant_types": ["authorization_code"],
        }
        response = self.client.put(
            self.management_url,
            data=json.dumps(update_data),
            content_type="application/json",
            **_bearer(self.registration_token),
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_put_malformed_post_logout_redirect_uri_port_is_400_and_keeps_metadata(self):
        """A rejected PUT leaves the stored metadata and registration token as they were (#1918)."""
        update_data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "post_logout_redirect_uris": ["https://rp.example.com:abc/bye", "https://rp.example.com/bye"],
        }
        response = self.client.put(
            self.management_url,
            data=json.dumps(update_data),
            content_type="application/json",
            **_bearer(self.registration_token),
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"
        app = Application.objects.get(client_id=self.client_id)
        assert app.name == "Managed App"
        assert app.post_logout_redirect_uris == ""
        get_response = self.client.get(self.management_url, **_bearer(self.registration_token))
        assert get_response.status_code == 200

    # -- DELETE --------------------------------------------------------------

    def test_delete_without_token_is_401(self):
        """DELETE without a registration token → 401, application kept."""
        response = self.client.delete(self.management_url)
        assert response.status_code == 401
        assert Application.objects.filter(client_id=self.client_id).exists()

    def test_delete_removes_application(self):
        """DELETE → 204, application deleted."""
        response = self.client.delete(self.management_url, **_bearer(self.registration_token))
        assert response.status_code == 204
        assert not Application.objects.filter(client_id=self.client_id).exists()
        # Registration token should also be gone (cascade)
        assert not AccessToken.objects.filter(token=self.registration_token).exists()


# ---------------------------------------------------------------------------
# OpenID Connect for dynamically registered clients (#1853)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings({**presets.DCR_SETTINGS, **presets.OIDC_SETTINGS_RW})
class TestDynamicClientRegistrationOpenID(TestCase):
    def setUp(self):
        self.user = UserModel.objects.create_user("dcr_oidc_user", "dcr_oidc@example.com", "pass")
        self.client.force_login(self.user)

    def test_registered_public_client_receives_id_token(self):
        """Regression for #1853: an openid code flow mints an RS256 ID Token.

        Before the fix the registered application had no signing algorithm and
        the token endpoint raised ``ImproperlyConfigured`` ("This application
        does not support signed tokens").
        """
        redirect_uri = "https://example.com/cb"
        response = _post_register(
            self.client,
            {
                "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "none",
            },
        )
        assert response.status_code == 201
        registered = response.json()
        assert registered["id_token_signed_response_alg"] == "RS256"
        client_id = registered["client_id"]

        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": redirect_uri,
                "scope": "openid",
                "state": "random_state_string",
                "nonce": "random_nonce",
                "allow": True,
            },
        )
        assert response.status_code == 302, response.content
        code = parse_qs(urlparse(response["Location"]).query)["code"][0]

        response = post_form(
            self.client,
            reverse("oauth2_provider:token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
            },
        )
        assert response.status_code == 200, response.content
        content = response.json()
        assert "id_token" in content

        key = jwk.JWK.from_pem(presets.OIDC_SETTINGS_RW["OIDC_RSA_PRIVATE_KEY"].encode("utf8"))
        verified = jwt.JWT(key=key, jwt=content["id_token"])
        assert verified.token.jose_header["alg"] == "RS256"
        claims = json.loads(verified.claims)
        assert claims["aud"] == client_id
        assert claims["nonce"] == "random_nonce"

    def test_registered_hybrid_client_completes_hybrid_flow(self):
        """#1895: a registered hybrid client gets a code and an ID Token in the fragment."""
        redirect_uri = "https://example.com/cb"
        response = _post_register(
            self.client,
            {
                "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code", "implicit", "refresh_token"],
                "response_types": ["code id_token"],
            },
        )
        assert response.status_code == 201, response.content
        registered = response.json()

        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": registered["client_id"],
                "response_type": "code id_token",
                "redirect_uri": redirect_uri,
                "scope": "openid",
                "state": "random_state_string",
                "nonce": "random_nonce",
                "allow": True,
            },
        )
        assert response.status_code == 302, response.content
        fragment = parse_qs(urlparse(response["Location"]).fragment)
        assert "code" in fragment
        assert "id_token" in fragment

        response = post_form(
            self.client,
            reverse("oauth2_provider:token"),
            data={
                "grant_type": "authorization_code",
                "code": fragment["code"][0],
                "redirect_uri": redirect_uri,
            },
            **get_basic_auth_header(registered["client_id"], registered["client_secret"]),
        )
        assert response.status_code == 200, response.content
        content = response.json()
        assert "id_token" in content
        assert "refresh_token" in content

    def test_registered_client_receives_signed_userinfo(self):
        """OIDC Core 5.3.2: a client registering userinfo_signed_response_alg=RS256
        receives the UserInfo response as an RS256 JWT verifiable with the JWKS."""
        redirect_uri = "https://example.com/cb"
        response = _post_register(
            self.client,
            {
                "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "none",
                "userinfo_signed_response_alg": "RS256",
            },
        )
        assert response.status_code == 201
        client_id = response.json()["client_id"]

        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": redirect_uri,
                "scope": "openid",
                "state": "random_state_string",
                "allow": True,
            },
        )
        assert response.status_code == 302, response.content
        code = parse_qs(urlparse(response["Location"]).query)["code"][0]
        response = post_form(
            self.client,
            reverse("oauth2_provider:token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
            },
        )
        assert response.status_code == 200, response.content
        access_token = response.json()["access_token"]

        response = self.client.get(
            reverse("oauth2_provider:user-info"), HTTP_AUTHORIZATION=f"Bearer {access_token}"
        )
        assert response.status_code == 200
        assert response["Content-Type"] == "application/jwt"
        jwks = jwk.JWKSet.from_json(self.client.get(reverse("oauth2_provider:jwks-info")).content)
        verified = jwt.JWT(key=jwks, jwt=response.content.decode())
        assert verified.token.jose_header["alg"] == "RS256"
        claims = json.loads(verified.claims)
        assert claims["sub"] == str(self.user.pk)
        assert claims["aud"] == client_id
        assert claims["iss"] == presets.OIDC_SETTINGS_RW["OIDC_ISS_ENDPOINT"]


# ---------------------------------------------------------------------------
# Settings coverage
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(
    {
        **presets.DCR_SETTINGS,
        "DCR_REGISTRATION_PERMISSION_CLASSES": (
            "oauth2_provider.authorization_server.dcr.AllowAllDCRPermission",
        ),
        "DCR_REGISTRATION_SCOPE": "my:custom:scope",
    }
)
class TestDCRCustomScope(TestCase):
    def test_custom_scope_on_registration_token(self):
        """DCR_REGISTRATION_SCOPE custom value → management token uses custom scope."""
        data = {"redirect_uris": ["https://example.com/cb"], "grant_types": ["authorization_code"]}
        response = _post_register(self.client, data)
        assert response.status_code == 201
        body = response.json()
        token = AccessToken.objects.get(token=body["registration_access_token"])
        assert token.scope == "my:custom:scope"


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(
    {
        **presets.DCR_SETTINGS,
        "DCR_REGISTRATION_PERMISSION_CLASSES": (
            "oauth2_provider.authorization_server.dcr.AllowAllDCRPermission",
        ),
        "DCR_REGISTRATION_TOKEN_EXPIRE_SECONDS": 3600,
    }
)
class TestDCRTokenExpiry(TestCase):
    def test_token_expires_after_set_seconds(self):
        """DCR_REGISTRATION_TOKEN_EXPIRE_SECONDS=3600 → token expires ~1 hour from now."""
        from django.utils import timezone

        data = {"redirect_uris": ["https://example.com/cb"], "grant_types": ["authorization_code"]}
        response = _post_register(self.client, data)
        assert response.status_code == 201
        body = response.json()
        token = AccessToken.objects.get(token=body["registration_access_token"])
        delta = (token.expires - timezone.now()).total_seconds()
        # Should be close to 3600 seconds (within 30s tolerance)
        assert 3570 <= delta <= 3630

    def test_token_no_expire_is_far_future(self):
        """DCR_REGISTRATION_TOKEN_EXPIRE_SECONDS=None → expiry is year 9999."""
        # Use the default DCR_SETTINGS (None expiry)
        self.oauth2_settings.DCR_REGISTRATION_TOKEN_EXPIRE_SECONDS = None
        data = {"redirect_uris": ["https://example.com/cb"], "grant_types": ["authorization_code"]}
        response = _post_register(self.client, data)
        assert response.status_code == 201
        body = response.json()
        token = AccessToken.objects.get(token=body["registration_access_token"])
        assert token.expires.year == 9999


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(
    {
        **presets.DCR_SETTINGS,
        "DCR_REGISTRATION_PERMISSION_CLASSES": (),
    }
)
class TestDCREmptyPermissionClasses(TestCase):
    def test_empty_permission_classes_fails_closed(self):
        """An empty DCR_REGISTRATION_PERMISSION_CLASSES denies registration instead of opening it."""
        user = UserModel.objects.create_user("noperm_user", "noperm@example.com", "pass")
        self.client.force_login(user)
        data = {"redirect_uris": ["https://example.com/cb"], "grant_types": ["authorization_code"]}
        response = _post_register(self.client, data)
        assert response.status_code == 401
        assert response.json()["error"] == "access_denied"


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.DCR_SETTINGS)
class TestDCRCustomPermissionClass(TestCase):
    def test_custom_permission_class_applied(self):
        """DCR_REGISTRATION_PERMISSION_CLASSES with always-deny class → 401."""
        from unittest.mock import patch

        with patch(
            "oauth2_provider.authorization_server.views.dynamic_client_registration._check_permissions",
            return_value=False,
        ):
            data = {
                "redirect_uris": ["https://example.com/cb"],
                "grant_types": ["authorization_code"],
            }
            response = _post_register(self.client, data)
            assert response.status_code == 401


# ---------------------------------------------------------------------------
# DCR_ENABLED=False — endpoints return 404
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings({**presets.DCR_SETTINGS, "DCR_ENABLED": False})
class TestDCRDisabled(TestCase):
    def test_register_returns_404_when_disabled(self):
        response = self.client.post(
            _register_url(),
            data=json.dumps(
                {
                    "redirect_uris": ["https://example.com/cb"],
                    "grant_types": ["authorization_code"],
                }
            ),
            content_type="application/json",
        )
        assert response.status_code == 404

    def test_management_returns_404_when_disabled(self):
        response = self.client.get(_management_url("any-client-id"))
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Full roundtrip test
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(
    {
        **presets.DCR_SETTINGS,
        "DCR_REGISTRATION_PERMISSION_CLASSES": (
            "oauth2_provider.authorization_server.dcr.AllowAllDCRPermission",
        ),
        "DCR_ROTATE_REGISTRATION_TOKEN_ON_UPDATE": True,
    }
)
class TestDCRFullRoundtrip(TestCase):
    def test_register_get_put_delete(self):
        """Full roundtrip: register → GET → PUT → DELETE."""
        # 1. Register
        reg_data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "client_name": "Roundtrip App",
        }
        reg_response = _post_register(self.client, reg_data)
        assert reg_response.status_code == 201
        reg_body = reg_response.json()
        client_id = reg_body["client_id"]
        token = reg_body["registration_access_token"]
        mgmt_url = _management_url(client_id)

        # 2. GET
        get_response = self.client.get(mgmt_url, **_bearer(token))
        assert get_response.status_code == 200
        assert get_response.json()["client_name"] == "Roundtrip App"

        # 3. PUT
        put_data = {
            "redirect_uris": ["https://updated.example.com/cb"],
            "grant_types": ["authorization_code"],
            "client_name": "Updated Roundtrip App",
        }
        put_response = self.client.put(
            mgmt_url,
            data=json.dumps(put_data),
            content_type="application/json",
            **_bearer(token),
        )
        assert put_response.status_code == 200
        put_body = put_response.json()
        new_token = put_body["registration_access_token"]
        assert new_token != token  # token was rotated
        assert put_body["client_name"] == "Updated Roundtrip App"

        # 4. DELETE (use new token)
        delete_response = self.client.delete(mgmt_url, **_bearer(new_token))
        assert delete_response.status_code == 204
        assert not Application.objects.filter(client_id=client_id).exists()


# ---------------------------------------------------------------------------
# RFC 7591 §2 display metadata (client_uri, logo_uri, policy_uri, tos_uri)
# ---------------------------------------------------------------------------

DISPLAY_METADATA = {
    "client_uri": "https://client.example.com/",
    "logo_uri": "https://client.example.com/logo.png",
    "policy_uri": "https://client.example.com/policy",
    "tos_uri": "https://client.example.com/tos",
}


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.DCR_SETTINGS)
class TestDCRDisplayMetadata(TestCase):
    """#1904: the metadata the server SHOULD show the End-User during approval."""

    base = {"redirect_uris": ["https://client.example.com/cb"], "grant_types": ["authorization_code"]}

    def setUp(self):
        self.user = UserModel.objects.create_user("display_user", "display@example.com", "pass")
        self.client.force_login(self.user)

    def _put(self, body, data):
        return self.client.put(
            _management_url(body["client_id"]),
            data=json.dumps(data),
            content_type="application/json",
            **_bearer(body["registration_access_token"]),
        )

    def test_register_stores_and_echoes_display_metadata(self):
        response = _post_register(self.client, {**self.base, **DISPLAY_METADATA})
        assert response.status_code == 201, response.content
        body = response.json()
        app = Application.objects.get(client_id=body["client_id"])
        for name, value in DISPLAY_METADATA.items():
            assert body[name] == value
            assert getattr(app, name) == value

    def test_register_without_display_metadata_omits_it(self):
        response = _post_register(self.client, {**self.base, "logo_uri": None, "tos_uri": ""})
        assert response.status_code == 201, response.content
        body = response.json()
        app = Application.objects.get(client_id=body["client_id"])
        for name in DISPLAY_METADATA:
            assert name not in body
            assert getattr(app, name) == ""

    def test_register_rejects_invalid_display_metadata(self):
        invalid = (
            123,
            ["https://client.example.com/logo.png"],
            "http://client.example.com/logo.png",
            "javascript:alert(1)",
            "data:image/png;base64,AAAA",
            "/logo.png",
            "https://client.example.com/" + "a" * 500,
        )
        for name in DISPLAY_METADATA:
            for value in invalid:
                with self.subTest(name=name, value=value):
                    response = _post_register(self.client, {**self.base, name: value})
                    assert response.status_code == 400, response.content
                    body = response.json()
                    assert body["error"] == "invalid_client_metadata"
                    assert body["error_description"].startswith(name)
        assert not Application.objects.exists()

    def test_management_get_put_round_trip(self):
        body = _post_register(self.client, {**self.base, **DISPLAY_METADATA}).json()
        self.client.logout()

        response = self.client.get(
            _management_url(body["client_id"]), **_bearer(body["registration_access_token"])
        )
        assert response.status_code == 200
        for name, value in DISPLAY_METADATA.items():
            assert response.json()[name] == value

        # PUT replaces the values it sends and, as a full replacement
        # (RFC 7592 §2.2), clears the ones it omits.
        response = self._put(body, {**self.base, "logo_uri": "https://client.example.com/new-logo.png"})
        assert response.status_code == 200, response.content
        put_body = response.json()
        assert put_body["logo_uri"] == "https://client.example.com/new-logo.png"
        app = Application.objects.get(client_id=body["client_id"])
        assert app.logo_uri == "https://client.example.com/new-logo.png"
        for name in ("client_uri", "policy_uri", "tos_uri"):
            assert name not in put_body
            assert getattr(app, name) == ""

    def test_management_put_rejects_invalid_display_metadata(self):
        body = _post_register(self.client, {**self.base, **DISPLAY_METADATA}).json()
        self.client.logout()
        response = self._put(body, {**self.base, "policy_uri": "http://client.example.com/policy"})
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"
        app = Application.objects.get(client_id=body["client_id"])
        assert app.policy_uri == DISPLAY_METADATA["policy_uri"]


# ---------------------------------------------------------------------------
# RFC 9700 hashed-at-rest token storage
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(
    {
        **presets.DCR_SETTINGS,
        "COMPLIANT_BCP_RFC9700_TOKEN_STORAGE": True,
    }
)
class TestDCRRegistrationTokenStorage(TestCase):
    """Registration access tokens honour COMPLIANT_BCP_RFC9700_TOKEN_STORAGE.

    These tokens are minted by the DCR views rather than by the validator's normal
    issuance path, so they are the one kind that can keep being written in cleartext
    after a deployment enables hashed-at-rest storage.
    """

    def setUp(self):
        self.user = UserModel.objects.create_user("hashed_user", "hashed@example.com", "pass")
        self.client.force_login(self.user)
        response = _post_register(
            self.client,
            {
                "redirect_uris": ["https://example.com/cb"],
                "grant_types": ["authorization_code"],
                "client_name": "Hashed App",
            },
        )
        assert response.status_code == 201
        body = response.json()
        self.client_id = body["client_id"]
        self.registration_token = body["registration_access_token"]
        self.management_url = _management_url(self.client_id)
        self.client.logout()

    def test_registration_token_is_not_persisted_in_cleartext(self):
        checksum = hashlib.sha256(self.registration_token.encode()).hexdigest()
        token = AccessToken.objects.get(token_checksum=checksum)
        assert token.token == ""
        assert token.token_checksum == checksum

    def test_issued_token_authenticates_and_is_echoed_back(self):
        """Redacting the column must not cost the client the token it was issued, and
        RFC 7592 §3 still wants that token in the read response. With no readable copy
        left on the server, the endpoint echoes back whatever the client presented."""
        assert self.registration_token
        response = self.client.get(self.management_url, **_bearer(self.registration_token))
        assert response.status_code == 200
        assert response.json()["registration_access_token"] == self.registration_token

    def test_rotation_returns_a_usable_token_and_retires_the_old_one(self):
        response = self.client.put(
            self.management_url,
            data=json.dumps(
                {
                    "redirect_uris": ["https://example.com/cb"],
                    "grant_types": ["authorization_code"],
                    "client_name": "Hashed App v2",
                }
            ),
            content_type="application/json",
            **_bearer(self.registration_token),
        )
        assert response.status_code == 200
        rotated = response.json()["registration_access_token"]
        assert rotated
        assert rotated != self.registration_token

        stored = AccessToken.objects.get(token_checksum=hashlib.sha256(rotated.encode()).hexdigest())
        assert stored.token == ""
        assert self.client.get(self.management_url, **_bearer(rotated)).status_code == 200

        rotated_away = self.client.get(self.management_url, **_bearer(self.registration_token))
        assert rotated_away.status_code == 401


# ---------------------------------------------------------------------------
# RFC 7523 — JWT client authentication methods via DCR
# ---------------------------------------------------------------------------


def _public_jwks():
    from jwcrypto import jwk

    key = jwk.JWK.generate(kty="EC", crv="P-256", kid="dcr-ec-1")
    return {"keys": [json.loads(key.export_public())]}


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(
    {**presets.DCR_SETTINGS, "OIDC_ENABLED": True, "OIDC_REQUEST_OBJECTS_ENABLED": True}
)
class TestDCRRequestObjectMetadata(TestCase):
    """OpenID Connect Dynamic Client Registration 1.0 section 2 request object metadata."""

    def setUp(self):
        self.user = UserModel.objects.create_user("dcr_ro_user", "dcr_ro@example.com", "pass")
        self.client.force_login(self.user)

    def _data(self, **overrides):
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": _public_jwks(),
        }
        data.update(overrides)
        return data

    def test_register_request_uris_and_signing_alg(self):
        request_uris = ["https://client.example.com/req/1", "https://client.example.com/req/2#hash"]
        response = _post_register(
            self.client, self._data(request_uris=request_uris, request_object_signing_alg="ES256")
        )
        assert response.status_code == 201, response.content
        body = response.json()
        assert body["request_uris"] == request_uris
        assert body["request_object_signing_alg"] == "ES256"
        application = Application.objects.get(client_id=body["client_id"])
        assert application.request_uris == " ".join(request_uris)
        assert application.request_object_signing_alg == "ES256"

    def test_register_without_request_object_metadata_omits_it(self):
        response = _post_register(self.client, self._data())
        assert response.status_code == 201, response.content
        body = response.json()
        assert "request_uris" not in body
        assert "request_object_signing_alg" not in body

    def test_signing_alg_with_jwks_uri(self):
        data = self._data(jwks_uri="https://client.example.com/jwks.json", request_object_signing_alg="RS256")
        del data["jwks"]
        response = _post_register(self.client, data)
        assert response.status_code == 201, response.content
        assert response.json()["request_object_signing_alg"] == "RS256"

    def test_unsigned_request_objects_need_no_keys(self):
        data = self._data(token_endpoint_auth_method="client_secret_basic", request_object_signing_alg="none")
        del data["jwks"]
        response = _post_register(self.client, data)
        assert response.status_code == 201, response.content
        assert response.json()["request_object_signing_alg"] == "none"

    def test_invalid_request_object_metadata_is_400(self):
        no_keys = self._data(
            token_endpoint_auth_method="client_secret_basic", request_object_signing_alg="RS256"
        )
        del no_keys["jwks"]
        for data, message in [
            (self._data(request_uris="https://client.example.com/req"), "request_uris must be an array"),
            (self._data(request_uris=["http://client.example.com/req"]), "must be an https URL"),
            (self._data(request_uris=["https://client.example.com/a b"]), "must be an https URL"),
            (self._data(request_object_signing_alg="HS256"), "Unsupported request_object_signing_alg"),
            (self._data(request_object_signing_alg=["RS256"]), "Unsupported request_object_signing_alg"),
            (no_keys, "requires jwks or jwks_uri"),
        ]:
            with self.subTest(data=data):
                response = _post_register(self.client, data)
                assert response.status_code == 400, response.content
                body = response.json()
                assert body["error"] == "invalid_client_metadata"
                assert message in body["error_description"]

    def test_request_object_metadata_is_ignored_when_disabled(self):
        self.oauth2_settings.OIDC_REQUEST_OBJECTS_ENABLED = False
        response = _post_register(
            self.client,
            self._data(request_uris=["http://client.example.com/req"], request_object_signing_alg="EdDSA"),
        )
        assert response.status_code == 201, response.content
        body = response.json()
        assert "request_uris" not in body
        assert "request_object_signing_alg" not in body

    def test_stored_request_object_metadata_survives_an_update_while_disabled(self):
        # Registered while enabled, then the feature is turned off: a client
        # updating without the fields must not lose the restrictions they set.
        restrictions = {
            "request_uris": ["https://client.example.com/req"],
            "request_object_signing_alg": "ES256",
        }
        body = _post_register(self.client, self._data(**restrictions)).json()
        self.oauth2_settings.OIDC_REQUEST_OBJECTS_ENABLED = False
        response = self.client.put(
            _management_url(body["client_id"]),
            data=json.dumps({**self._data(), "client_id": body["client_id"]}),
            content_type="application/json",
            **_bearer(body["registration_access_token"]),
        )
        assert response.status_code == 200, response.content
        application = Application.objects.get(client_id=body["client_id"])
        assert application.request_uris == "https://client.example.com/req"
        assert application.request_object_signing_alg == "ES256"
        assert response.json()["request_object_signing_alg"] == "ES256"

    def test_dropping_keys_while_disabled(self):
        # The stored signing alg would need keys, but is unused while disabled.
        body = _post_register(self.client, self._data(request_object_signing_alg="ES256")).json()
        self.oauth2_settings.OIDC_REQUEST_OBJECTS_ENABLED = False
        data = {
            **self._data(token_endpoint_auth_method="client_secret_basic"),
            "client_id": body["client_id"],
        }
        del data["jwks"]
        response = self.client.put(
            _management_url(body["client_id"]),
            data=json.dumps(data),
            content_type="application/json",
            **_bearer(body["registration_access_token"]),
        )
        assert response.status_code == 200, response.content

    def test_error_description_does_not_echo_the_value(self):
        response = _post_register(self.client, self._data(request_object_signing_alg='x"\\é'))
        assert response.status_code == 400
        description = response.json()["error_description"]
        assert '"' not in description and "\\" not in description and "é" not in description

    def test_update_without_request_object_metadata_resets_it(self):
        response = _post_register(
            self.client,
            self._data(request_uris=["https://client.example.com/req"], request_object_signing_alg="ES256"),
        )
        body = response.json()
        response = self.client.put(
            _management_url(body["client_id"]),
            data=json.dumps({**self._data(), "client_id": body["client_id"]}),
            content_type="application/json",
            **_bearer(body["registration_access_token"]),
        )
        assert response.status_code == 200, response.content
        application = Application.objects.get(client_id=body["client_id"])
        assert application.request_uris == ""
        assert application.request_object_signing_alg == ""


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.DCR_SETTINGS)
class TestDCRJwtAuthMethods(TestCase):
    def setUp(self):
        self.user = UserModel.objects.create_user("dcr_jwt_user", "dcr_jwt@example.com", "pass")
        self.client.force_login(self.user)

    def test_register_private_key_jwt_with_jwks(self):
        jwks = _public_jwks()
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": jwks,
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201, response.content
        body = response.json()
        assert body["token_endpoint_auth_method"] == "private_key_jwt"
        assert body["jwks"] == jwks
        # The client authenticates with its key; no secret is issued.
        assert "client_secret" not in body
        assert "client_secret_expires_at" not in body

        application = Application.objects.get(client_id=body["client_id"])
        assert application.token_endpoint_auth_method == "private_key_jwt"
        assert application.client_type == "confidential"
        assert json.loads(application.client_jwks) == jwks
        assert application.client_jwks_uri == ""

    def test_register_private_key_jwt_with_jwks_uri(self):
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks_uri": "https://client.example.com/jwks.json",
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201, response.content
        body = response.json()
        assert body["jwks_uri"] == "https://client.example.com/jwks.json"
        application = Application.objects.get(client_id=body["client_id"])
        assert application.client_jwks_uri == "https://client.example.com/jwks.json"
        assert application.client_jwks == ""

    def test_register_jwks_and_jwks_uri_is_400(self):
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": _public_jwks(),
            "jwks_uri": "https://client.example.com/jwks.json",
        }
        response = _post_register(self.client, data)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_register_private_key_jwt_without_keys_is_400(self):
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "private_key_jwt",
        }
        response = _post_register(self.client, data)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_register_non_string_jwks_uri_is_400(self):
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks_uri": 12345,
        }
        response = _post_register(self.client, data)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_register_malformed_jwks_is_400(self):
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": {"not_keys": []},
        }
        response = _post_register(self.client, data)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_register_client_secret_jwt(self):
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "client_secret_jwt",
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201, response.content
        body = response.json()
        assert body["token_endpoint_auth_method"] == "client_secret_jwt"
        # The secret is the HMAC key: returned raw and stored unhashed.
        assert body["client_secret"]
        assert body["client_secret_expires_at"] == 0
        application = Application.objects.get(client_id=body["client_id"])
        assert application.hash_client_secret is False
        assert application.client_secret == body["client_secret"]

    def test_put_replacement_resets_jwks(self):
        jwks = _public_jwks()
        register = _post_register(
            self.client,
            {
                "redirect_uris": ["https://example.com/cb"],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": jwks,
            },
        )
        assert register.status_code == 201
        body = register.json()

        # Replace with a client_secret_basic registration omitting jwks: the
        # stored key set must be cleared (RFC 7592 full-replacement semantics).
        response = self.client.put(
            _management_url(body["client_id"]),
            data=json.dumps(
                {
                    "redirect_uris": ["https://example.com/cb"],
                    "grant_types": ["authorization_code"],
                    "token_endpoint_auth_method": "client_secret_basic",
                }
            ),
            content_type="application/json",
            **_bearer(body["registration_access_token"]),
        )
        assert response.status_code == 200, response.content
        updated = response.json()
        assert updated["token_endpoint_auth_method"] == "client_secret_basic"
        assert "jwks" not in updated
        application = Application.objects.get(client_id=body["client_id"])
        assert application.client_jwks == ""
        assert application.token_endpoint_auth_method == "client_secret_basic"

    def test_put_private_key_jwt_without_keys_is_400(self):
        register = _post_register(
            self.client,
            {
                "redirect_uris": ["https://example.com/cb"],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": _public_jwks(),
            },
        )
        assert register.status_code == 201
        body = register.json()
        response = self.client.put(
            _management_url(body["client_id"]),
            data=json.dumps(
                {
                    "redirect_uris": ["https://example.com/cb"],
                    "grant_types": ["authorization_code"],
                    "token_endpoint_auth_method": "private_key_jwt",
                }
            ),
            content_type="application/json",
            **_bearer(body["registration_access_token"]),
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_corrupted_stored_jwks_omitted_from_response(self):
        register = _post_register(
            self.client,
            {
                "redirect_uris": ["https://example.com/cb"],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": _public_jwks(),
            },
        )
        assert register.status_code == 201
        body = register.json()

        # Simulate a corrupted row (e.g. a manual DB edit): the management GET
        # must degrade to omitting jwks, never 500.
        Application.objects.filter(client_id=body["client_id"]).update(client_jwks="corrupted{")
        response = self.client.get(
            _management_url(body["client_id"]),
            **_bearer(body["registration_access_token"]),
        )
        assert response.status_code == 200, response.content
        assert "jwks" not in response.json()

    def test_register_non_https_jwks_uri_is_400_with_rfc_field_name(self):
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks_uri": "http://client.example.com/jwks.json",
        }
        response = _post_register(self.client, data)
        assert response.status_code == 400
        body = response.json()
        assert body["error"] == "invalid_client_metadata"
        # RFC 7591 field naming, not the internal client_jwks_uri model field.
        assert "jwks_uri" in body["error_description"]
        assert "client_jwks_uri" not in body["error_description"]

    def test_register_private_key_jwt_with_blank_jwks_uri_uses_rfc_wording(self):
        for blank in ("", "   "):
            data = {
                "redirect_uris": ["https://example.com/cb"],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks_uri": blank,
            }
            response = _post_register(self.client, data)
            assert response.status_code == 400
            body = response.json()
            assert body["error"] == "invalid_client_metadata"
            # RFC 7591 field names, not the internal model field names.
            assert "jwks or jwks_uri" in body["error_description"]
            assert "client_jwks" not in body["error_description"]

    def test_register_jwks_with_blank_jwks_uri_is_accepted(self):
        # A blank jwks_uri counts as absent, so it does not trip the
        # mutual-exclusion check when a real jwks is supplied.
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": _public_jwks(),
            "jwks_uri": "",
        }
        response = _post_register(self.client, data)
        assert response.status_code == 201, response.content
        application = Application.objects.get(client_id=response.json()["client_id"])
        assert application.client_jwks_uri == ""

    def test_private_key_material_never_echoed_in_response(self):
        from jwcrypto import jwk

        register = _post_register(
            self.client,
            {
                "redirect_uris": ["https://example.com/cb"],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": _public_jwks(),
            },
        )
        assert register.status_code == 201
        body = register.json()

        # Simulate a manually edited row holding a private key alongside a
        # public one: the private key must be dropped from the response.
        private_key = json.loads(jwk.JWK.generate(kty="EC", crv="P-256", kid="leaked").export_private())
        public_key = _public_jwks()["keys"][0]
        Application.objects.filter(client_id=body["client_id"]).update(
            client_jwks=json.dumps({"keys": [private_key, public_key]})
        )
        response = self.client.get(
            _management_url(body["client_id"]),
            **_bearer(body["registration_access_token"]),
        )
        assert response.status_code == 200, response.content
        returned = response.json()["jwks"]["keys"]
        assert returned == [public_key]
        assert all("d" not in key for key in returned)

        # All keys private -> the jwks field is omitted entirely.
        Application.objects.filter(client_id=body["client_id"]).update(
            client_jwks=json.dumps({"keys": [private_key]})
        )
        response = self.client.get(
            _management_url(body["client_id"]),
            **_bearer(body["registration_access_token"]),
        )
        assert response.status_code == 200
        assert "jwks" not in response.json()

        # Non-dict entries in the keys list are dropped, not echoed.
        Application.objects.filter(client_id=body["client_id"]).update(
            client_jwks=json.dumps({"keys": ["not-a-jwk", public_key]})
        )
        response = self.client.get(
            _management_url(body["client_id"]),
            **_bearer(body["registration_access_token"]),
        )
        assert response.status_code == 200
        assert response.json()["jwks"]["keys"] == [public_key]

        # Valid JSON but not a JWK Set shape -> omitted as well.
        Application.objects.filter(client_id=body["client_id"]).update(client_jwks='{"kty": "EC"}')
        response = self.client.get(
            _management_url(body["client_id"]),
            **_bearer(body["registration_access_token"]),
        )
        assert response.status_code == 200
        assert "jwks" not in response.json()

    def test_register_unusable_jwks_fails_with_rfc_wording(self):
        from jwcrypto import jwk

        base = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "private_key_jwt",
        }
        private_key = json.loads(jwk.JWK.generate(kty="EC", crv="P-256", kid="p1").export_private())
        enc_key = dict(_public_jwks()["keys"][0], use="enc")
        mixed = {"keys": ["not-a-jwk", _public_jwks()["keys"][0]]}
        for jwks in ({"keys": []}, {"keys": [private_key]}, {"keys": [enc_key]}, mixed):
            response = _post_register(self.client, dict(base, jwks=jwks))
            assert response.status_code == 400, response.content
            body = response.json()
            assert body["error"] == "invalid_client_metadata"
            # RFC 7591 field naming, never the internal model field name.
            assert "jwks" in body["error_description"]
            assert "client_jwks" not in body["error_description"]
