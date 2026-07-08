"""
Tests for Dynamic Client Registration views (RFC 7591 / RFC 7592).
"""

import json

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse

from oauth2_provider.models import get_access_token_model, get_application_model

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase


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
        assert app.dcr_created is True

    def test_manually_created_application_is_not_dcr_created(self):
        """Applications created outside DCR default to dcr_created=False."""
        app = Application.objects.create(
            name="Manual App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="https://example.com/cb",
        )
        assert app.dcr_created is False

    def test_dcr_created_is_readonly_in_admin(self):
        """dcr_created is a security boundary and must be read-only in the admin.

        The RFC 7592 management endpoint only operates on dcr_created
        applications; an editable admin field would let it be flipped on a
        manually provisioned client and defeat that protection.
        """
        from django.contrib.admin.sites import AdminSite

        from oauth2_provider.admin import ApplicationAdmin

        model_admin = ApplicationAdmin(Application, AdminSite())
        assert "dcr_created" in model_admin.get_readonly_fields(request=None)

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
        app = Application.objects.get(client_id=body["client_id"])
        assert app.client_type == Application.CLIENT_PUBLIC

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
        app = Application.objects.get(client_id=body["client_id"])
        assert app.client_type == Application.CLIENT_CONFIDENTIAL

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

    def test_register_multiple_grant_types_is_400(self):
        """Multiple non-refresh_token grant types → 400."""
        self.client.force_login(self.user)
        data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code", "implicit"],
        }
        response = _post_register(self.client, data)
        assert response.status_code == 400
        body = response.json()
        assert body["error"] == "invalid_client_metadata"

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

        from oauth2_provider.views.dynamic_client_registration import _validation_error_description

        assert _validation_error_description(ValidationError("plain message")) == "plain message"


# ---------------------------------------------------------------------------
# Open registration (AllowAllDCRPermission)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(
    {
        **presets.DCR_SETTINGS,
        "DCR_REGISTRATION_PERMISSION_CLASSES": ("oauth2_provider.dcr.AllowAllDCRPermission",),
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
        "DCR_REGISTRATION_PERMISSION_CLASSES": ("oauth2_provider.dcr.AllowAllDCRPermission",),
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
        """PUT with multiple non-refresh_token grant types → 400."""
        update_data = {
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code", "implicit"],
        }
        response = self.client.put(
            self.management_url,
            data=json.dumps(update_data),
            content_type="application/json",
            **_bearer(self.registration_token),
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

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
# Settings coverage
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(
    {
        **presets.DCR_SETTINGS,
        "DCR_REGISTRATION_PERMISSION_CLASSES": ("oauth2_provider.dcr.AllowAllDCRPermission",),
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
        "DCR_REGISTRATION_PERMISSION_CLASSES": ("oauth2_provider.dcr.AllowAllDCRPermission",),
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
            "oauth2_provider.views.dynamic_client_registration._check_permissions",
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
        "DCR_REGISTRATION_PERMISSION_CLASSES": ("oauth2_provider.dcr.AllowAllDCRPermission",),
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
