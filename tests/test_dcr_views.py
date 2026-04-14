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
        assert Application.objects.filter(client_id=body["client_id"]).exists()

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

    def test_get_wrong_token_is_401(self):
        """GET without token → 401."""
        response = self.client.get(self.management_url)
        assert response.status_code == 401

    def test_get_token_wrong_client_is_403(self):
        """GET with token for a different client → 403."""
        # Create a second application with its own token
        self.client.force_login(self.user)
        data2 = {"redirect_uris": ["https://other.com/cb"], "grant_types": ["authorization_code"]}
        r2 = _post_register(self.client, data2)
        other_token = r2.json()["registration_access_token"]
        self.client.logout()

        response = self.client.get(self.management_url, **_bearer(other_token))
        assert response.status_code == 403

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

    # -- DELETE --------------------------------------------------------------

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
