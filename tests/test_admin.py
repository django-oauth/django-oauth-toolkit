"""
Tests for the default admin classes, ensuring that cleartext bearer tokens and
authorization codes are never exposed verbatim (in ``list_display``, in the
change/view form, or via ``__str__``) nor made searchable (in ``search_fields``,
which would leak them into the ``?q=`` query string and therefore into access
logs / browser history).
"""

import pytest
from django.contrib import admin
from django.contrib.admin.sites import AdminSite
from django.contrib.auth import get_user_model
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import RequestFactory
from django.utils import timezone

from oauth2_provider.admin import (
    AccessTokenAdmin,
    GrantAdmin,
    IDTokenAdmin,
    RefreshTokenAdmin,
    mask_credential,
)
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_grant_model,
    get_id_token_model,
    get_refresh_token_model,
)


class _PermissiveUser:
    """A minimal stand-in for an authenticated superuser, so admin permission checks pass
    without a database user."""

    is_active = True
    is_staff = True
    is_superuser = True

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True


def _admin_form_fields(admin_class, model, obj):
    """
    Return the fields the admin form would render. Pass ``obj=None`` for the add
    form and an instance for the change/view form (the two can differ).
    """
    request = RequestFactory().get("/")
    model_admin = admin_class(model, AdminSite())
    return list(model_admin.get_form(request, obj=obj).base_fields)


def test_mask_credential_hides_the_secret():
    # A long value reveals only its last few characters.
    assert mask_credential("abcdef1234567890") == "…7890"
    # Short (non-empty) values are fully masked and reveal nothing.
    assert mask_credential("short") == "…"
    # Falsy values are returned unchanged (nothing to mask).
    assert mask_credential("") == ""
    assert mask_credential(None) is None
    # Boundary: a value just over the old 6-char threshold must not reveal most of itself.
    assert mask_credential("abcdefg") == "…"
    # Boundary: just below the minimum reveal length is still fully masked.
    assert mask_credential("a" * 15) == "…"
    # At the minimum length only the last few characters are shown.
    assert mask_credential("b" * 16) == "…bbbb"
    # The full secret is never returned, regardless of length.
    for secret in ("abcdefg", "supersecrettokenvalue", "x" * 40):
        assert secret not in mask_credential(secret)


def _assert_hidden_on_change_form(admin_class, model, field, masked_field):
    site = AdminSite()
    model_admin = admin_class(model, site)
    request = RequestFactory().get("/")
    obj = model()  # a (dummy) instance -> change-form context, not the add form
    # The raw secret field is not rendered on the change/view form; a masked value is shown.
    assert field not in _admin_form_fields(admin_class, model, obj=obj)
    assert masked_field in model_admin.get_readonly_fields(request, obj=obj)
    # masked_* must be safe to render even for an unsaved / None object.
    assert getattr(model_admin, masked_field)(None) == ""
    # Adding credentials via the admin is disabled; they are issued by the OAuth flows.
    assert model_admin.has_add_permission(request) is False


def test_credential_admins_disable_add():
    """Credential models must not be hand-created in the admin (issued by the OAuth flows)."""
    request = RequestFactory().get("/")
    for admin_class, model in (
        (AccessTokenAdmin, get_access_token_model()),
        (RefreshTokenAdmin, get_refresh_token_model()),
        (GrantAdmin, get_grant_model()),
        (IDTokenAdmin, get_id_token_model()),
    ):
        model_admin = admin_class(model, AdminSite())
        assert model_admin.has_add_permission(request) is False


def test_admin_overrides_preserve_subclass_config():
    """get_exclude/get_readonly_fields extend, rather than replace, a subclass's config."""

    class CustomAccessTokenAdmin(AccessTokenAdmin):
        exclude = ("expires",)
        readonly_fields = ("created",)

    model = get_access_token_model()
    model_admin = CustomAccessTokenAdmin(model, AdminSite())
    request = RequestFactory().get("/")
    obj = model()

    exclude = model_admin.get_exclude(request, obj=obj)
    assert "expires" in exclude  # subclass configuration is preserved ...
    assert "token" in exclude  # ... and our secret-hiding is still applied

    readonly = model_admin.get_readonly_fields(request, obj=obj)
    assert "created" in readonly
    assert "masked_token" in readonly


def _assert_searchable_by_app_and_user(admin_class):
    # Search stays available by non-secret application identifiers ...
    assert "application__client_id" in admin_class.search_fields
    assert "application__name" in admin_class.search_fields
    # ... and by a non-secret user identifier (the USERNAME_FIELD, e.g. "username").
    assert any(field.startswith("user__") for field in admin_class.search_fields)


def test_access_token_admin_does_not_expose_token():
    assert "token" not in AccessTokenAdmin.list_display
    assert "token" not in AccessTokenAdmin.search_fields
    _assert_searchable_by_app_and_user(AccessTokenAdmin)
    _assert_hidden_on_change_form(AccessTokenAdmin, get_access_token_model(), "token", "masked_token")


def test_refresh_token_admin_does_not_expose_token():
    assert "token" not in RefreshTokenAdmin.list_display
    assert "token" not in RefreshTokenAdmin.search_fields
    _assert_searchable_by_app_and_user(RefreshTokenAdmin)
    _assert_hidden_on_change_form(RefreshTokenAdmin, get_refresh_token_model(), "token", "masked_token")


def test_grant_admin_does_not_expose_code():
    assert "code" not in GrantAdmin.list_display
    assert "code" not in GrantAdmin.search_fields
    _assert_searchable_by_app_and_user(GrantAdmin)
    _assert_hidden_on_change_form(GrantAdmin, get_grant_model(), "code", "masked_code")


def test_id_token_admin_searchable_by_app_and_user():
    # IDTokenAdmin holds no cleartext replayable secret, but its search should stay
    # consistent with the other credential admins (and non-empty on custom user models).
    _assert_searchable_by_app_and_user(IDTokenAdmin)


def test_credential_admins_delete_policy():
    """Access/refresh tokens are invalidated via the revoke action, not raw delete (a raw delete
    would orphan the paired token / discard the reuse-protection tombstone). Grants and ID tokens
    keep Django's default delete."""
    request = RequestFactory().get("/")
    # get_actions() can consult request.user for permission-gated actions; a RequestFactory
    # request has none, so attach a permissive stub (no DB needed) to keep the assertion robust.
    request.user = _PermissiveUser()
    for admin_class, model in (
        (AccessTokenAdmin, get_access_token_model()),
        (RefreshTokenAdmin, get_refresh_token_model()),
    ):
        model_admin = admin_class(model, AdminSite())
        assert model_admin.has_delete_permission(request) is False
        assert "revoke_tokens" in model_admin.get_actions(request)
    # Grants and ID tokens don't override delete -- they keep Django's default policy.
    assert GrantAdmin.has_delete_permission is admin.ModelAdmin.has_delete_permission
    assert IDTokenAdmin.has_delete_permission is admin.ModelAdmin.has_delete_permission


def _request_with_messages():
    # message_user() needs the messages framework attached to the request.
    request = RequestFactory().post("/")
    # A real session (via SessionMiddleware) so message_user() works even if the messages
    # framework falls back from cookie to session storage.
    SessionMiddleware(lambda r: None).process_request(request)
    setattr(request, "_messages", FallbackStorage(request))
    return request


def _make_application(user):
    Application = get_application_model()
    return Application.objects.create(
        name="revoke-test-app",
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="https://example.com/callback",
        user=user,
    )


@pytest.mark.django_db(databases="__all__")
def test_access_token_admin_revoke_action_revokes_token_family():
    UserModel = get_user_model()
    AccessToken = get_access_token_model()
    RefreshToken = get_refresh_token_model()

    user = UserModel.objects.create_user(username="revoke-at")
    app = _make_application(user)
    access_token = AccessToken.objects.create(
        user=user, token="at-to-revoke", application=app, expires=timezone.now(), scope="read"
    )
    refresh_token = RefreshToken.objects.create(
        user=user, token="rt-bound", application=app, access_token=access_token
    )

    model_admin = AccessTokenAdmin(AccessToken, AdminSite())
    model_admin.revoke_tokens(_request_with_messages(), AccessToken.objects.filter(pk=access_token.pk))

    # The access token is gone and the bound refresh token is revoked (kept as a tombstone).
    assert not AccessToken.objects.filter(pk=access_token.pk).exists()
    refresh_token.refresh_from_db()
    assert refresh_token.revoked is not None


@pytest.mark.django_db(databases="__all__")
def test_access_token_admin_revoke_action_without_refresh_token_deletes():
    UserModel = get_user_model()
    AccessToken = get_access_token_model()

    user = UserModel.objects.create_user(username="revoke-at-solo")
    app = _make_application(user)
    access_token = AccessToken.objects.create(
        user=user, token="at-solo", application=app, expires=timezone.now(), scope="read"
    )

    model_admin = AccessTokenAdmin(AccessToken, AdminSite())
    model_admin.revoke_tokens(_request_with_messages(), AccessToken.objects.filter(pk=access_token.pk))

    assert not AccessToken.objects.filter(pk=access_token.pk).exists()


@pytest.mark.django_db(databases="__all__")
def test_refresh_token_admin_revoke_action_revokes_token_family():
    UserModel = get_user_model()
    AccessToken = get_access_token_model()
    RefreshToken = get_refresh_token_model()

    user = UserModel.objects.create_user(username="revoke-rt")
    app = _make_application(user)
    access_token = AccessToken.objects.create(
        user=user, token="at-bound", application=app, expires=timezone.now(), scope="read"
    )
    refresh_token = RefreshToken.objects.create(
        user=user, token="rt-to-revoke", application=app, access_token=access_token
    )

    model_admin = RefreshTokenAdmin(RefreshToken, AdminSite())
    model_admin.revoke_tokens(_request_with_messages(), RefreshToken.objects.filter(pk=refresh_token.pk))

    # Revoking the refresh token revokes the bound access token (deletes it) and tombstones itself.
    assert not AccessToken.objects.filter(pk=access_token.pk).exists()
    refresh_token.refresh_from_db()
    assert refresh_token.revoked is not None
