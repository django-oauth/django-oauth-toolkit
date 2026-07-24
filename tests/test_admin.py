"""
Tests for the default admin classes, ensuring that cleartext bearer tokens and
authorization codes are never exposed verbatim (in ``list_display``, in the
change/view form, or via ``__str__``) nor made searchable (in ``search_fields``,
which would leak them into the ``?q=`` query string and therefore into access
logs / browser history).
"""

from django.contrib.admin.sites import AdminSite
from django.test import RequestFactory

from oauth2_provider.admin import (
    AccessTokenAdmin,
    GrantAdmin,
    IDTokenAdmin,
    PushedAuthorizationRequestAdmin,
    RefreshTokenAdmin,
    mask_credential,
)
from oauth2_provider.models import (
    get_access_token_model,
    get_grant_model,
    get_id_token_model,
    get_par_request_model,
    get_refresh_token_model,
)


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


def test_par_admin_does_not_expose_request_uri():
    # request_uri is a single-use bearer reference; it must not be searchable or rendered verbatim.
    assert "request_uri" not in PushedAuthorizationRequestAdmin.list_display
    assert "request_uri" not in PushedAuthorizationRequestAdmin.search_fields
    _assert_hidden_on_change_form(
        PushedAuthorizationRequestAdmin, get_par_request_model(), "request_uri", "masked_request_uri"
    )


def test_id_token_admin_searchable_by_app_and_user():
    # IDTokenAdmin holds no cleartext replayable secret, but its search should stay
    # consistent with the other credential admins (and non-empty on custom user models).
    _assert_searchable_by_app_and_user(IDTokenAdmin)
