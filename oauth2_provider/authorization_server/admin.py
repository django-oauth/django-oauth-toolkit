from django.contrib import admin
from django.contrib.auth import get_user_model

from oauth2_provider.authorization_server.forms import ApplicationForm
from oauth2_provider.models import (
    get_access_token_admin_class,
    get_access_token_model,
    get_application_admin_class,
    get_application_model,
    get_grant_admin_class,
    get_grant_model,
    get_id_token_admin_class,
    get_id_token_model,
    get_refresh_token_admin_class,
    get_refresh_token_model,
)


has_email = hasattr(get_user_model(), "email")

# Non-secret user identifiers used to keep the credential changelists searchable by user.
# Always include the user model's USERNAME_FIELD (so custom user models without an ``email``
# attribute still support "search by user"), plus ``email`` when it exists and differs from it.
_username_field = get_user_model().USERNAME_FIELD
USER_SEARCH_FIELDS = ("user__%s" % _username_field,)
if has_email and _username_field != "email":
    USER_SEARCH_FIELDS += ("user__email",)


# Only reveal a short suffix of a credential, and only when the value is long enough
# that the suffix is a small fraction of it. Shorter values are fully masked so a masked
# value never exposes most of a (potentially low-entropy) secret.
MASK_MIN_LENGTH = 16
MASK_SUFFIX_LENGTH = 4


def mask_credential(value):
    """
    Return a masked representation of a token/code that identifies a row in the
    admin without exposing the usable credential.

    Access/refresh tokens and authorization codes are stored in cleartext, so
    showing them verbatim (or making them searchable) would expose live,
    replayable credentials to any staff user with view access — and, for
    ``search_fields``, would leak them into the ``?q=`` query string captured by
    server access logs and browser history. Falsy values (``""``/``None``) are
    returned unchanged. Non-empty values shorter than ``MASK_MIN_LENGTH``
    characters are fully masked; values of at least that length reveal only
    their last ``MASK_SUFFIX_LENGTH`` characters, which is enough to correlate a
    row without meaningfully aiding a brute force of a high-entropy token.
    """
    if not value:
        return value
    if len(value) < MASK_MIN_LENGTH:
        return "…"
    return "…%s" % value[-MASK_SUFFIX_LENGTH:]


class ApplicationAdmin(admin.ModelAdmin):
    # Reuse the front-end ApplicationForm so the admin gets the same
    # hash_client_secret-driven client_secret help text (and the shared
    # application_form.js that updates it live as the checkbox is toggled).
    form = ApplicationForm
    list_display = ("pk", "name", "user", "client_type", "authorization_grant_type", "registration_source")
    list_filter = ("client_type", "authorization_grant_type", "skip_authorization", "registration_source")
    radio_fields = {
        "client_type": admin.HORIZONTAL,
        "authorization_grant_type": admin.VERTICAL,
    }
    search_fields = ("name",) + (("user__email",) if has_email else ())
    raw_id_fields = ("user",)
    # registration_source is a security boundary: the RFC 7592 management endpoint
    # only operates on applications registered via DCR, and the CIMD resolver only
    # refreshes applications registered via CIMD. It reflects how the client was
    # created and must not be editable in the admin, or a manually provisioned
    # application could be handed over to those code paths (e.g. by flipping it
    # to "dcr"). cimd_expires_at is maintained by the CIMD resolver.
    readonly_fields = ("registration_source", "cimd_expires_at")


class AccessTokenAdmin(admin.ModelAdmin):
    list_display = ("pk", "masked_token", "user", "application", "expires")
    list_select_related = ("application", "user")
    raw_id_fields = ("user", "source_refresh_token")
    # Search by non-secret identifiers only; never by the token itself.
    search_fields = ("application__client_id", "application__name") + USER_SEARCH_FIELDS
    list_filter = ("application",)

    def has_add_permission(self, request):
        # Access tokens are issued by the OAuth flows, not hand-created in the admin.
        # Disabling add also removes the add form's editable (cleartext) token field.
        return False

    def get_exclude(self, request, obj=None):
        # Hide the raw token on the change/view form (obj is set). Adding is disabled
        # (see has_add_permission), so the add form is unreachable; guarding on obj keeps
        # this correct if a subclass ever re-enables it. Extend, rather than replace, any
        # exclude configured on a subclass.
        exclude = tuple(super().get_exclude(request, obj) or ())
        if obj is not None and "token" not in exclude:
            exclude += ("token",)
        return exclude

    def get_readonly_fields(self, request, obj=None):
        readonly_fields = tuple(super().get_readonly_fields(request, obj))
        if obj is not None and "masked_token" not in readonly_fields:
            readonly_fields += ("masked_token",)
        return readonly_fields

    @admin.display(description="token")
    def masked_token(self, obj):
        return mask_credential(obj.token) if obj is not None else ""


class GrantAdmin(admin.ModelAdmin):
    list_display = ("pk", "masked_code", "application", "user", "expires")
    raw_id_fields = ("user",)
    # Search by non-secret identifiers only; never by the authorization code itself.
    search_fields = ("application__client_id", "application__name") + USER_SEARCH_FIELDS

    def has_add_permission(self, request):
        # Authorization codes are issued by the OAuth flows, not hand-created in the admin.
        return False

    def get_exclude(self, request, obj=None):
        # Hide the raw code on the change/view form. Adding is disabled (see
        # has_add_permission), so the add form is unreachable; guarding on obj keeps this
        # correct if a subclass ever re-enables it. Extend, rather than replace, any exclude
        # configured on a subclass.
        exclude = tuple(super().get_exclude(request, obj) or ())
        if obj is not None and "code" not in exclude:
            exclude += ("code",)
        return exclude

    def get_readonly_fields(self, request, obj=None):
        readonly_fields = tuple(super().get_readonly_fields(request, obj))
        if obj is not None and "masked_code" not in readonly_fields:
            readonly_fields += ("masked_code",)
        return readonly_fields

    @admin.display(description="code")
    def masked_code(self, obj):
        return mask_credential(obj.code) if obj is not None else ""


class IDTokenAdmin(admin.ModelAdmin):
    list_display = ("jti", "user", "application", "expires")
    raw_id_fields = ("user",)
    # Search by non-secret identifiers only, consistent with the other credential admins and
    # resilient to custom user models without an ``email`` field (see USER_SEARCH_FIELDS).
    search_fields = ("application__client_id", "application__name") + USER_SEARCH_FIELDS
    list_filter = ("application",)
    list_select_related = ("application", "user")

    def has_add_permission(self, request):
        # ID tokens are issued by the OIDC flows, not hand-created in the admin.
        return False


class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ("pk", "masked_token", "user", "application")
    list_select_related = ("application", "user")
    raw_id_fields = ("user", "access_token")
    # Search by non-secret identifiers only; never by the token itself.
    search_fields = ("application__client_id", "application__name") + USER_SEARCH_FIELDS
    list_filter = ("application",)

    def has_add_permission(self, request):
        # Refresh tokens are issued by the OAuth flows, not hand-created in the admin.
        return False

    def get_exclude(self, request, obj=None):
        # Hide the raw token on the change/view form. Adding is disabled (see
        # has_add_permission), so the add form is unreachable; guarding on obj keeps this
        # correct if a subclass ever re-enables it. Extend, rather than replace, any exclude
        # configured on a subclass.
        exclude = tuple(super().get_exclude(request, obj) or ())
        if obj is not None and "token" not in exclude:
            exclude += ("token",)
        return exclude

    def get_readonly_fields(self, request, obj=None):
        readonly_fields = tuple(super().get_readonly_fields(request, obj))
        if obj is not None and "masked_token" not in readonly_fields:
            readonly_fields += ("masked_token",)
        return readonly_fields

    @admin.display(description="token")
    def masked_token(self, obj):
        return mask_credential(obj.token) if obj is not None else ""


application_model = get_application_model()
access_token_model = get_access_token_model()
grant_model = get_grant_model()
id_token_model = get_id_token_model()
refresh_token_model = get_refresh_token_model()

application_admin_class = get_application_admin_class()
access_token_admin_class = get_access_token_admin_class()
grant_admin_class = get_grant_admin_class()
id_token_admin_class = get_id_token_admin_class()
refresh_token_admin_class = get_refresh_token_admin_class()

admin.site.register(application_model, application_admin_class)
admin.site.register(access_token_model, access_token_admin_class)
admin.site.register(grant_model, grant_admin_class)
admin.site.register(id_token_model, id_token_admin_class)
admin.site.register(refresh_token_model, refresh_token_admin_class)
