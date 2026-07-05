from django.contrib import admin
from django.contrib.auth import get_user_model

from oauth2_provider.models import (
    get_access_token_admin_class,
    get_access_token_model,
    get_application_admin_class,
    get_application_model,
    get_authorization_admin_class,
    get_authorization_model,
    get_grant_admin_class,
    get_grant_model,
    get_id_token_admin_class,
    get_id_token_model,
    get_refresh_token_admin_class,
    get_refresh_token_model,
    get_session_admin_class,
    get_session_model,
)


has_email = hasattr(get_user_model(), "email")


class ApplicationAdmin(admin.ModelAdmin):
    list_display = ("pk", "name", "user", "client_type", "authorization_grant_type")
    list_filter = ("client_type", "authorization_grant_type", "skip_authorization")
    radio_fields = {
        "client_type": admin.HORIZONTAL,
        "authorization_grant_type": admin.VERTICAL,
    }
    search_fields = ("name",) + (("user__email",) if has_email else ())
    raw_id_fields = ("user",)


class AccessTokenAdmin(admin.ModelAdmin):
    list_display = ("token", "user", "application", "expires")
    list_select_related = ("application", "user")
    raw_id_fields = ("user", "source_refresh_token")
    search_fields = ("token",) + (("user__email",) if has_email else ())
    list_filter = ("application",)


class AuthorizationAdmin(admin.ModelAdmin):
    """
    Authorizations are system-created audit records: the admin can inspect
    and *revoke* them, but not create, edit or delete them. Revocation is the
    domain action (it revokes every token issued under the authorization);
    row deletion is reserved for ``cleartokens`` once the tokens are gone.
    """

    list_display = ("pk", "application", "user", "grant_type", "created", "revoked_at")
    list_select_related = ("application", "user")
    search_fields = ("user__email",) if has_email else ()
    list_filter = ("application", "grant_type")
    readonly_fields = (
        "user",
        "application",
        "grant_type",
        "scope",
        "created",
        "updated",
        "revoked_at",
    )
    actions = ["revoke"]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    @admin.action(description="Revoke selected authorizations")
    def revoke(self, request, queryset):
        revoked = 0
        for authorization in queryset:
            if authorization.is_active():
                authorization.revoke()
                revoked += 1
        self.message_user(request, f"{revoked} authorization(s) revoked.")


class SessionAdmin(admin.ModelAdmin):
    list_display = ("sid", "user", "authenticated_at", "expires", "terminated_at", "termination_reason")
    list_select_related = ("user",)
    raw_id_fields = ("user",)
    search_fields = ("sid",) + (("user__email",) if has_email else ())
    list_filter = ("termination_reason",)


class GrantAdmin(admin.ModelAdmin):
    list_display = ("code", "application", "user", "expires")
    raw_id_fields = ("user", "authorization")
    search_fields = ("code",) + (("user__email",) if has_email else ())


class IDTokenAdmin(admin.ModelAdmin):
    list_display = ("jti", "user", "application", "expires")
    raw_id_fields = ("user",)
    search_fields = ("user__email",) if has_email else ()
    list_filter = ("application",)
    list_select_related = ("application", "user")


class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ("token", "user", "application")
    list_select_related = ("application", "user")
    raw_id_fields = ("user", "access_token")
    search_fields = ("token",) + (("user__email",) if has_email else ())
    list_filter = ("application",)


application_model = get_application_model()
authorization_model = get_authorization_model()
access_token_model = get_access_token_model()
grant_model = get_grant_model()
id_token_model = get_id_token_model()
refresh_token_model = get_refresh_token_model()
session_model = get_session_model()

application_admin_class = get_application_admin_class()
authorization_admin_class = get_authorization_admin_class()
access_token_admin_class = get_access_token_admin_class()
grant_admin_class = get_grant_admin_class()
id_token_admin_class = get_id_token_admin_class()
refresh_token_admin_class = get_refresh_token_admin_class()
session_admin_class = get_session_admin_class()

admin.site.register(application_model, application_admin_class)
admin.site.register(authorization_model, authorization_admin_class)
admin.site.register(access_token_model, access_token_admin_class)
admin.site.register(grant_model, grant_admin_class)
admin.site.register(id_token_model, id_token_admin_class)
admin.site.register(refresh_token_model, refresh_token_admin_class)
admin.site.register(session_model, session_admin_class)
