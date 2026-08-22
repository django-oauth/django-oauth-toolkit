from datetime import timedelta

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test.utils import override_settings
from oauthlib.common import Request

from oauth2_provider.authorization_server.admin import (
    get_access_token_admin_class,
    get_application_admin_class,
    get_grant_admin_class,
    get_id_token_admin_class,
    get_refresh_token_admin_class,
)
from oauth2_provider.settings import OAuth2ProviderSettings, oauth2_settings, perform_import
from tests.admin import (
    CustomAccessTokenAdmin,
    CustomApplicationAdmin,
    CustomGrantAdmin,
    CustomIDTokenAdmin,
    CustomRefreshTokenAdmin,
)
from tests.common_testing import OAuth2ProviderTestCase as TestCase

from . import presets


class TestAdminClass(TestCase):
    def test_import_error_message_maintained(self):
        """
        Make sure import errors are captured and raised sensibly.
        """
        settings = OAuth2ProviderSettings({"CLIENT_ID_GENERATOR_CLASS": "invalid_module.InvalidClassName"})
        with self.assertRaises(ImportError):
            settings.CLIENT_ID_GENERATOR_CLASS

    def test_get_application_admin_class(self):
        """
        Test for getting class for application admin.
        """
        application_admin_class = get_application_admin_class()
        default_application_admin_class = oauth2_settings.APPLICATION_ADMIN_CLASS
        assert application_admin_class == default_application_admin_class

    def test_get_access_token_admin_class(self):
        """
        Test for getting class for access token admin.
        """
        access_token_admin_class = get_access_token_admin_class()
        default_access_token_admin_class = oauth2_settings.ACCESS_TOKEN_ADMIN_CLASS
        assert access_token_admin_class == default_access_token_admin_class

    def test_get_grant_admin_class(self):
        """
        Test for getting class for grant admin.
        """
        grant_admin_class = get_grant_admin_class()
        default_grant_admin_class = oauth2_settings.GRANT_ADMIN_CLASS
        assert grant_admin_class == default_grant_admin_class

    def test_get_id_token_admin_class(self):
        """
        Test for getting class for ID token admin.
        """
        id_token_admin_class = get_id_token_admin_class()
        default_id_token_admin_class = oauth2_settings.ID_TOKEN_ADMIN_CLASS
        assert id_token_admin_class == default_id_token_admin_class

    def test_get_refresh_token_admin_class(self):
        """
        Test for getting class for refresh token admin.
        """
        refresh_token_admin_class = get_refresh_token_admin_class()
        default_refresh_token_admin_class = oauth2_settings.REFRESH_TOKEN_ADMIN_CLASS
        assert refresh_token_admin_class == default_refresh_token_admin_class

    @override_settings(OAUTH2_PROVIDER={"APPLICATION_ADMIN_CLASS": "tests.admin.CustomApplicationAdmin"})
    def test_get_custom_application_admin_class(self):
        """
        Test for getting custom class for application admin.
        """
        application_admin_class = get_application_admin_class()
        assert application_admin_class == CustomApplicationAdmin

    @override_settings(OAUTH2_PROVIDER={"ACCESS_TOKEN_ADMIN_CLASS": "tests.admin.CustomAccessTokenAdmin"})
    def test_get_custom_access_token_admin_class(self):
        """
        Test for getting custom class for access token admin.
        """
        access_token_admin_class = get_access_token_admin_class()
        assert access_token_admin_class == CustomAccessTokenAdmin

    @override_settings(OAUTH2_PROVIDER={"GRANT_ADMIN_CLASS": "tests.admin.CustomGrantAdmin"})
    def test_get_custom_grant_admin_class(self):
        """
        Test for getting custom class for grant admin.
        """
        grant_admin_class = get_grant_admin_class()
        assert grant_admin_class == CustomGrantAdmin

    @override_settings(OAUTH2_PROVIDER={"ID_TOKEN_ADMIN_CLASS": "tests.admin.CustomIDTokenAdmin"})
    def test_get_custom_id_token_admin_class(self):
        """
        Test for getting custom class for ID token admin.
        """
        id_token_admin_class = get_id_token_admin_class()
        assert id_token_admin_class == CustomIDTokenAdmin

    @override_settings(OAUTH2_PROVIDER={"REFRESH_TOKEN_ADMIN_CLASS": "tests.admin.CustomRefreshTokenAdmin"})
    def test_get_custom_refresh_token_admin_class(self):
        """
        Test for getting custom class for refresh token admin.
        """
        refresh_token_admin_class = get_refresh_token_admin_class()
        assert refresh_token_admin_class == CustomRefreshTokenAdmin


def test_perform_import_when_none():
    assert perform_import(None, "REFRESH_TOKEN_ADMIN_CLASS") is None


def test_perform_import_list():
    imports = ["tests.admin.CustomIDTokenAdmin", "tests.admin.CustomGrantAdmin"]
    assert perform_import(imports, "SOME_CLASSES") == [CustomIDTokenAdmin, CustomGrantAdmin]


def test_perform_import_already_imported():
    cls = perform_import(CustomRefreshTokenAdmin, "REFRESH_TOKEN_ADMIN_CLASS")
    assert cls == CustomRefreshTokenAdmin


def test_invalid_scopes_raises_error():
    settings = OAuth2ProviderSettings(
        {
            "SCOPES": {"foo": "foo scope"},
            "DEFAULT_SCOPES": ["bar"],
        }
    )
    with pytest.raises(ImproperlyConfigured) as exc:
        settings._DEFAULT_SCOPES
    assert str(exc.value) == "Defined DEFAULT_SCOPES not present in SCOPES"


def test_missing_mandatory_setting_raises_error():
    settings = OAuth2ProviderSettings(
        user_settings={}, defaults={"very_important": None}, mandatory=["very_important"]
    )
    with pytest.raises(AttributeError) as exc:
        settings.very_important
    assert str(exc.value) == "OAuth2Provider setting: very_important is mandatory"


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
@pytest.mark.parametrize("issuer_setting", ["http://foo.com/", None])
@pytest.mark.parametrize("request_type", ["django", "oauthlib"])
def test_generating_iss_endpoint(oauth2_settings, issuer_setting, request_type, rf):
    oauth2_settings.OIDC_ISS_ENDPOINT = issuer_setting
    if request_type == "django":
        request = rf.get("/")
    elif request_type == "oauthlib":
        request = Request("/", headers=rf.get("/").META)
    expected = issuer_setting or "http://testserver/o"
    assert oauth2_settings.oidc_issuer(request) == expected


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_generating_iss_endpoint_type_error(oauth2_settings):
    oauth2_settings.OIDC_ISS_ENDPOINT = None
    with pytest.raises(TypeError) as exc:
        oauth2_settings.oidc_issuer(None)
    assert str(exc.value) == "request must be a django or oauthlib request: got None"


def test_pkce_required_is_default():
    settings = OAuth2ProviderSettings()
    assert settings.PKCE_REQUIRED is True


def test_authentication_server_exp_time_zone_warns_when_configured():
    with pytest.warns(DeprecationWarning, match="AUTHENTICATION_SERVER_EXP_TIME_ZONE"):
        OAuth2ProviderSettings({"AUTHENTICATION_SERVER_EXP_TIME_ZONE": "Europe/Berlin"})


def test_authentication_server_exp_time_zone_no_warning_when_not_configured(recwarn):
    OAuth2ProviderSettings({})
    assert not [w for w in recwarn.list if issubclass(w.category, DeprecationWarning)]


def test_oidc_server_class_user_override_used_when_oidc_enabled():
    """
    When OIDC is enabled and OAUTH2_SERVER_CLASS is not user overridden,
    the user-overridden OIDC_SERVER_CLASS must be returned (not the default).
    """
    custom = "tests.admin.CustomApplicationAdmin"  # any importable class works for the test
    settings = OAuth2ProviderSettings(
        user_settings={
            "OIDC_ENABLED": True,
            "OIDC_SERVER_CLASS": custom,
        }
    )
    assert settings.OAUTH2_SERVER_CLASS is CustomApplicationAdmin


def test_oidc_server_class_default_used_when_neither_overridden():
    """When OIDC is enabled and neither *_SERVER_CLASS is overridden, fall back to OIDC default."""
    from oauthlib.openid import Server as OIDCServer

    settings = OAuth2ProviderSettings(user_settings={"OIDC_ENABLED": True})
    assert settings.OAUTH2_SERVER_CLASS is OIDCServer


class TestRefreshTokenAdminSelectRelated(TestCase):
    def test_changelist_queryset_select_related_is_bounded(self):
        """
        RefreshTokenAdmin changelist must not use unbounded select_related.

        The default (list_select_related = False) causes Django to call qs.select_related()
        with no arguments when list_display contains FK fields, recursively following every
        FK in the model graph. On MySQL, this can produce a query with so many columns that
        it exceeds the server's column limit and raises an error.

        list_select_related = ("application", "user") makes Django call
        qs.select_related("application", "user") instead, bounding the JOIN.
        """
        from django.contrib.admin.sites import AdminSite
        from django.contrib.auth import get_user_model
        from django.test import RequestFactory

        from oauth2_provider.authorization_server.admin import RefreshTokenAdmin
        from oauth2_provider.models import get_refresh_token_model

        UserModel = get_user_model()
        RefreshToken = get_refresh_token_model()

        admin_user = UserModel.objects.create_superuser("admin", "admin@example.com", "password")
        request = RequestFactory().get("/")
        request.user = admin_user
        ma = RefreshTokenAdmin(RefreshToken, AdminSite())
        qs = ma.get_queryset(request)

        # Replicate what ChangeList.apply_select_related does with list_select_related.
        if ma.list_select_related is True:
            qs = qs.select_related()
        elif ma.list_select_related:
            qs = qs.select_related(*ma.list_select_related)

        # qs.query.select_related is True when called with no arguments (unbounded).
        # It must be a dict so the JOIN is scoped to only the declared fields.
        self.assertIsInstance(qs.query.select_related, dict)
        self.assertEqual(set(qs.query.select_related.keys()), {"application", "user"})


def _expires_in_by_grant_type(request):
    """Sample dynamic ACCESS_TOKEN_EXPIRE_SECONDS, referenced by dotted path below."""
    return 60 if request.grant_type == "client_credentials" else 600


class TestAccessTokenExpiresIn(TestCase):
    """``ACCESS_TOKEN_EXPIRE_SECONDS`` accepts seconds, a timedelta, or a callable."""

    def test_int_is_returned_unchanged(self):
        settings = OAuth2ProviderSettings({"ACCESS_TOKEN_EXPIRE_SECONDS": 120})
        assert settings.access_token_expires_in() == 120

    def test_timedelta_is_coerced_to_seconds(self):
        settings = OAuth2ProviderSettings({"ACCESS_TOKEN_EXPIRE_SECONDS": timedelta(minutes=5)})
        assert settings.access_token_expires_in() == 300

    def test_callable_is_evaluated_with_the_request(self):
        settings = OAuth2ProviderSettings(
            {"ACCESS_TOKEN_EXPIRE_SECONDS": lambda request: 42 if request.grant_type == "password" else 7}
        )
        request = Request("/o/token/")
        request.grant_type = "password"
        assert settings.access_token_expires_in(request) == 42

    def test_callable_may_return_a_timedelta(self):
        settings = OAuth2ProviderSettings({"ACCESS_TOKEN_EXPIRE_SECONDS": lambda request: timedelta(hours=2)})
        assert settings.access_token_expires_in(Request("/o/token/")) == 7200

    def test_import_string_resolves_to_the_callable(self):
        settings = OAuth2ProviderSettings(
            {"ACCESS_TOKEN_EXPIRE_SECONDS": "tests.test_settings._expires_in_by_grant_type"}
        )
        assert settings.ACCESS_TOKEN_EXPIRE_SECONDS is _expires_in_by_grant_type
        request = Request("/o/token/")
        request.grant_type = "client_credentials"
        assert settings.access_token_expires_in(request) == 60

    def test_invalid_static_value_is_rejected(self):
        # True is an int subclass, so it would otherwise sneak through as "1 second".
        for value in (0, -1, True, None, object()):
            with self.subTest(value=value):
                settings = OAuth2ProviderSettings({"ACCESS_TOKEN_EXPIRE_SECONDS": value})
                with pytest.raises(ImproperlyConfigured, match="ACCESS_TOKEN_EXPIRE_SECONDS"):
                    settings.access_token_expires_in()

    def test_unimportable_string_names_the_setting(self):
        # The setting is import-string aware, so a string is treated as a dotted path to
        # the callable rather than as a number of seconds.
        settings = OAuth2ProviderSettings({"ACCESS_TOKEN_EXPIRE_SECONDS": "3600"})
        with pytest.raises(ImportError, match="ACCESS_TOKEN_EXPIRE_SECONDS"):
            settings.access_token_expires_in()

    def test_invalid_callable_return_value_is_rejected(self):
        settings = OAuth2ProviderSettings({"ACCESS_TOKEN_EXPIRE_SECONDS": lambda request: -5})
        with pytest.raises(ImproperlyConfigured, match="ACCESS_TOKEN_EXPIRE_SECONDS must be positive"):
            settings.access_token_expires_in(Request("/o/token/"))


class TestServerKwargsTokenExpiresIn(TestCase):
    """``server_kwargs`` hands oauthlib a number for a static setting, a callable for a dynamic one."""

    def test_static_setting_is_resolved_to_an_int(self):
        settings = OAuth2ProviderSettings({"ACCESS_TOKEN_EXPIRE_SECONDS": timedelta(minutes=1)})
        assert settings.server_kwargs["token_expires_in"] == 60

    def test_callable_setting_is_passed_through_for_per_request_evaluation(self):
        settings = OAuth2ProviderSettings(
            {"ACCESS_TOKEN_EXPIRE_SECONDS": "tests.test_settings._expires_in_by_grant_type"}
        )
        token_expires_in = settings.server_kwargs["token_expires_in"]
        request = Request("/o/token/")
        request.grant_type = "authorization_code"
        assert callable(token_expires_in)
        assert token_expires_in(request) == 600

    def test_extra_server_kwargs_still_wins(self):
        settings = OAuth2ProviderSettings(
            {
                "ACCESS_TOKEN_EXPIRE_SECONDS": 100,
                "EXTRA_SERVER_KWARGS": {"token_expires_in": 200},
            }
        )
        assert settings.server_kwargs["token_expires_in"] == 200
