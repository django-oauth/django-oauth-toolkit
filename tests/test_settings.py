import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test.utils import override_settings
from oauthlib.common import Request

from oauth2_provider.admin import (
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
