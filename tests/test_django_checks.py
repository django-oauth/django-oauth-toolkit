from copy import deepcopy

from django.core.management import call_command
from django.core.management.base import SystemCheckError
from django.test import override_settings

from .common_testing import OAuth2ProviderTestCase as TestCase
from .presets import OIDC_SETTINGS_BACKCHANNEL_LOGOUT


BAD_HANDLER_SETTINGS = deepcopy(OIDC_SETTINGS_BACKCHANNEL_LOGOUT)
BAD_HANDLER_SETTINGS["OIDC_BACKCHANNEL_LOGOUT_HANDLER"] = "sys.api_version"

MISSING_ISS_OIDC_ENDPOINT = deepcopy(OIDC_SETTINGS_BACKCHANNEL_LOGOUT)
MISSING_ISS_OIDC_ENDPOINT["OIDC_ISS_ENDPOINT"] = None


class DjangoChecksTestCase(TestCase):
    def test_checks_pass(self):
        call_command("check")

    # CrossDatabaseRouter claims AccessToken is in beta while everything else is in alpha.
    # This will cause the database checks to fail.
    @override_settings(
        DATABASE_ROUTERS=["tests.db_router.CrossDatabaseRouter", "tests.db_router.AlphaRouter"]
    )
    def test_checks_fail_when_router_crosses_databases(self):
        message = "The token models are expected to be stored in the same database."
        with self.assertRaisesMessage(SystemCheckError, message):
            call_command("check")

    @override_settings(OAUTH2_PROVIDER=BAD_HANDLER_SETTINGS)
    def test_checks_fail_when_backchannel_logout_handler_is_not_callable(self):
        message = "OIDC_BACKCHANNEL_LOGOUT_HANDLER must be a callable."
        with self.assertRaisesMessage(SystemCheckError, message):
            call_command("check")

    @override_settings(OAUTH2_PROVIDER=MISSING_ISS_OIDC_ENDPOINT)
    def test_checks_fail_when_iss_oidc_endpoint_is_missing(self):
        message = "OIDC_ISS_ENDPOINT must be set to enable OIDC backchannel logout."
        with self.assertRaisesMessage(SystemCheckError, message):
            call_command("check")
