from copy import deepcopy

from django.core.management import call_command
from django.core.management.base import SystemCheckError
from django.test import override_settings

from .common_testing import OAuth2ProviderTestCase as TestCase
from .presets import OIDC_SETTINGS_SESSION_MANAGEMENT


MISSING_DEFAULT_SESSION_KEY = deepcopy(OIDC_SETTINGS_SESSION_MANAGEMENT)
MISSING_DEFAULT_SESSION_KEY["OIDC_SESSION_MANAGEMENT_DEFAULT_SESSION_KEY"] = None


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

    @override_settings(OAUTH2_PROVIDER=MISSING_DEFAULT_SESSION_KEY)
    def test_checks_fail_when_default_session_key_is_missing(self):
        message = (
            "OIDC Session management is enabled, OIDC_SESSION_MANAGEMENT_DEFAULT_SESSION_KEY is required."
        )
        with self.assertRaisesMessage(SystemCheckError, message):
            call_command("check")
