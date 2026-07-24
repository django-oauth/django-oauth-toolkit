from django.core.management import call_command
from django.core.management.base import SystemCheckError
from django.test import override_settings

from .common_testing import OAuth2ProviderTestCase as TestCase


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


class JWTBearerGrantChecksTestCase(TestCase):
    def _ids(self):
        from oauth2_provider.checks import validate_jwt_bearer_grant_configuration

        return [m.id for m in validate_jwt_bearer_grant_configuration(None)]

    def test_no_warning_when_grant_disabled(self):
        self.assertNotIn("oauth2_provider.W011", self._ids())

    @override_settings(OAUTH2_PROVIDER={"JWT_BEARER_GRANT_ENABLED": True})
    def test_warns_when_enabled_without_trust(self):
        self.assertIn("oauth2_provider.W011", self._ids())

    @override_settings(
        OAUTH2_PROVIDER={
            "JWT_BEARER_GRANT_ENABLED": True,
            "JWT_BEARER_TRUSTED_ISSUERS": {"https://sts.example.com": {"jwks_uri": "https://sts/jwks"}},
        }
    )
    def test_no_warning_with_trusted_issuers(self):
        self.assertNotIn("oauth2_provider.W011", self._ids())
