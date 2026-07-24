import pytest
from django.core import checks
from django.core.management import call_command
from django.core.management.base import SystemCheckError
from django.test import override_settings

from oauth2_provider.checks import validate_swapped_model_consistency

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


@pytest.mark.usefixtures("oauth2_settings")
class SwappedModelConsistencyCheckTestCase(TestCase):
    def _ids(self):
        return {m.id for m in validate_swapped_model_consistency(None)}

    def test_check_is_registered(self):
        # Guard against the @checks.register decorator being dropped: the direct-call
        # tests below would still pass, but Django would never run the check.
        from django.core.checks.registry import registry as checks_registry

        self.assertIn(
            validate_swapped_model_consistency,
            checks_registry.get_checks(include_deployment_checks=True),
        )

    def test_default_models_pass(self):
        # Both models default to the oauth2_provider app.
        self.assertNotIn("oauth2_provider.W011", self._ids())

    def test_token_pair_swapped_together_pass(self):
        self.oauth2_settings.ACCESS_TOKEN_MODEL = "myapp.AccessToken"
        self.oauth2_settings.REFRESH_TOKEN_MODEL = "myapp.RefreshToken"
        self.assertNotIn("oauth2_provider.W011", self._ids())

    def test_only_access_token_swapped_warns(self):
        # Regression for #634: swapping AccessToken but leaving RefreshToken on the
        # default app creates a cross-app circular FK that cannot be migrated.
        self.oauth2_settings.ACCESS_TOKEN_MODEL = "myapp.AccessToken"
        messages = validate_swapped_model_consistency(None)
        self.assertEqual([m.id for m in messages], ["oauth2_provider.W011"])
        self.assertIsInstance(messages[0], checks.Warning)

    def test_token_models_in_different_apps_warns(self):
        self.oauth2_settings.ACCESS_TOKEN_MODEL = "app_a.AccessToken"
        self.oauth2_settings.REFRESH_TOKEN_MODEL = "app_b.RefreshToken"
        self.assertIn("oauth2_provider.W011", self._ids())
