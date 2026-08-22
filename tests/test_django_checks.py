from copy import deepcopy
from datetime import timedelta

import pytest
from django.core import checks
from django.core.management import call_command
from django.core.management.base import SystemCheckError
from django.test import override_settings

from oauth2_provider.core.checks import (
    validate_access_token_expiry_configuration,
    validate_backchannel_logout,
    validate_refresh_token_configuration,
    validate_swapped_model_consistency,
    validate_token_configuration,
)

from .common_testing import OAuth2ProviderTestCase as TestCase
from .presets import OIDC_SETTINGS_BACKCHANNEL_LOGOUT


BAD_HANDLER_SETTINGS = deepcopy(OIDC_SETTINGS_BACKCHANNEL_LOGOUT)
BAD_HANDLER_SETTINGS["OIDC_BACKCHANNEL_LOGOUT_HANDLER"] = "sys.api_version"

MISSING_ISS_OIDC_ENDPOINT = deepcopy(OIDC_SETTINGS_BACKCHANNEL_LOGOUT)
MISSING_ISS_OIDC_ENDPOINT["OIDC_ISS_ENDPOINT"] = None

OIDC_DISABLED_SETTINGS = deepcopy(OIDC_SETTINGS_BACKCHANNEL_LOGOUT)
OIDC_DISABLED_SETTINGS["OIDC_ENABLED"] = False


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

    def test_token_configuration_check_runs_without_a_database_alias(self):
        # Django 6.1 skips `database`-tagged checks unless an alias is passed explicitly
        # (`manage.py check --database default`). This check only asks the routers where the
        # token models would be written -- it never opens a connection -- so it must not carry
        # that tag, or a plain `manage.py check` would silently stop running it.
        self.assertNotIn(checks.Tags.database, validate_token_configuration.tags)
        self.assertIn(checks.Tags.models, validate_token_configuration.tags)

    def test_backchannel_logout_check_is_tagged(self):
        # An untagged check is skipped by tag-filtered runs (`manage.py check --tag
        # security`, which deploy pipelines commonly use), so this misconfiguration guard
        # has to carry the tag its neighbours do.
        self.assertIn(checks.Tags.security, validate_backchannel_logout.tags)

    @override_settings(OAUTH2_PROVIDER=OIDC_DISABLED_SETTINGS)
    def test_checks_fail_when_backchannel_is_enabled_and_oidc_is_disabled(self):
        message = "OIDC_ENABLED must be True to enable OIDC backchannel logout."
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


@pytest.mark.usefixtures("oauth2_settings")
class RefreshTokenConfigurationCheckTestCase(TestCase):
    def _ids(self):
        return {m.id for m in validate_refresh_token_configuration(None)}

    def test_check_is_registered(self):
        from django.core.checks.registry import registry as checks_registry

        self.assertIn(
            validate_refresh_token_configuration,
            checks_registry.get_checks(include_deployment_checks=True),
        )

    def test_defaults_pass(self):
        # ROTATE_REFRESH_TOKEN defaults to True and reuse protection to False.
        self.assertNotIn("oauth2_provider.W012", self._ids())

    def test_reuse_protection_with_rotation_passes(self):
        self.oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION = True
        self.oauth2_settings.ROTATE_REFRESH_TOKEN = True
        self.assertNotIn("oauth2_provider.W012", self._ids())

    def test_rotation_off_without_reuse_protection_passes(self):
        # Non-rotating refresh tokens are legitimate for confidential clients
        # (RFC 6749 section 6); only the combination with reuse protection is incoherent.
        self.oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION = False
        self.oauth2_settings.ROTATE_REFRESH_TOKEN = False
        self.assertNotIn("oauth2_provider.W012", self._ids())

    def test_reuse_protection_without_rotation_warns(self):
        self.oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION = True
        self.oauth2_settings.ROTATE_REFRESH_TOKEN = False
        messages = validate_refresh_token_configuration(None)
        self.assertEqual([m.id for m in messages], ["oauth2_provider.W012"])
        self.assertIsInstance(messages[0], checks.Warning)


@pytest.mark.usefixtures("oauth2_settings")
class AccessTokenExpiryConfigurationCheckTestCase(TestCase):
    def _ids(self):
        return [m.id for m in validate_access_token_expiry_configuration(None)]

    def test_check_is_registered(self):
        from django.core.checks.registry import registry as checks_registry

        self.assertIn(
            validate_access_token_expiry_configuration,
            checks_registry.get_checks(include_deployment_checks=True),
        )

    @override_settings(OAUTH2_PROVIDER={"ACCESS_TOKEN_EXPIRE_SECONDS": "nope.not_importable"})
    def test_unimportable_string_is_reported_not_raised(self):
        messages = validate_access_token_expiry_configuration(None)
        self.assertEqual([m.id for m in messages], ["oauth2_provider.E006"])

    def test_check_is_tagged(self):
        # An untagged check is skipped by tag-filtered runs (`manage.py check --tag ...`),
        # so it must carry a tag like every other check in the module.
        self.assertIn(checks.Tags.security, validate_access_token_expiry_configuration.tags)

    def test_valid_values_pass(self):
        for value in (36000, timedelta(minutes=5), lambda request: 60):
            with self.subTest(value=value):
                self.oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS = value
                self.assertEqual(self._ids(), [])

    def test_invalid_static_value_errors(self):
        # A string is treated as a dotted path to the callable, so an unimportable one is
        # a misconfiguration too -- and must be reported, not raised out of the check.
        for value in (0, -1, "not a number"):
            with self.subTest(value=value):
                self.oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS = value
                messages = validate_access_token_expiry_configuration(None)
                self.assertEqual([m.id for m in messages], ["oauth2_provider.E006"])
                self.assertIsInstance(messages[0], checks.Error)
