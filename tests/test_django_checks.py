import warnings
from datetime import timedelta

import pytest
from django.core import checks
from django.core.management import call_command
from django.core.management.base import SystemCheckError
from django.test import override_settings

from oauth2_provider.core.checks import (
    validate_access_token_expiry_configuration,
    validate_refresh_token_configuration,
    validate_response_types_supported,
    validate_swapped_model_consistency,
    validate_token_configuration,
)

from . import presets
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

    def test_token_configuration_check_runs_without_a_database_alias(self):
        # Django 6.1 skips `database`-tagged checks unless an alias is passed explicitly
        # (`manage.py check --database default`). This check only asks the routers where the
        # token models would be written -- it never opens a connection -- so it must not carry
        # that tag, or a plain `manage.py check` would silently stop running it.
        self.assertNotIn(checks.Tags.database, validate_token_configuration.tags)
        self.assertIn(checks.Tags.models, validate_token_configuration.tags)


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


@pytest.mark.usefixtures("oauth2_settings")
class ResponseTypesSupportedCheckTestCase(TestCase):
    def _messages(self):
        return [m for m in validate_response_types_supported(None) if m.id == "oauth2_provider.W013"]

    def test_check_is_registered_as_a_deploy_check(self):
        from django.core.checks.registry import registry as checks_registry

        self.assertIn(
            validate_response_types_supported,
            checks_registry.get_checks(include_deployment_checks=True),
        )
        # Advertising an unreachable response type is a misconfiguration rather than a
        # runtime fault, so it is only reported by `manage.py check --deploy`.
        self.assertNotIn(validate_response_types_supported, checks_registry.get_checks())

    def test_default_response_types_pass(self):
        self.assertEqual(self._messages(), [])

    def test_unregistered_response_type_warns_with_the_accepted_values(self):
        self.oauth2_settings.OAUTH2_RESPONSE_TYPES_SUPPORTED = ["code", "code assertion"]
        (message,) = self._messages()
        self.assertIsInstance(message, checks.Warning)
        self.assertIn("code assertion", message.msg)
        self.assertIn("OAUTH2_RESPONSE_TYPES_SUPPORTED", message.msg)
        self.assertIn("The configured server accepts:", message.hint)

    def test_oidc_response_types_are_not_checked_while_oidc_is_disabled(self):
        # The OIDC discovery document that advertises them is not served, and the
        # non-OIDC server registers none of the id_token response types.
        self.oauth2_settings.OIDC_RESPONSE_TYPES_SUPPORTED = ["id_token token", "token id_token"]
        self.assertEqual(self._messages(), [])

    def test_a_non_string_entry_is_reported_rather_than_raised(self):
        # `manage.py check` does not catch exceptions raised by a check, so a malformed
        # entry must not be allowed to abort the whole command.
        self.oauth2_settings.OAUTH2_RESPONSE_TYPES_SUPPORTED = ["code", 123]
        (message,) = self._messages()
        self.assertIsInstance(message, checks.Warning)
        self.assertIn("123", message.msg)
        self.assertIn("The configured server accepts:", message.hint)

    def test_the_check_survives_a_deprecated_backend_under_warnings_as_errors(self):
        # The check must not depend on OAUTH2_BACKEND_CLASS being constructible: the
        # deprecated JSONOAuthLibCore raises its DeprecationWarning as an exception under
        # warnings-as-errors, which would otherwise silently return no messages.
        self.oauth2_settings.OAUTH2_BACKEND_CLASS = "oauth2_provider.core.backends_oauthlib.JSONOAuthLibCore"
        self.oauth2_settings.OAUTH2_RESPONSE_TYPES_SUPPORTED = ["code", "code assertion"]
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            (message,) = self._messages()
        self.assertIn("code assertion", message.msg)


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class OIDCResponseTypesSupportedCheckTestCase(TestCase):
    def _messages(self):
        return [m for m in validate_response_types_supported(None) if m.id == "oauth2_provider.W013"]

    def test_default_oidc_response_types_pass(self):
        # Every default entry is a canonical ordering registered by oauthlib's OIDC server.
        self.assertEqual(self._messages(), [])

    def test_permuted_oidc_response_type_warns_with_the_canonical_ordering(self):
        # "token id_token" is the same response type *set* as the registered
        # "id_token token", but oauthlib only dispatches on the exact string.
        self.oauth2_settings.OIDC_RESPONSE_TYPES_SUPPORTED = ["code", "token id_token"]
        (message,) = self._messages()
        self.assertIsInstance(message, checks.Warning)
        self.assertIn("token id_token", message.msg)
        self.assertIn("OIDC_RESPONSE_TYPES_SUPPORTED", message.msg)
        self.assertIn("'id_token token'", message.hint)

    def test_implicit_entries_dropped_by_the_bcp_gate_are_not_reported(self):
        # With COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT enabled, bcp_filter_response_types()
        # removes implicit entries from both discovery documents, so a permuted implicit
        # entry is never advertised and warning about it would be wrong.
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT = True
        self.oauth2_settings.OIDC_RESPONSE_TYPES_SUPPORTED = ["code", "token id_token"]
        self.assertEqual(self._messages(), [])

    def test_hybrid_entries_are_still_reported_under_the_bcp_gate(self):
        # A response type containing `code` is not implicit, so the gate does not drop it
        # and the permutation is still advertised and still unreachable.
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT = True
        self.oauth2_settings.OIDC_RESPONSE_TYPES_SUPPORTED = ["code", "token code"]
        (message,) = self._messages()
        self.assertIn("token code", message.msg)
        self.assertIn("'code token'", message.hint)
