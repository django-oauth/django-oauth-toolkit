from io import StringIO

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.core.management import call_command
from django.core.management.base import CommandError

from oauth2_provider.models import get_application_model

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()


class CreateApplicationTest(TestCase):
    def test_command_creates_application(self):
        output = StringIO()
        self.assertEqual(Application.objects.count(), 0)
        call_command(
            "createapplication",
            "confidential",
            "authorization-code",
            "--redirect-uris=http://example.com http://example2.com",
            stdout=output,
        )
        self.assertEqual(Application.objects.count(), 1)
        self.assertIn("created successfully", output.getvalue())

    def test_missing_required_args(self):
        self.assertEqual(Application.objects.count(), 0)
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "createapplication",
                "--redirect-uris=http://example.com http://example2.com",
            )

        self.assertIn("client_type", ctx.exception.args[0])
        self.assertIn("authorization_grant_type", ctx.exception.args[0])
        self.assertEqual(Application.objects.count(), 0)

    def test_command_creates_application_with_skipped_auth(self):
        self.assertEqual(Application.objects.count(), 0)
        call_command(
            "createapplication",
            "confidential",
            "authorization-code",
            "--redirect-uris=http://example.com http://example2.com",
            "--skip-authorization",
        )
        app = Application.objects.get()

        self.assertTrue(app.skip_authorization)

    def test_application_created_normally_with_no_skipped_auth(self):
        call_command(
            "createapplication",
            "confidential",
            "authorization-code",
            "--redirect-uris=http://example.com http://example2.com",
        )
        app = Application.objects.get()

        self.assertFalse(app.skip_authorization)

    def test_application_created_with_name(self):
        call_command(
            "createapplication",
            "confidential",
            "authorization-code",
            "--redirect-uris=http://example.com http://example2.com",
            "--name=TEST",
        )
        app = Application.objects.get()

        self.assertEqual(app.name, "TEST")

    def test_application_created_with_client_secret(self):
        call_command(
            "createapplication",
            "confidential",
            "authorization-code",
            "--redirect-uris=http://example.com http://example2.com",
            "--client-secret=SECRET",
        )
        app = Application.objects.get()

        self.assertTrue(check_password("SECRET", app.client_secret))

    def test_application_created_with_client_id(self):
        call_command(
            "createapplication",
            "confidential",
            "authorization-code",
            "--redirect-uris=http://example.com http://example2.com",
            "--client-id=someId",
        )
        app = Application.objects.get()

        self.assertEqual(app.client_id, "someId")

    def test_application_created_with_user(self):
        User = get_user_model()
        user = User.objects.create()
        call_command(
            "createapplication",
            "confidential",
            "authorization-code",
            "--redirect-uris=http://example.com http://example2.com",
            "--user=%s" % user.pk,
        )
        app = Application.objects.get()

        self.assertEqual(app.user, user)

    @pytest.mark.usefixtures("oauth2_settings")
    @pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
    def test_application_created_with_algorithm(self):
        call_command(
            "createapplication",
            "confidential",
            "authorization-code",
            "--redirect-uris=http://example.com http://example2.com",
            "--algorithm=RS256",
        )
        app = Application.objects.get()

        self.assertEqual(app.algorithm, "RS256")

    def test_validation_failed_message(self):
        import django

        output = StringIO()
        call_command(
            "createapplication",
            "confidential",
            "authorization-code",
            "--redirect-uris=http://example.com http://example2.com",
            "--user=783",
            stdout=output,
        )

        output_str = output.getvalue()
        self.assertIn("user", output_str)
        self.assertIn("783", output_str)
        if django.VERSION < (5, 2):
            self.assertIn("does not exist", output_str)
        else:
            self.assertIn("is not a valid choice", output_str)


@pytest.mark.usefixtures("oauth2_settings")
class ClearTokensTest(TestCase):
    def test_warns_when_refresh_token_expiry_unset(self):
        # With REFRESH_TOKEN_EXPIRE_SECONDS unset, refresh tokens never age-expire and
        # cleartokens cannot reclaim expired access/ID tokens, so the command warns.
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = None
        stderr = StringIO()
        call_command("cleartokens", stderr=stderr)
        self.assertIn("REFRESH_TOKEN_EXPIRE_SECONDS is not set", stderr.getvalue())

    def test_warns_when_refresh_token_expiry_zero(self):
        # 0 is treated the same as unset (expiry disabled), so it also warns.
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = 0
        stderr = StringIO()
        call_command("cleartokens", stderr=stderr)
        self.assertIn("REFRESH_TOKEN_EXPIRE_SECONDS is not set", stderr.getvalue())

    def test_no_warning_when_refresh_token_expiry_set(self):
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = 3600
        stderr = StringIO()
        call_command("cleartokens", stderr=stderr)
        self.assertEqual(stderr.getvalue(), "")
