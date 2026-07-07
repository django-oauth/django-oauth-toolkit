import hashlib
import secrets
from datetime import timedelta
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.test.utils import override_settings
from django.utils import timezone

from oauth2_provider import models as oauth2_models
from oauth2_provider.models import (
    clear_expired,
    get_access_token_model,
    get_application_model,
    get_grant_model,
    get_id_token_model,
    get_refresh_token_model,
    redirect_to_uri_allowed,
)

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .models import CustomPkAccessToken, CustomPkRefreshToken


CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"

Application = get_application_model()
Grant = get_grant_model()
AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()
UserModel = get_user_model()
IDToken = get_id_token_model()


class BaseTestModels(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("test_user", "test@example.com", "123456")


class TestModels(BaseTestModels):
    def test_allow_scopes(self):
        self.client.login(username="test_user", password="123456")
        app = Application.objects.create(
            name="test_app",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

        access_token = AccessToken(user=self.user, scope="read write", expires=0, token="", application=app)

        self.assertTrue(access_token.allow_scopes(["read", "write"]))
        self.assertTrue(access_token.allow_scopes(["write", "read"]))
        self.assertTrue(access_token.allow_scopes(["write", "read", "read"]))
        self.assertTrue(access_token.allow_scopes([]))
        self.assertFalse(access_token.allow_scopes(["write", "destroy"]))

    def test_hashed_secret(self):
        app = Application.objects.create(
            name="test_app",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
            hash_client_secret=True,
        )

        self.assertNotEqual(app.client_secret, CLEARTEXT_SECRET)
        self.assertTrue(check_password(CLEARTEXT_SECRET, app.client_secret))

    @override_settings(OAUTH2_PROVIDER={"CLIENT_SECRET_HASHER": "fast_pbkdf2"})
    def test_hashed_from_settings(self):
        app = Application.objects.create(
            name="test_app",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
            hash_client_secret=True,
        )

        self.assertNotEqual(app.client_secret, CLEARTEXT_SECRET)
        self.assertIn("fast_pbkdf2", app.client_secret)
        self.assertTrue(check_password(CLEARTEXT_SECRET, app.client_secret))

    def test_unhashed_secret(self):
        app = Application.objects.create(
            name="test_app",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
            hash_client_secret=False,
        )

        self.assertEqual(app.client_secret, CLEARTEXT_SECRET)

    def test_grant_authorization_code_redirect_uris(self):
        app = Application(
            name="test_app",
            redirect_uris="",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

        self.assertRaises(ValidationError, app.full_clean)

    def test_grant_implicit_redirect_uris(self):
        app = Application(
            name="test_app",
            redirect_uris="",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_IMPLICIT,
        )

        self.assertRaises(ValidationError, app.full_clean)

    def test_str(self):
        app = Application(
            redirect_uris="",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_IMPLICIT,
        )
        self.assertEqual("%s" % app, app.client_id)

        app.name = "test_app"
        self.assertEqual("%s" % app, "test_app")

    def test_credential_models_str_do_not_leak_secrets(self):
        app = Application.objects.create(
            name="test_app",
            redirect_uris="http://example.org",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        access_token = AccessToken.objects.create(
            user=self.user,
            scope="read",
            expires=timezone.now() + timedelta(seconds=60),
            token="secret-access-token-value",
            application=app,
        )
        refresh_token = RefreshToken.objects.create(
            user=self.user,
            token="secret-refresh-token-value",
            application=app,
            access_token=access_token,
        )
        grant = Grant.objects.create(
            user=self.user,
            code="secret-grant-code-value",
            application=app,
            expires=timezone.now() + timedelta(seconds=60),
            redirect_uri="http://example.org",
            scope="read",
        )

        # __str__ is rendered in the admin change page/breadcrumbs, repr(), and logs;
        # it must identify the row by pk without exposing the credential.
        self.assertNotIn("secret-access-token-value", str(access_token))
        self.assertIn(str(access_token.pk), str(access_token))
        self.assertNotIn("secret-refresh-token-value", str(refresh_token))
        self.assertIn(str(refresh_token.pk), str(refresh_token))
        self.assertNotIn("secret-grant-code-value", str(grant))
        self.assertIn(str(grant.pk), str(grant))

    def test_scopes_property(self):
        self.client.login(username="test_user", password="123456")

        app = Application.objects.create(
            name="test_app",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

        access_token = AccessToken(user=self.user, scope="read write", expires=0, token="", application=app)

        access_token2 = AccessToken(user=self.user, scope="write", expires=0, token="", application=app)

        self.assertEqual(access_token.scopes, {"read": "Reading scope", "write": "Writing scope"})
        self.assertEqual(access_token2.scopes, {"write": "Writing scope"})


@override_settings(
    OAUTH2_PROVIDER_APPLICATION_MODEL="tests.SampleApplication",
    OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL="tests.SampleAccessToken",
    OAUTH2_PROVIDER_REFRESH_TOKEN_MODEL="tests.SampleRefreshToken",
    OAUTH2_PROVIDER_GRANT_MODEL="tests.SampleGrant",
)
@pytest.mark.usefixtures("oauth2_settings")
class TestCustomModels(BaseTestModels):
    def test_custom_application_model(self):
        """
        If a custom application model is installed, it should be present in
        the related objects and not the swapped out one.

        See issue #90 (https://github.com/django-oauth/django-oauth-toolkit/issues/90)
        """
        related_object_names = [
            f.name
            for f in UserModel._meta.get_fields()
            if (f.one_to_many or f.one_to_one) and f.auto_created and not f.concrete
        ]
        self.assertNotIn("oauth2_provider:application", related_object_names)
        self.assertIn("tests_sampleapplication", related_object_names)

    def test_custom_application_model_incorrect_format(self):
        # Patch oauth2 settings to use a custom Application model
        self.oauth2_settings.APPLICATION_MODEL = "IncorrectApplicationFormat"

        self.assertRaises(ValueError, get_application_model)

    def test_custom_application_model_not_installed(self):
        # Patch oauth2 settings to use a custom Application model
        self.oauth2_settings.APPLICATION_MODEL = "tests.ApplicationNotInstalled"

        self.assertRaises(LookupError, get_application_model)

    def test_custom_access_token_model(self):
        """
        If a custom access token model is installed, it should be present in
        the related objects and not the swapped out one.
        """
        # Django internals caches the related objects.
        related_object_names = [
            f.name
            for f in UserModel._meta.get_fields()
            if (f.one_to_many or f.one_to_one) and f.auto_created and not f.concrete
        ]
        self.assertNotIn("oauth2_provider:access_token", related_object_names)
        self.assertIn("tests_sampleaccesstoken", related_object_names)

    def test_custom_access_token_model_incorrect_format(self):
        # Patch oauth2 settings to use a custom AccessToken model
        self.oauth2_settings.ACCESS_TOKEN_MODEL = "IncorrectAccessTokenFormat"

        self.assertRaises(ValueError, get_access_token_model)

    def test_custom_access_token_model_not_installed(self):
        # Patch oauth2 settings to use a custom AccessToken model
        self.oauth2_settings.ACCESS_TOKEN_MODEL = "tests.AccessTokenNotInstalled"

        self.assertRaises(LookupError, get_access_token_model)

    def test_custom_refresh_token_model(self):
        """
        If a custom refresh token model is installed, it should be present in
        the related objects and not the swapped out one.
        """
        # Django internals caches the related objects.
        related_object_names = [
            f.name
            for f in UserModel._meta.get_fields()
            if (f.one_to_many or f.one_to_one) and f.auto_created and not f.concrete
        ]
        self.assertNotIn("oauth2_provider:refresh_token", related_object_names)
        self.assertIn("tests_samplerefreshtoken", related_object_names)

    def test_custom_refresh_token_model_incorrect_format(self):
        # Patch oauth2 settings to use a custom RefreshToken model
        self.oauth2_settings.REFRESH_TOKEN_MODEL = "IncorrectRefreshTokenFormat"

        self.assertRaises(ValueError, get_refresh_token_model)

    def test_custom_refresh_token_model_not_installed(self):
        # Patch oauth2 settings to use a custom AccessToken model
        self.oauth2_settings.REFRESH_TOKEN_MODEL = "tests.RefreshTokenNotInstalled"

        self.assertRaises(LookupError, get_refresh_token_model)

    def test_custom_grant_model(self):
        """
        If a custom grant model is installed, it should be present in
        the related objects and not the swapped out one.
        """
        # Django internals caches the related objects.
        related_object_names = [
            f.name
            for f in UserModel._meta.get_fields()
            if (f.one_to_many or f.one_to_one) and f.auto_created and not f.concrete
        ]
        self.assertNotIn("oauth2_provider:grant", related_object_names)
        self.assertIn("tests_samplegrant", related_object_names)

    def test_custom_grant_model_incorrect_format(self):
        # Patch oauth2 settings to use a custom Grant model
        self.oauth2_settings.GRANT_MODEL = "IncorrectGrantFormat"

        self.assertRaises(ValueError, get_grant_model)

    def test_custom_grant_model_not_installed(self):
        # Patch oauth2 settings to use a custom AccessToken model
        self.oauth2_settings.GRANT_MODEL = "tests.GrantNotInstalled"

        self.assertRaises(LookupError, get_grant_model)


class TestGrantModel(BaseTestModels):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.application = Application.objects.create(
            name="Test Application",
            redirect_uris="",
            user=cls.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

    def test_str(self):
        # __str__ must identify the row without exposing the authorization code.
        grant = Grant(code="test_code")
        self.assertNotIn("test_code", "%s" % grant)
        self.assertEqual("%s" % grant, "Grant #{}".format(grant.pk))

    def test_expires_can_be_none(self):
        grant = Grant(code="test_code")
        self.assertIsNone(grant.expires)
        self.assertTrue(grant.is_expired())

    def test_redirect_uri_can_be_longer_than_255_chars(self):
        long_redirect_uri = "http://example.com/{}".format("authorized/" * 25)
        self.assertTrue(len(long_redirect_uri) > 255)
        grant = Grant.objects.create(
            user=self.user,
            code="test_code",
            application=self.application,
            expires=timezone.now(),
            redirect_uri=long_redirect_uri,
            scope="",
        )
        grant.refresh_from_db()

        # It would be necessary to run test using another DB engine than sqlite
        # that transform varchar(255) into text data type.
        # https://sqlite.org/datatype3.html#affinity_name_examples
        self.assertEqual(grant.redirect_uri, long_redirect_uri)


class TestAccessTokenModel(BaseTestModels):
    def test_str(self):
        # __str__ must identify the row without exposing the token.
        access_token = AccessToken(token="test_token")
        self.assertNotIn("test_token", "%s" % access_token)
        self.assertEqual("%s" % access_token, "AccessToken #{}".format(access_token.pk))

    def test_user_can_be_none(self):
        app = Application.objects.create(
            name="test_app",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        access_token = AccessToken.objects.create(token="test_token", application=app, expires=timezone.now())
        self.assertIsNone(access_token.user)

    def test_expires_can_be_none(self):
        access_token = AccessToken(token="test_token")
        self.assertIsNone(access_token.expires)
        self.assertTrue(access_token.is_expired())

    def test_token_checksum_field(self):
        token = secrets.token_urlsafe(32)
        access_token = AccessToken.objects.create(
            user=self.user,
            token=token,
            expires=timezone.now() + timedelta(hours=1),
        )
        expected_checksum = hashlib.sha256(token.encode()).hexdigest()

        self.assertEqual(access_token.token_checksum, expected_checksum)


class TestRefreshTokenModel(BaseTestModels):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.app = Application.objects.create(
            name="test_app",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=cls.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

    def test_str(self):
        # __str__ must identify the row without exposing the token.
        refresh_token = RefreshToken(token="test_token")
        self.assertNotIn("test_token", "%s" % refresh_token)
        self.assertEqual("%s" % refresh_token, "RefreshToken #{}".format(refresh_token.pk))

    def test_token_checksum_field(self):
        token = secrets.token_urlsafe(32)
        refresh_token = RefreshToken.objects.create(
            user=self.user,
            token=token,
            application=self.app,
        )
        expected_checksum = hashlib.sha256(token.encode()).hexdigest()

        self.assertEqual(refresh_token.token_checksum, expected_checksum)

    def test_token_longer_than_255_characters(self):
        # e.g. Microsoft issues JWT refresh tokens well over 255 characters
        token = secrets.token_urlsafe(600)
        self.assertGreater(len(token), 255)
        refresh_token = RefreshToken.objects.create(
            user=self.user,
            token=token,
            application=self.app,
        )
        refresh_token.refresh_from_db()

        self.assertEqual(refresh_token.token, token)
        self.assertEqual(
            refresh_token.token_checksum,
            hashlib.sha256(token.encode()).hexdigest(),
        )

    def test_same_token_allowed_with_different_revoked_timestamps(self):
        token = secrets.token_urlsafe(32)
        RefreshToken.objects.create(
            user=self.user,
            token=token,
            application=self.app,
            revoked=timezone.now(),
        )
        active = RefreshToken.objects.create(
            user=self.user,
            token=token,
            application=self.app,
        )

        self.assertIsNone(active.revoked)
        self.assertEqual(RefreshToken.objects.filter(token_checksum=active.token_checksum).count(), 2)


@pytest.mark.usefixtures("oauth2_settings")
class TestClearExpired(BaseTestModels):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        # Insert many tokens, both expired and not, and grants.
        cls.num_tokens = 100
        cls.delta_secs = 1000
        cls.now = timezone.now()
        cls.earlier = cls.now - timedelta(seconds=cls.delta_secs)
        cls.later = cls.now + timedelta(seconds=cls.delta_secs)

        app = Application.objects.create(
            name="test_app",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=cls.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        # make 200 access tokens, half current and half expired.
        expired_access_tokens = [
            AccessToken(token="expired AccessToken {}".format(i), expires=cls.earlier)
            for i in range(cls.num_tokens)
        ]
        for a in expired_access_tokens:
            a.save()

        current_access_tokens = [
            AccessToken(token=f"current AccessToken {i}", expires=cls.later) for i in range(cls.num_tokens)
        ]
        for a in current_access_tokens:
            a.save()

        # Give the first half of the access tokens a refresh token,
        # alternating between current and expired ones.
        for i in range(0, len(expired_access_tokens) // 2, 2):
            RefreshToken(
                token=f"expired AT's refresh token {i}",
                application=app,
                access_token=expired_access_tokens[i],
                user=cls.user,
            ).save()

        for i in range(1, len(current_access_tokens) // 2, 2):
            RefreshToken(
                token=f"current AT's refresh token {i}",
                application=app,
                access_token=current_access_tokens[i],
                user=cls.user,
            ).save()

        # Make some grants, half of which are expired.
        for i in range(cls.num_tokens):
            Grant(
                user=cls.user,
                code=f"old grant code {i}",
                application=app,
                expires=cls.earlier,
                redirect_uri="https://localhost/redirect",
            ).save()
        for i in range(cls.num_tokens):
            Grant(
                user=cls.user,
                code=f"new grant code {i}",
                application=app,
                expires=cls.later,
                redirect_uri="https://localhost/redirect",
            ).save()

    def test_clear_expired_tokens_incorect_timetype(self):
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = "A"
        with pytest.raises(ImproperlyConfigured) as excinfo:
            clear_expired()
        result = excinfo.value.__class__.__name__
        assert result == "ImproperlyConfigured"

    def test_clear_expired_tokens_with_tokens(self):
        self.oauth2_settings.CLEAR_EXPIRED_TOKENS_BATCH_SIZE = 10
        self.oauth2_settings.CLEAR_EXPIRED_TOKENS_BATCH_INTERVAL = 0.0
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = self.delta_secs // 2

        # before clear_expired(), confirm setup as expected
        initial_at_count = AccessToken.objects.count()
        assert initial_at_count == 2 * self.num_tokens, f"{2 * self.num_tokens} access tokens should exist."
        initial_expired_at_count = AccessToken.objects.filter(expires__lte=self.now).count()
        assert initial_expired_at_count == self.num_tokens, (
            f"{self.num_tokens} expired access tokens should exist."
        )
        initial_current_at_count = AccessToken.objects.filter(expires__gt=self.now).count()
        assert initial_current_at_count == self.num_tokens, (
            f"{self.num_tokens} current access tokens should exist."
        )
        initial_rt_count = RefreshToken.objects.count()
        assert initial_rt_count == self.num_tokens // 2, (
            f"{self.num_tokens // 2} refresh tokens should exist."
        )
        initial_rt_expired_at_count = RefreshToken.objects.filter(access_token__expires__lte=self.now).count()
        assert initial_rt_expired_at_count == initial_rt_count / 2, (
            "half the refresh tokens should be for expired access tokens."
        )
        initial_rt_current_at_count = RefreshToken.objects.filter(access_token__expires__gt=self.now).count()
        assert initial_rt_current_at_count == initial_rt_count / 2, (
            "half the refresh tokens should be for current access tokens."
        )
        initial_gt_count = Grant.objects.count()
        assert initial_gt_count == self.num_tokens * 2, f"{self.num_tokens * 2} grants should exist."

        clear_expired()

        # after clear_expired():
        remaining_at_count = AccessToken.objects.count()
        assert remaining_at_count == initial_at_count // 2, (
            "half the initial access tokens should still exist."
        )
        remaining_expired_at_count = AccessToken.objects.filter(expires__lte=self.now).count()
        assert remaining_expired_at_count == 0, "no remaining expired access tokens should still exist."
        remaining_current_at_count = AccessToken.objects.filter(expires__gt=self.now).count()
        assert remaining_current_at_count == initial_current_at_count, (
            "all current access tokens should still exist."
        )
        remaining_rt_count = RefreshToken.objects.count()
        assert remaining_rt_count == initial_rt_count // 2, "half the refresh tokens should still exist."
        remaining_rt_expired_at_count = RefreshToken.objects.filter(
            access_token__expires__lte=self.now
        ).count()
        assert remaining_rt_expired_at_count == 0, "no refresh tokens for expired AT's should still exist."
        remaining_rt_current_at_count = RefreshToken.objects.filter(
            access_token__expires__gt=self.now
        ).count()
        assert remaining_rt_current_at_count == initial_rt_current_at_count, (
            "all the refresh tokens for current access tokens should still exist."
        )
        remaining_gt_count = Grant.objects.count()
        assert remaining_gt_count == initial_gt_count // 2, "half the remaining grants should still exist."


@pytest.mark.usefixtures("oauth2_settings")
class TestCustomPrimaryKeyTokens(BaseTestModels):
    """
    Regression tests for token models that use a custom primary key field
    (i.e. not named ``id``).

    ``tests.CustomPkAccessToken`` and ``tests.CustomPkRefreshToken`` use a
    ``UUIDField`` primary key named ``custom_pk``. The model getters are patched
    so that ``clear_expired()`` and ``RefreshToken.revoke()`` operate on these
    models, exercising the code paths that previously hard-coded ``id``.

    See https://github.com/django-oauth/django-oauth-toolkit/pull/1593
    """

    def test_clear_expired_with_custom_pk(self):
        """clear_expired() must work when the access token uses a custom pk."""
        now = timezone.now()
        expired = now - timedelta(seconds=3600)
        later = now + timedelta(seconds=3600)
        for i in range(3):
            CustomPkAccessToken.objects.create(token=f"expired {i}", expires=expired)
        for i in range(2):
            CustomPkAccessToken.objects.create(token=f"current {i}", expires=later)

        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = None
        with (
            mock.patch.object(oauth2_models, "get_access_token_model", return_value=CustomPkAccessToken),
            mock.patch.object(oauth2_models, "get_refresh_token_model", return_value=CustomPkRefreshToken),
        ):
            clear_expired()

        assert CustomPkAccessToken.objects.count() == 2, "expired access tokens should be deleted."
        assert not CustomPkAccessToken.objects.filter(expires__lt=now).exists()

    def test_refresh_token_revoke_with_custom_pk(self):
        """RefreshToken.revoke() must work when tokens use a custom pk."""
        application = Application.objects.create(
            name="test_app",
            redirect_uris="http://localhost",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        access_token = CustomPkAccessToken.objects.create(
            token="test_token",
            expires=timezone.now() + timedelta(hours=1),
        )
        refresh_token = CustomPkRefreshToken.objects.create(
            token="test_refresh_token",
            user=self.user,
            application=application,
            access_token=access_token,
        )

        with (
            mock.patch.object(oauth2_models, "get_access_token_model", return_value=CustomPkAccessToken),
            mock.patch.object(oauth2_models, "get_refresh_token_model", return_value=CustomPkRefreshToken),
        ):
            refresh_token.revoke()

        refresh_token.refresh_from_db()
        assert refresh_token.revoked is not None
        assert refresh_token.access_token_id is None
        assert not CustomPkAccessToken.objects.filter(pk=access_token.pk).exists(), (
            "the related access token should have been revoked."
        )


@pytest.mark.usefixtures("oauth2_settings")
class TestClearRevoked(BaseTestModels):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.num_tokens = 9
        cls.grace_secs = 1000
        cls.now = timezone.now()
        cls.grace_time = cls.now - timedelta(seconds=cls.grace_secs)
        cls.within_grace = cls.now - timedelta(seconds=cls.grace_secs // 2)
        cls.outside_grace = cls.now - timedelta(seconds=cls.grace_secs * 2)

        app = Application.objects.create(
            name="test_app",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=cls.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        # make refresh tokens, one third current, one third revoked within
        # grace period and one third revoked outside grace period.
        for i in range(0, cls.num_tokens, 3):
            RefreshToken(
                token=f"revoked refresh token {i}",
                application=app,
                user=cls.user,
                revoked=cls.outside_grace,
            ).save()

        for i in range(1, cls.num_tokens, 3):
            RefreshToken(
                token=f"revoked within grace period refresh token {i}",
                application=app,
                user=cls.user,
                revoked=cls.within_grace,
            ).save()

        for i in range(2, cls.num_tokens, 3):
            RefreshToken(
                token=f"current refresh token {i}",
                application=app,
                user=cls.user,
            ).save()

        cls.initial_rt_count = RefreshToken.objects.count()
        assert cls.initial_rt_count == cls.num_tokens, f"{cls.num_tokens} refresh tokens should exist."
        initial_revoked_rt_outside_grace_count = RefreshToken.objects.filter(
            revoked__lte=cls.grace_time
        ).count()
        assert initial_revoked_rt_outside_grace_count == cls.initial_rt_count // 3, (
            "one third of the refresh tokens should be revoked and outside grace period."
        )
        cls.initial_revoked_rt_inside_grace_count = RefreshToken.objects.filter(
            revoked__gt=cls.grace_time
        ).count()
        assert cls.initial_revoked_rt_inside_grace_count == cls.initial_rt_count // 3, (
            "one third of the refresh tokens should be revoked and inside grace period."
        )
        initial_revoked_rt_count = RefreshToken.objects.filter(revoked__lte=cls.now).count()
        assert initial_revoked_rt_count == cls.initial_rt_count // 3 * 2, (
            "two thirds of the refresh tokens should be revoked."
        )
        cls.initial_current_rt_count = RefreshToken.objects.filter(revoked__isnull=True).count()
        assert cls.initial_current_rt_count == cls.initial_rt_count // 3, (
            "one third of the refresh tokens should be current."
        )

    def test_clear_expired_tokens_incorrect_timetype(self):
        self.oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS = "A"
        with pytest.raises(
            ImproperlyConfigured, match="REFRESH_TOKEN_GRACE_PERIOD_SECONDS must be in seconds"
        ):
            clear_expired()

    def test_clear_expired_tokens_negative_grace_period(self):
        self.oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS = -self.grace_secs
        with pytest.raises(
            ImproperlyConfigured, match="REFRESH_TOKEN_GRACE_PERIOD_SECONDS must not be negative"
        ):
            clear_expired()

    def test_clear_revoked_tokens_with_grace_period(self):
        self.oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS = self.grace_secs

        clear_expired()

        remaining_rt_count = RefreshToken.objects.count()
        assert remaining_rt_count == self.initial_rt_count // 3 * 2, (
            "two thirds of the refresh tokens should still exist."
        )
        remaining_rt_revoked_count = RefreshToken.objects.filter(revoked__lte=self.grace_time).count()
        assert remaining_rt_revoked_count == 0, (
            "no revoked refresh tokens outside grace period should still exist."
        )
        remaining_revoked_rt_inside_grace_count = RefreshToken.objects.filter(
            revoked__gt=self.grace_time
        ).count()
        assert remaining_revoked_rt_inside_grace_count == self.initial_revoked_rt_inside_grace_count, (
            "all revoked refresh tokens inside grace period should still exist."
        )
        remaining_current_rt_count = RefreshToken.objects.filter(revoked__isnull=True).count()
        assert remaining_current_rt_count == self.initial_current_rt_count, (
            "all the current refresh tokens should still exist."
        )

    def test_clear_revoked_tokens_without_grace_period(self):
        self.oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS = 0

        clear_expired()

        remaining_rt_count = RefreshToken.objects.count()
        assert remaining_rt_count == self.initial_rt_count // 3, (
            "one third of the refresh tokens should still exist."
        )
        remaining_revoked_rt_count = RefreshToken.objects.filter(revoked__lte=self.now).count()
        assert remaining_revoked_rt_count == 0, "no revoked refresh tokens should still exist."
        remaining_current_rt_count = RefreshToken.objects.filter(revoked__isnull=True).count()
        assert remaining_current_rt_count == self.initial_current_rt_count, (
            "all the current refresh tokens should still exist."
        )

    def test_clear_revoked_tokens_with_reuse_protection(self):
        self.oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION = True
        self.oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS = self.grace_secs
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = None

        clear_expired()

        remaining_rt_count = RefreshToken.objects.count()
        assert remaining_rt_count == self.initial_rt_count, (
            "with reuse protection and no expiry, all revoked refresh tokens should be kept."
        )

    def test_clear_revoked_tokens_with_reuse_protection_and_expiry(self):
        self.oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION = True
        self.oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS = self.grace_secs
        # expiry cutoff falls between the two groups of revoked tokens
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = self.grace_secs + self.grace_secs // 2

        clear_expired()

        remaining_rt_count = RefreshToken.objects.count()
        assert remaining_rt_count == self.initial_rt_count // 3 * 2, (
            "with reuse protection, only revoked refresh tokens older than the expiry should be deleted."
        )
        remaining_revoked_rt_inside_grace_count = RefreshToken.objects.filter(
            revoked__gt=self.grace_time
        ).count()
        assert remaining_revoked_rt_inside_grace_count == self.initial_revoked_rt_inside_grace_count, (
            "all revoked refresh tokens inside grace period should still exist."
        )
        remaining_current_rt_count = RefreshToken.objects.filter(revoked__isnull=True).count()
        assert remaining_current_rt_count == self.initial_current_rt_count, (
            "all the current refresh tokens should still exist."
        )


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_id_token_methods(oidc_tokens, rf):
    id_token = IDToken.objects.get()

    # Token was just created, so should be valid
    assert id_token.is_valid()

    # if expires is None, it should always be expired
    # the column is NOT NULL, but could be NULL in sub-classes
    id_token.expires = None
    assert id_token.is_expired()

    # if no scopes are passed, they should be valid
    assert id_token.allow_scopes(None)

    # if the requested scopes are in the token, they should be valid
    assert id_token.allow_scopes(["openid"])

    # if the requested scopes are not in the token, they should not be valid
    assert id_token.allow_scopes(["fizzbuzz"]) is False

    # we should be able to get a list of the scopes on the token
    assert id_token.scopes == {"openid": "OpenID connect"}

    # the id token should stringify as the JWT token
    id_token_str = str(id_token)
    assert str(id_token.jti) in id_token_str
    assert id_token_str.endswith(str(id_token.user_id))

    # revoking the token should delete it
    id_token.revoke()
    assert IDToken.objects.filter(jti=id_token.jti).count() == 0


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_clear_expired_id_tokens(oauth2_settings, oidc_tokens, rf):
    id_token = IDToken.objects.get()
    access_token = id_token.access_token

    # All tokens still valid
    clear_expired()

    assert IDToken.objects.filter(jti=id_token.jti).exists()

    earlier = timezone.now() - timedelta(minutes=1)
    id_token.expires = earlier
    id_token.save()

    # ID token should be preserved until the access token is deleted
    clear_expired()

    assert IDToken.objects.filter(jti=id_token.jti).exists()

    access_token.expires = earlier
    access_token.save()

    # ID and access tokens are expired but refresh token is still valid
    clear_expired()

    assert IDToken.objects.filter(jti=id_token.jti).exists()

    # Mark refresh token as expired
    delta = timedelta(seconds=oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS + 60)
    access_token.expires = timezone.now() - delta
    access_token.save()

    # With the refresh token expired, the ID token should be deleted
    clear_expired()

    assert not IDToken.objects.filter(jti=id_token.jti).exists()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_key(oauth2_settings, application):
    # RS256 key
    key = application.jwk_key
    assert key.kty == "RSA"

    # RS256 key, but not configured
    oauth2_settings.OIDC_RSA_PRIVATE_KEY = None
    with pytest.raises(ImproperlyConfigured) as exc:
        application.jwk_key
    assert "You must set OIDC_RSA_PRIVATE_KEY" in str(exc.value)

    # HS256 key: the secret is the signing key, so it must be stored unhashed.
    application.algorithm = Application.HS256_ALGORITHM
    application.hash_client_secret = False
    application.client_secret = CLEARTEXT_SECRET
    application.save()
    key = application.jwk_key
    assert key.kty == "oct"

    # HS256 with a hashed secret must fail loudly instead of signing a token the relying
    # party (which holds the plaintext secret) could never verify.
    application.hash_client_secret = True
    application.client_secret = CLEARTEXT_SECRET
    application.save()
    with pytest.raises(ImproperlyConfigured) as exc:
        application.jwk_key
    assert "hash_client_secret=False" in str(exc.value)
    application.hash_client_secret = False
    application.client_secret = CLEARTEXT_SECRET
    application.save()

    # HS256 with an empty secret must fail loudly rather than sign with an empty (forgeable) key.
    application.client_secret = ""
    application.save()
    with pytest.raises(ImproperlyConfigured) as exc:
        application.jwk_key
    assert "non-empty client secret" in str(exc.value)
    application.client_secret = CLEARTEXT_SECRET
    application.save()

    # No algorithm
    application.algorithm = Application.NO_ALGORITHM
    with pytest.raises(ImproperlyConfigured) as exc:
        application.jwk_key
    assert "This application does not support signed tokens" == str(exc.value)


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean(oauth2_settings, application):
    # RS256, RSA key is configured
    application.clean()

    # RS256, RSA key is not configured
    oauth2_settings.OIDC_RSA_PRIVATE_KEY = None
    with pytest.raises(ValidationError) as exc:
        application.clean()
    assert "You must set OIDC_RSA_PRIVATE_KEY" in str(exc.value)

    # HS256 algorithm, auth code + confidential, unhashed secret -> allowed
    application.algorithm = Application.HS256_ALGORITHM
    application.hash_client_secret = False
    application.client_secret = CLEARTEXT_SECRET
    application.save()
    application.clean()

    # HS256 with hash_client_secret=True -> forbidden (the secret is the HS256 signing key)
    application.hash_client_secret = True
    with pytest.raises(ValidationError) as exc:
        application.clean()
    assert "hashed client secret" in str(exc.value)

    # HS256 with an already-hashed stored secret is rejected even when the flag is False
    # (e.g. the flag was toggled after the secret had already been hashed).
    application.client_secret = CLEARTEXT_SECRET
    application.save()  # hash_client_secret is still True here, so this stores a hashed secret
    application.hash_client_secret = False
    with pytest.raises(ValidationError) as exc:
        application.clean()
    assert "hashed client secret" in str(exc.value)

    # HS256 with an empty client secret -> forbidden (the secret is the HMAC signing key)
    application.hash_client_secret = False
    application.client_secret = ""
    application.save()
    with pytest.raises(ValidationError) as exc:
        application.clean()
    assert "without a client secret" in str(exc.value)

    # restore an unhashed secret for the remaining assertions
    application.client_secret = CLEARTEXT_SECRET
    application.save()

    # HS256, auth code + public -> forbidden
    application.client_type = Application.CLIENT_PUBLIC
    with pytest.raises(ValidationError) as exc:
        application.clean()
    assert "You cannot use HS256" in str(exc.value)

    # HS256, hybrid + confidential -> forbidden
    application.client_type = Application.CLIENT_CONFIDENTIAL
    application.authorization_grant_type = Application.GRANT_OPENID_HYBRID
    with pytest.raises(ValidationError) as exc:
        application.clean()
    assert "You cannot use HS256" in str(exc.value)

    application.authorization_grant_type = Application.GRANT_AUTHORIZATION_CODE

    # allowed_origins can be only https://
    application.allowed_origins = "http://example.com"
    with pytest.raises(ValidationError) as exc:
        application.clean()
    assert "allowed origin URI Validation error. invalid_scheme: http://example.com" in str(exc.value)
    application.allowed_origins = "https://example.com"
    application.clean()


def _test_wildcard_redirect_uris_valid(oauth2_settings, application, uris):
    oauth2_settings.ALLOW_URI_WILDCARDS = True
    application.redirect_uris = uris
    application.clean()


def _test_wildcard_redirect_uris_invalid(oauth2_settings, application, uris):
    oauth2_settings.ALLOW_URI_WILDCARDS = True
    application.redirect_uris = uris
    with pytest.raises(ValidationError):
        application.clean()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_wildcard_redirect_uris_valid_3ld(oauth2_settings, application):
    _test_wildcard_redirect_uris_valid(oauth2_settings, application, "https://*.example.com/path")


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_wildcard_redirect_uris_valid_partial_3ld(oauth2_settings, application):
    _test_wildcard_redirect_uris_valid(oauth2_settings, application, "https://*-partial.example.com/path")


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_wildcard_redirect_uris_invalid_3ld_not_starting_with_wildcard(
    oauth2_settings, application
):
    _test_wildcard_redirect_uris_invalid(oauth2_settings, application, "https://invalid-*.example.com/path")


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_wildcard_redirect_uris_invalid_2ld(oauth2_settings, application):
    _test_wildcard_redirect_uris_invalid(oauth2_settings, application, "https://*.com/path")


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_wildcard_redirect_uris_invalid_partial_2ld(oauth2_settings, application):
    _test_wildcard_redirect_uris_invalid(oauth2_settings, application, "https://*-partial.com/path")


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_wildcard_redirect_uris_invalid_2ld_not_starting_with_wildcard(
    oauth2_settings, application
):
    _test_wildcard_redirect_uris_invalid(oauth2_settings, application, "https://invalid-*.com/path")


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_wildcard_redirect_uris_invalid_tld(oauth2_settings, application):
    _test_wildcard_redirect_uris_invalid(oauth2_settings, application, "https://*/path")


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_wildcard_redirect_uris_invalid_tld_partial(oauth2_settings, application):
    _test_wildcard_redirect_uris_invalid(oauth2_settings, application, "https://*-partial/path")


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_wildcard_redirect_uris_invalid_tld_not_starting_with_wildcard(
    oauth2_settings, application
):
    _test_wildcard_redirect_uris_invalid(oauth2_settings, application, "https://invalid-*/path")


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.ALLOWED_SCHEMES_DEFAULT)
def test_application_origin_allowed_default_https(oauth2_settings, cors_application):
    """Test that http schemes are not allowed because ALLOWED_SCHEMES allows only https"""
    assert cors_application.origin_allowed("https://example.com")
    assert not cors_application.origin_allowed("http://example.com")


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.ALLOWED_SCHEMES_HTTP)
def test_application_origin_allowed_http(oauth2_settings, cors_application):
    """Test that http schemes are allowed because http was added to ALLOWED_SCHEMES"""
    assert cors_application.origin_allowed("https://example.com")
    assert cors_application.origin_allowed("http://example.com")


def test_redirect_to_uri_allowed_expects_allowed_uri_list():
    with pytest.raises(ValueError):
        redirect_to_uri_allowed("https://example.com", "https://example.com")
    assert redirect_to_uri_allowed("https://example.com", ["https://example.com"])


valid_wildcard_redirect_to_params = [
    ("https://valid.example.com", ["https://*.example.com"]),
    ("https://valid.valid.example.com", ["https://*.example.com"]),
    ("https://valid-partial.example.com", ["https://*-partial.example.com"]),
    ("https://valid.valid-partial.example.com", ["https://*-partial.example.com"]),
]


@pytest.mark.parametrize("uri, allowed_uri", valid_wildcard_redirect_to_params)
def test_wildcard_redirect_to_uri_allowed_valid(uri, allowed_uri, oauth2_settings):
    oauth2_settings.ALLOW_URI_WILDCARDS = True
    assert redirect_to_uri_allowed(uri, allowed_uri)


invalid_wildcard_redirect_to_params = [
    ("https://invalid.com", ["https://*.example.com"]),
    ("https://invalid.example.com", ["https://*-partial.example.com"]),
]


@pytest.mark.parametrize("uri, allowed_uri", invalid_wildcard_redirect_to_params)
def test_wildcard_redirect_to_uri_allowed_invalid(uri, allowed_uri, oauth2_settings):
    oauth2_settings.ALLOW_URI_WILDCARDS = True
    assert not redirect_to_uri_allowed(uri, allowed_uri)


def test_localhost_loopback_port_mismatch_rejected_by_default():
    # Default (ALLOW_LOCALHOST_LOOPBACK off): only the 127.0.0.1/::1 literals
    # get the RFC 8252 any-port exemption; "localhost" keeps strict matching.
    assert not redirect_to_uri_allowed("http://localhost:49152/callback", ["http://localhost/callback"])
    # ...and the IP literals keep the exemption regardless of the setting.
    assert redirect_to_uri_allowed("http://127.0.0.1:49152/callback", ["http://127.0.0.1/callback"])
    assert redirect_to_uri_allowed("http://[::1]:49152/callback", ["http://[::1]/callback"])


valid_localhost_loopback_params = [
    # RFC 8252 §7.3 any-port exemption, extended to "localhost" when enabled.
    ("http://localhost:49152/callback", ["http://localhost/callback"]),
    ("http://localhost/callback", ["http://localhost/callback"]),
    # urlparse lowercases the hostname, so the match is case-insensitive.
    ("http://LOCALHOST:49152/callback", ["http://localhost/callback"]),
]


@pytest.mark.parametrize("uri, allowed_uri", valid_localhost_loopback_params)
def test_localhost_loopback_redirect_allowed_when_enabled(uri, allowed_uri, oauth2_settings):
    oauth2_settings.ALLOW_LOCALHOST_LOOPBACK = True
    assert redirect_to_uri_allowed(uri, allowed_uri)


invalid_localhost_loopback_params = [
    # Path stays strict — a different callback path is a different endpoint.
    ("http://localhost:49152/other", ["http://localhost/callback"]),
    # https is not the RFC 8252 loopback shape; the exemption is http-only.
    ("https://localhost:49152/callback", ["https://localhost/callback"]),
    # No cross-spelling, both directions: the hostname must still match
    # exactly, so "localhost" is never conflated with the IP literals.
    ("http://127.0.0.1:49152/callback", ["http://localhost/callback"]),
    ("http://localhost:49152/callback", ["http://127.0.0.1/callback"]),
    ("http://localhost:49152/callback", ["http://[::1]/callback"]),
    # A hostname merely containing "localhost" is not loopback.
    ("http://localhost.evil.example:49152/callback", ["http://localhost/callback"]),
]


@pytest.mark.parametrize("uri, allowed_uri", invalid_localhost_loopback_params)
def test_localhost_loopback_redirect_rejected_when_enabled(uri, allowed_uri, oauth2_settings):
    oauth2_settings.ALLOW_LOCALHOST_LOOPBACK = True
    assert not redirect_to_uri_allowed(uri, allowed_uri)
