import hashlib
import secrets
import uuid
from datetime import timedelta
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db import connection
from django.db import models as django_models
from django.test.utils import CaptureQueriesContext, override_settings
from django.utils import timezone
from django.utils.functional import Promise

from oauth2_provider import models as oauth2_models
from oauth2_provider.models import (
    _format_uri_mismatch_reasons,
    _loggable_uri,
    check_redirect_to_uri_allowed,
    clear_expired,
    get_access_token_model,
    get_application_model,
    get_grant_model,
    get_id_token_model,
    get_refresh_token_model,
    redirect_to_uri_allowed,
    refresh_token_expire_timedelta,
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

    def _make_refresh_token(self, token_family, revoked=None, with_access_token=True):
        access_token = None
        if with_access_token:
            access_token = AccessToken.objects.create(
                user=self.user,
                token=f"access token for {secrets.token_urlsafe(8)}",
                application=self.app,
                expires=timezone.now() + timedelta(hours=1),
                scope="read write",
            )
        return RefreshToken.objects.create(
            user=self.user,
            token=secrets.token_urlsafe(32),
            application=self.app,
            access_token=access_token,
            token_family=token_family,
            revoked=revoked,
        )

    def test_revoke_family_matches_revoking_each_member(self):
        """
        revoke_family() must leave the family in the state a revoke() per row would:
        live members revoked with their access tokens deleted, the revoked timestamp of
        an already revoked member kept, and nothing outside the family affected. See
        issue #1809.
        """
        family = uuid.uuid4()
        live = self._make_refresh_token(family)
        live_access_token_pk = live.access_token_id
        already_revoked_at = timezone.now() - timedelta(minutes=5)
        already_revoked = self._make_refresh_token(family, revoked=already_revoked_at)
        already_revoked_access_token_pk = already_revoked.access_token_id
        other_family = self._make_refresh_token(uuid.uuid4())
        no_family = self._make_refresh_token(None)

        RefreshToken.revoke_family(family)

        live.refresh_from_db()
        self.assertIsNotNone(live.revoked)
        self.assertIsNone(live.access_token_id)
        self.assertFalse(
            AccessToken.objects.filter(pk=live_access_token_pk).exists(),
            "the bound access token should have been deleted, as revoke() does",
        )

        already_revoked.refresh_from_db()
        self.assertEqual(already_revoked.revoked, already_revoked_at)
        # revoke() nulls access_token as it deletes it, so a revoked row does not
        # normally have one. Where it does, the family is compromised: it goes too.
        self.assertIsNone(already_revoked.access_token_id)
        self.assertFalse(AccessToken.objects.filter(pk=already_revoked_access_token_pk).exists())

        for untouched in (other_family, no_family):
            untouched.refresh_from_db()
            self.assertIsNone(untouched.revoked)
            self.assertIsNotNone(untouched.access_token_id)

    def test_revoke_family_without_a_family_is_a_no_op(self):
        # token_family is null for tokens issued before rotation was enabled, and those
        # rows are each their own lineage: sweeping on null would revoke unrelated tokens.
        no_family = self._make_refresh_token(None)

        RefreshToken.revoke_family(None)

        no_family.refresh_from_db()
        self.assertIsNone(no_family.revoked)
        self.assertIsNotNone(no_family.access_token_id)

    def test_revoke_family_falls_back_when_two_live_members_share_a_checksum(self):
        """
        Uniqueness is (token_checksum, revoked), so the bulk update cannot stamp one
        timestamp across two live members holding the same checksum. No request path mints
        that state today -- rotation draws a fresh token every time, and #1818 closed the
        non-rotating re-issue that used to resurrect a revoked token as a live row with the
        same value -- but the schema still permits it (#1816), so a custom
        REFRESH_TOKEN_GENERATOR, a data migration or a direct write can leave a family in
        it. Reuse detection is a security path and must not raise on the way to
        invalid_grant, so fall back to the pre-#1809 per-row sweep instead.
        """
        family = uuid.uuid4()
        first = self._make_refresh_token(family)
        first_access_token_pk = first.access_token_id
        second = RefreshToken.objects.create(
            user=self.user,
            token=first.token,
            application=self.app,
            access_token=AccessToken.objects.create(
                user=self.user,
                token=f"access token for {secrets.token_urlsafe(8)}",
                application=self.app,
                expires=timezone.now() + timedelta(hours=1),
                scope="read write",
            ),
            token_family=family,
        )
        second_access_token_pk = second.access_token_id
        self.assertEqual(first.token_checksum, second.token_checksum)

        RefreshToken.revoke_family(family)

        for member in (first, second):
            member.refresh_from_db()
            self.assertIsNotNone(member.revoked, "every live member must still be revoked")
            self.assertIsNone(member.access_token_id)
        # The per-row fallback gives each row its own timezone.now(), which is what keeps
        # the two rows apart under the constraint.
        self.assertNotEqual(first.revoked, second.revoked)
        self.assertFalse(
            AccessToken.objects.filter(pk__in=[first_access_token_pk, second_access_token_pk]).exists()
        )

    def test_revoke_family_query_count_does_not_grow_with_the_family(self):
        """
        The whole point of the set-based sweep: a family that has been rotating for weeks
        costs the same as a fresh one. See issue #1809.
        """

        def query_count_for(historical_members):
            family = uuid.uuid4()
            self._make_refresh_token(family)
            for _ in range(historical_members):
                self._make_refresh_token(family, revoked=timezone.now())
            with CaptureQueriesContext(connection) as captured:
                RefreshToken.revoke_family(family)
            return len(captured)

        self.assertEqual(query_count_for(1), query_count_for(30))


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

    def test_clear_expired_reclaims_refresh_token_at_expiry_boundary(self):
        # A refresh token whose access token expired exactly at the cutoff
        # (access_token.expires == now - REFRESH_TOKEN_EXPIRE_SECONDS) is reclaimed, matching
        # AccessToken.is_expired() (``now >= expires``) and validation-time expiry.
        self.oauth2_settings.CLEAR_EXPIRED_TOKENS_BATCH_INTERVAL = 0.0
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = self.delta_secs // 2
        app = Application.objects.get(name="test_app")
        frozen_now = timezone.now()
        boundary_at = AccessToken.objects.create(
            token="boundary AT", expires=frozen_now - timedelta(seconds=self.delta_secs // 2)
        )
        boundary_rt = RefreshToken.objects.create(
            token="boundary RT", application=app, access_token=boundary_at, user=self.user
        )

        with mock.patch("oauth2_provider.models.timezone.now", return_value=frozen_now):
            clear_expired()

        assert not RefreshToken.objects.filter(pk=boundary_rt.pk).exists(), (
            "a refresh token at exactly the expiry cutoff must be reclaimed"
        )

    def test_clear_expired_deletes_orphaned_refresh_tokens(self):
        """
        A non-revoked refresh token whose access token is gone (``access_token`` is
        SET_NULL, so an out-of-band access-token deletion strands it) is an orphan. The
        toolkit no longer produces these -- the ``/revoke/`` endpoint and admin view both
        revoke the bound refresh token -- so any that remain are stale and are reclaimed
        regardless of age or REFRESH_TOKEN_EXPIRE_SECONDS. This is the case that could
        previously survive in the DB forever, since the age join can never match a NULL
        access token (#746).
        """
        # No age policy at all: orphans are still deleted.
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = None
        app = Application.objects.get(name="test_app")

        old_orphan = RefreshToken.objects.create(
            token="old orphan", application=app, access_token=None, user=self.user
        )
        RefreshToken.objects.filter(pk=old_orphan.pk).update(created=self.earlier)
        new_orphan = RefreshToken.objects.create(
            token="new orphan", application=app, access_token=None, user=self.user
        )

        # A refresh token paired with a current access token must survive.
        paired_at = AccessToken.objects.create(token="paired current AT", expires=self.later)
        paired = RefreshToken.objects.create(
            token="paired refresh token", application=app, access_token=paired_at, user=self.user
        )

        clear_expired()

        assert not RefreshToken.objects.filter(pk=old_orphan.pk).exists()
        assert not RefreshToken.objects.filter(pk=new_orphan.pk).exists(), (
            "orphaned refresh tokens are reclaimed regardless of age"
        )
        assert RefreshToken.objects.filter(pk=paired.pk).exists(), (
            "a refresh token paired with a current access token must survive"
        )


@pytest.mark.usefixtures("oauth2_settings")
class TestRefreshTokenExpireTimedelta(TestCase):
    def test_none_and_zero_disable_expiry(self):
        for value in (None, 0, timedelta(0)):
            self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = value
            assert refresh_token_expire_timedelta() is None, f"{value!r} should disable expiry"

    def test_int_seconds_coerced_to_timedelta(self):
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = 3600
        assert refresh_token_expire_timedelta() == timedelta(seconds=3600)

    def test_timedelta_passed_through(self):
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = timedelta(days=1)
        assert refresh_token_expire_timedelta() == timedelta(days=1)

    def test_non_numeric_raises(self):
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = "not-a-number"
        with pytest.raises(ImproperlyConfigured, match="must be either a timedelta or seconds"):
            refresh_token_expire_timedelta()

    def test_negative_raises(self):
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = -3600
        with pytest.raises(ImproperlyConfigured, match="must not be negative"):
            refresh_token_expire_timedelta()

    def test_out_of_range_raises(self):
        # timedelta() overflows for absurdly large values; normalize to ImproperlyConfigured.
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = 10**20
        with pytest.raises(ImproperlyConfigured, match="must be either a timedelta or seconds"):
            refresh_token_expire_timedelta()


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
            # A current (non-revoked) refresh token is always paired with an access token
            # in normal operation; without one it would be an orphan that clear_expired now
            # reclaims. Give it a non-expired access token so it survives on its own merits.
            current_access_token = AccessToken.objects.create(
                token=f"current refresh token's access token {i}",
                expires=cls.now + timedelta(seconds=cls.grace_secs),
            )
            RefreshToken(
                token=f"current refresh token {i}",
                application=app,
                user=cls.user,
                access_token=current_access_token,
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


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_errors_are_associated_with_their_field(oauth2_settings, application):
    """Every ``clean()`` error names the field it belongs to (see #1343)."""
    # An unusable redirect uri belongs to redirect_uris.
    application.redirect_uris = "invalid"
    with pytest.raises(ValidationError) as exc:
        application.clean()
    assert list(exc.value.message_dict) == ["redirect_uris"]
    assert "invalid_scheme: invalid" in exc.value.message_dict["redirect_uris"][0]

    # So does an empty redirect_uris for a grant type that requires one.
    application.redirect_uris = ""
    with pytest.raises(ValidationError) as exc:
        application.clean()
    assert list(exc.value.message_dict) == ["redirect_uris"]
    assert "redirect_uris cannot be empty" in exc.value.message_dict["redirect_uris"][0]
    application.redirect_uris = "https://example.org"

    # A non-https origin belongs to allowed_origins, not to the whole form.
    application.allowed_origins = "http://example.com"
    with pytest.raises(ValidationError) as exc:
        application.clean()
    assert list(exc.value.message_dict) == ["allowed_origins"]
    application.allowed_origins = ""

    # A missing RSA key is only actionable on the algorithm field.
    oauth2_settings.OIDC_RSA_PRIVATE_KEY = None
    with pytest.raises(ValidationError) as exc:
        application.clean()
    assert list(exc.value.message_dict) == ["algorithm"]

    # HS256 with a public client: again the algorithm is what has to change.
    application.algorithm = Application.HS256_ALGORITHM
    application.hash_client_secret = False
    application.client_secret = CLEARTEXT_SECRET
    application.client_type = Application.CLIENT_PUBLIC
    with pytest.raises(ValidationError) as exc:
        application.clean()
    assert list(exc.value.message_dict) == ["algorithm"]
    application.client_type = Application.CLIENT_CONFIDENTIAL

    # HS256 without a secret: the secret is the missing piece.
    application.client_secret = ""
    with pytest.raises(ValidationError) as exc:
        application.clean()
    assert list(exc.value.message_dict) == ["client_secret"]

    # HS256 while hashing is enabled: the flag is the thing to uncheck.
    application.client_secret = CLEARTEXT_SECRET
    application.hash_client_secret = True
    with pytest.raises(ValidationError) as exc:
        application.clean()
    assert list(exc.value.message_dict) == ["hash_client_secret"]

    # HS256 with a secret that is already hashed: hashing is off, so the stored
    # secret itself has to be replaced with an unhashed one.
    application.hash_client_secret = False
    application.client_secret = make_password(CLEARTEXT_SECRET)
    with pytest.raises(ValidationError) as exc:
        application.clean()
    assert list(exc.value.message_dict) == ["client_secret"]


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_reports_every_error_at_once(oauth2_settings, application):
    """Unrelated problems are collected, not reported one save at a time."""
    application.redirect_uris = "invalid"
    application.allowed_origins = "http://example.com"
    application.algorithm = Application.HS256_ALGORITHM
    application.client_type = Application.CLIENT_PUBLIC
    application.hash_client_secret = True

    with pytest.raises(ValidationError) as exc:
        application.clean()
    assert set(exc.value.message_dict) == {
        "redirect_uris",
        "allowed_origins",
        "algorithm",
        "hash_client_secret",
    }


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_reports_every_invalid_uri(oauth2_settings, application):
    """Each bad uri in a multi-line field gets its own message."""
    application.redirect_uris = "invalid-one\ninvalid-two"
    with pytest.raises(ValidationError) as exc:
        application.clean()
    messages = exc.value.message_dict["redirect_uris"]
    assert len(messages) == 2
    assert "invalid-one" in messages[0]
    assert "invalid-two" in messages[1]


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
    ("https://deploy-preview-42--sitename.netlify.app", ["https://*--sitename.netlify.app"]),
]


@pytest.mark.parametrize("uri, allowed_uri", valid_wildcard_redirect_to_params)
def test_wildcard_redirect_to_uri_allowed_valid(uri, allowed_uri, oauth2_settings):
    oauth2_settings.ALLOW_URI_WILDCARDS = True
    assert redirect_to_uri_allowed(uri, allowed_uri)


invalid_wildcard_redirect_to_params = [
    ("https://invalid.com", ["https://*.example.com"]),
    ("https://invalid.example.com", ["https://*-partial.example.com"]),
    ("https://x-sitename.netlify.app", ["https://*--sitename.netlify.app"]),
    ("https://evil--othersite.netlify.app", ["https://*--sitename.netlify.app"]),
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


# RFC 9700 §2.1 requires exact matching of redirect URIs (see also OpenID Connect
# Core §3.1.2.1, mandating RFC 3986 §6.2.1 Simple String Comparison).
exact_redirect_match_params = [
    # Identical URIs match, with and without a registered query.
    ("https://example.com/cb", ["https://example.com/cb"], True),
    ("https://example.com/cb?a=1", ["https://example.com/cb?a=1"], True),
    ("https://example.com/cb?a=1&b=2", ["https://example.com/cb?a=1&b=2"], True),
    # Query parameters that were never registered must not be accepted: an
    # attacker could otherwise append parameters to an otherwise-legitimate
    # redirect URI and have them reflected into the client's callback alongside
    # the authorization code (RFC 9700 §4.1).
    ("https://example.com/cb?evil=1", ["https://example.com/cb"], False),
    ("https://example.com/cb?a=1&evil=1", ["https://example.com/cb?a=1"], False),
    # A registered parameter that is missing from the request is also a mismatch.
    ("https://example.com/cb", ["https://example.com/cb?a=1"], False),
    # A bare trailing "?" is an empty query component, not the absence of one;
    # .query is "" for both, so the delimiter's presence is what distinguishes them.
    ("https://example.com/cb?", ["https://example.com/cb"], False),
    ("https://example.com/cb", ["https://example.com/cb?"], False),
    ("https://example.com/cb?", ["https://example.com/cb?"], True),
    # ...but a percent-encoded %3F is not a query delimiter.
    ("https://example.com/cb%3F", ["https://example.com/cb%3F"], True),
    # Reordered parameters are no longer accepted; matching is by string.
    ("https://example.com/cb?b=2&a=1", ["https://example.com/cb?a=1&b=2"], False),
    # RFC 6749 §3.1.2: the endpoint URI MUST NOT include a fragment component.
    # urlparse() splits the fragment off, so these used to match.
    ("https://example.com/cb#x", ["https://example.com/cb"], False),
    ("https://example.com/cb?a=1#x", ["https://example.com/cb?a=1"], False),
    # A bare "#" is an empty fragment component, not the absence of one; .fragment
    # is "" for both, so the raw string is what has to be tested.
    ("https://example.com/cb#", ["https://example.com/cb"], False),
    # ...but a percent-encoded %23 is not a fragment delimiter.
    ("https://example.com/cb%23", ["https://example.com/cb%23"], True),
    # A registered URI carrying a fragment cannot authorize anything, since every
    # request form that would match it is rejected above.
    ("https://example.com/cb", ["https://example.com/cb#frag"], False),
    # urlparse() peels ";params" off the last path segment into a separate
    # attribute, so comparing .path alone let these smuggle data to the callback.
    ("https://example.com/cb;evil=1", ["https://example.com/cb"], False),
    ("https://example.com/cb;evil=1?a=1", ["https://example.com/cb?a=1"], False),
    # ...and a registered URI that genuinely carries parameters still matches.
    ("https://example.com/cb;a=1", ["https://example.com/cb;a=1"], True),
    # Credentials are not part of a registered callback: only .hostname was
    # compared, so userinfo rode along unnoticed.
    ("https://evil@example.com/cb", ["https://example.com/cb"], False),
    ("https://user:pw@example.com/cb", ["https://example.com/cb"], False),
    ("https://example.com/cb", ["https://evil@example.com/cb"], False),
]


@pytest.mark.parametrize("uri, allowed_uris, expected", exact_redirect_match_params)
def test_redirect_to_uri_allowed_matches_exactly(uri, allowed_uris, expected):
    assert redirect_to_uri_allowed(uri, allowed_uris) is expected


def test_redirect_to_uri_allowed_loopback_port_exemption_survives_exact_matching():
    # RFC 9700 §2.1 carves out "port numbers in localhost redirection URIs of
    # native apps"; RFC 8252 §7.3 requires it.  Exact matching must not undo it.
    assert redirect_to_uri_allowed("http://127.0.0.1:49152/cb", ["http://127.0.0.1/cb"])
    # ...but the exemption is only for the port, not for the query.
    assert not redirect_to_uri_allowed("http://127.0.0.1:49152/cb?evil=1", ["http://127.0.0.1/cb"])


def test_private_use_uri_scheme_redirect_allowed():
    # RFC 8252 §7.1: a private-use URI scheme redirect has no naming authority,
    # so a single slash follows the scheme and urlparse() reports hostname None.
    uri = "com.example.app:/oauth2redirect/example-provider"
    assert redirect_to_uri_allowed(uri, [uri])
    assert redirect_to_uri_allowed("com.example.app:/oauth2redirect", ["com.example.app:/oauth2redirect"])
    # The single-slash and double-slash spellings parse to different hostnames
    # (None vs "oauth2redirect"), so they are not interchangeable.
    single, double = "com.example.app:/oauth2redirect", "com.example.app://oauth2redirect"
    assert not redirect_to_uri_allowed(single, [double])
    assert not redirect_to_uri_allowed(double, [single])
    # A different path is a different endpoint.
    assert not redirect_to_uri_allowed("com.example.app:/other", ["com.example.app:/oauth2redirect"])


def test_private_use_uri_scheme_redirect_allowed_with_wildcards_enabled(oauth2_settings):
    # Regression: the wildcard branch used to call .startswith() on the hostname
    # unguarded, raising AttributeError for authority-less private-use URIs.
    oauth2_settings.ALLOW_URI_WILDCARDS = True
    assert redirect_to_uri_allowed("com.example.app:/oauth2redirect", ["com.example.app:/oauth2redirect"])
    assert not redirect_to_uri_allowed("com.example.app:/oauth2redirect", ["https://*.example.com/cb"])
    # ...and from the other side: an authority-less request against a wildcard.
    assert not redirect_to_uri_allowed("https:/oauth2redirect", ["https://*.example.com/cb"])


# All model bases whose fields are rendered as labels in the admin and in
# user-facing forms.
TRANSLATABLE_LABEL_MODELS = [
    oauth2_models.AbstractApplication,
    oauth2_models.AbstractGrant,
    oauth2_models.AbstractAccessToken,
    oauth2_models.AbstractRefreshToken,
    oauth2_models.AbstractIDToken,
    oauth2_models.AbstractDeviceGrant,
]


@pytest.mark.parametrize("model", TRANSLATABLE_LABEL_MODELS, ids=lambda model: model.__name__)
def test_model_field_labels_are_translatable(model):
    # See #403: every user-visible field label must go through gettext_lazy so
    # deployments can ship the admin and the authorization UI in other languages.
    # Auto-created primary keys are excluded: Django supplies "ID" itself.
    untranslated = sorted(
        field.name
        for field in model._meta.fields
        if not isinstance(field, django_models.AutoField) and not isinstance(field.verbose_name, Promise)
    )
    assert untranslated == []


# Diagnostics for a redirect URI that matched nothing (#681).  The detail lives in
# the log and nowhere else: see test_pre_auth_redirect_uri_mismatch_does_not_leak_
# registered_uris in tests/test_authorization_code.py for the other half of that
# contract.

mismatch_reason_params = [
    # (uri, allowed_uris, expected reason)
    ("https://example.com/cb#frag", ["https://example.com/cb"], "fragment"),
    ("https://evil@example.com/cb", ["https://example.com/cb"], "userinfo credentials"),
    ("https://example.com/cb", ["https://example.com/cb#frag"], "registered URI has a fragment"),
    ("https://example.com/cb", ["https://evil@example.com/cb"], "registered URI carries userinfo"),
    ("http://example.com/cb", ["https://example.com/cb"], "scheme differs"),
    ("https://other.com/cb", ["https://example.com/cb"], "hostname differs"),
    ("https://example.com:8443/cb", ["https://example.com/cb"], "port differs"),
    ("https://example.com/other", ["https://example.com/cb"], "path differs"),
    ("https://example.com/cb?a=1", ["https://example.com/cb"], "query component"),
    ("https://example.com/cb?a=2", ["https://example.com/cb?a=1"], "query string differs"),
]


@pytest.mark.parametrize("uri, allowed_uris, expected_reason", mismatch_reason_params)
def test_check_redirect_to_uri_allowed_reports_reason(uri, allowed_uris, expected_reason):
    allowed, reasons = check_redirect_to_uri_allowed(uri, allowed_uris)
    assert not allowed
    assert expected_reason in _format_uri_mismatch_reasons(reasons)


def test_check_redirect_to_uri_allowed_reports_wildcard_reason(oauth2_settings):
    oauth2_settings.ALLOW_URI_WILDCARDS = True
    allowed, reasons = check_redirect_to_uri_allowed("https://other.com/cb", ["https://*.example.com/cb"])
    assert not allowed
    assert "registered wildcard" in _format_uri_mismatch_reasons(reasons)


def test_check_redirect_to_uri_allowed_reports_every_candidate():
    allowed, reasons = check_redirect_to_uri_allowed(
        "https://example.com/cb", ["https://example.com/other", "http://example.com/cb"]
    )
    assert not allowed
    assert [candidate for candidate, _reason in reasons] == [
        "https://example.com/other",
        "http://example.com/cb",
    ]
    assert _format_uri_mismatch_reasons(reasons) == (
        "'https://example.com/other': path differs; 'http://example.com/cb': scheme differs"
    )


def test_format_uri_mismatch_reasons_with_nothing_registered():
    allowed, reasons = check_redirect_to_uri_allowed("https://example.com/cb", [])
    assert not allowed
    assert _format_uri_mismatch_reasons(reasons) == "no URIs are registered"


@pytest.mark.parametrize(
    "uri, allowed_uris, expected",
    exact_redirect_match_params + [(u, a, True) for u, a in valid_wildcard_redirect_to_params],
)
def test_check_redirect_to_uri_allowed_agrees_with_redirect_to_uri_allowed(
    uri, allowed_uris, expected, oauth2_settings
):
    # check_redirect_to_uri_allowed() is the matcher; redirect_to_uri_allowed() is
    # a thin wrapper over it.  Assert the verdict against `expected` on both, not
    # just that the two agree -- agreement alone holds by construction and would
    # survive the matcher returning the wrong answer.  Wildcards are enabled here
    # because this is the only place the wildcard configuration is exercised
    # against the exact-match corpus.
    oauth2_settings.ALLOW_URI_WILDCARDS = True
    allowed, _reasons = check_redirect_to_uri_allowed(uri, allowed_uris)
    assert allowed is expected
    assert redirect_to_uri_allowed(uri, allowed_uris) is expected


def test_check_redirect_to_uri_allowed_expects_allowed_uri_list():
    with pytest.raises(ValueError):
        check_redirect_to_uri_allowed("https://example.com", "https://example.com")


def test_loggable_uri_escapes_control_characters():
    # A raw CR/LF in a client-supplied URI would otherwise forge log lines.
    rendered = _loggable_uri("https://example.com/cb\r\nWARNING forged log line")
    assert "\r" not in rendered
    assert "\n" not in rendered
    assert "\\r\\n" in rendered


def test_loggable_uri_truncates_long_uris():
    rendered = _loggable_uri("https://example.com/cb?x=" + "a" * 10000)
    assert len(rendered) < 300
    assert rendered.endswith("...[truncated]'")


def test_loggable_uri_handles_none():
    assert _loggable_uri(None) == "None"


class TestRedirectURIMismatchLogging(BaseTestModels):
    """The mismatch detail requested in #681 is emitted to the log, at DEBUG."""

    def setUp(self):
        super().setUp()
        self.application = Application.objects.create(
            name="Test Application",
            redirect_uris="https://example.com/cb",
            post_logout_redirect_uris="https://example.com/logout",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

    def test_application_redirect_uri_mismatch_is_logged(self):
        with self.assertLogs("oauth2_provider", level="DEBUG") as captured:
            assert not self.application.redirect_uri_allowed("https://example.com/other")
        message = "\n".join(captured.output)
        assert "redirect_uri 'https://example.com/other'" in message
        assert "does not match any redirect_uri registered" in message
        assert repr(self.application.client_id) in message
        assert "'https://example.com/cb': path differs" in message

    def test_application_post_logout_redirect_uri_mismatch_is_logged(self):
        with self.assertLogs("oauth2_provider", level="DEBUG") as captured:
            assert not self.application.post_logout_redirect_uri_allowed("https://example.com/elsewhere")
        message = "\n".join(captured.output)
        assert "post_logout_redirect_uri 'https://example.com/elsewhere'" in message
        assert "does not match any post_logout_redirect_uri registered" in message
        assert "'https://example.com/logout': path differs" in message

    def test_matching_redirect_uri_is_not_logged(self):
        with self.assertNoLogs("oauth2_provider", level="DEBUG"):
            assert self.application.redirect_uri_allowed("https://example.com/cb")

    def test_nothing_is_logged_above_debug(self):
        # The detail must stay out of production logs unless the operator opts in
        # by lowering the level of the "oauth2_provider" logger, and the message
        # must not even be assembled when it would be discarded.
        with mock.patch.object(oauth2_models, "_format_uri_mismatch_reasons") as format_reasons:
            with self.assertNoLogs("oauth2_provider", level="INFO"):
                assert not self.application.redirect_uri_allowed("https://example.com/other")
        format_reasons.assert_not_called()

    def test_logged_requested_uri_is_escaped(self):
        # Short enough to survive truncation, so the CRLF really is neutralised by
        # escaping rather than by being cut off past the truncation point.
        hostile = "https://example.com/cb?x=1\r\nWARNING forged log line"
        with self.assertLogs("oauth2_provider", level="DEBUG") as captured:
            assert not self.application.redirect_uri_allowed(hostile)
        message = "\n".join(captured.output)
        assert "...[truncated]" not in message
        assert "\r" not in message
        assert "\\r\\n" in message

    def test_logged_requested_uri_is_truncated(self):
        hostile = "https://example.com/cb?x=" + "a" * 10000 + "\r\nWARNING forged"
        with self.assertLogs("oauth2_provider", level="DEBUG") as captured:
            assert not self.application.redirect_uri_allowed(hostile)
        message = "\n".join(captured.output)
        assert "...[truncated]" in message
        assert "WARNING forged" not in message

    def test_logged_registered_uris_are_escaped_truncated_and_capped(self):
        # Registered URIs are registrant-supplied under DCR/CIMD, so they get the
        # same treatment as the requested URI: escaped, truncated, and capped.
        self.application.redirect_uris = " ".join(
            ["https://example.com/cb%d" % i for i in range(25)] + ["https://example.com/" + "b" * 10000]
        )
        with self.assertLogs("oauth2_provider", level="DEBUG") as captured:
            assert not self.application.redirect_uri_allowed("https://example.com/nope")
        message = "\n".join(captured.output)
        assert "...and 16 further registered URI(s) not listed" in message
        assert message.count("path differs") == 10

    def test_grant_redirect_uri_mismatch_is_logged_without_the_code(self):
        grant = Grant.objects.create(
            user=self.user,
            code="grant_code_that_must_not_be_logged",
            application=self.application,
            expires=timezone.now() + timedelta(days=1),
            redirect_uri="https://example.com/cb",
            scope="",
        )
        with self.assertLogs("oauth2_provider", level="DEBUG") as captured:
            assert not grant.redirect_uri_allowed("https://example.com/other")
        message = "\n".join(captured.output)
        assert "redirect_uri 'https://example.com/other'" in message
        assert "'https://example.com/cb'" in message
        assert "grant #%s" % grant.pk in message
        # An authorization code is a credential and must never reach the log.
        assert grant.code not in message

    def test_grant_redirect_uri_match_is_not_logged(self):
        grant = Grant.objects.create(
            user=self.user,
            code="another_grant_code",
            application=self.application,
            expires=timezone.now() + timedelta(days=1),
            redirect_uri="https://example.com/cb",
            scope="",
        )
        with self.assertNoLogs("oauth2_provider", level="DEBUG"):
            assert grant.redirect_uri_allowed("https://example.com/cb")
