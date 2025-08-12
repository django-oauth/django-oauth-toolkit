import hashlib
import secrets
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.test.utils import override_settings
from django.utils import timezone

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
from .common_testing import retrieve_current_databases


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
        grant = Grant(code="test_code")
        self.assertEqual("%s" % grant, grant.code)

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
        access_token = AccessToken(token="test_token")
        self.assertEqual("%s" % access_token, access_token.token)

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
    def test_str(self):
        refresh_token = RefreshToken(token="test_token")
        self.assertEqual("%s" % refresh_token, refresh_token.token)


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


@pytest.mark.django_db(databases=retrieve_current_databases())
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


@pytest.mark.django_db(databases=retrieve_current_databases())
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


@pytest.mark.django_db(databases=retrieve_current_databases())
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

    # HS256 key
    application.algorithm = Application.HS256_ALGORITHM
    key = application.jwk_key
    assert key.kty == "oct"

    # No algorithm
    application.algorithm = Application.NO_ALGORITHM
    with pytest.raises(ImproperlyConfigured) as exc:
        application.jwk_key
    assert "This application does not support signed tokens" == str(exc.value)


@pytest.mark.django_db(databases=retrieve_current_databases())
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean(oauth2_settings, application):
    # RS256, RSA key is configured
    application.clean()

    # RS256, RSA key is not configured
    oauth2_settings.OIDC_RSA_PRIVATE_KEY = None
    with pytest.raises(ValidationError) as exc:
        application.clean()
    assert "You must set OIDC_RSA_PRIVATE_KEY" in str(exc.value)

    # HS256 algorithm, auth code + confidential -> allowed
    application.algorithm = Application.HS256_ALGORITHM
    application.clean()

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


@pytest.mark.django_db(databases=retrieve_current_databases())
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_wildcard_redirect_uris_valid_3ld(oauth2_settings, application):
    _test_wildcard_redirect_uris_valid(oauth2_settings, application, "https://*.example.com/path")


@pytest.mark.django_db(databases=retrieve_current_databases())
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_wildcard_redirect_uris_valid_partial_3ld(oauth2_settings, application):
    _test_wildcard_redirect_uris_valid(oauth2_settings, application, "https://*-partial.example.com/path")


@pytest.mark.django_db(databases=retrieve_current_databases())
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_wildcard_redirect_uris_invalid_3ld_not_starting_with_wildcard(
    oauth2_settings, application
):
    _test_wildcard_redirect_uris_invalid(oauth2_settings, application, "https://invalid-*.example.com/path")


@pytest.mark.django_db(databases=retrieve_current_databases())
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_wildcard_redirect_uris_invalid_2ld(oauth2_settings, application):
    _test_wildcard_redirect_uris_invalid(oauth2_settings, application, "https://*.com/path")


@pytest.mark.django_db(databases=retrieve_current_databases())
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_wildcard_redirect_uris_invalid_partial_2ld(oauth2_settings, application):
    _test_wildcard_redirect_uris_invalid(oauth2_settings, application, "https://*-partial.com/path")


@pytest.mark.django_db(databases=retrieve_current_databases())
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_wildcard_redirect_uris_invalid_2ld_not_starting_with_wildcard(
    oauth2_settings, application
):
    _test_wildcard_redirect_uris_invalid(oauth2_settings, application, "https://invalid-*.com/path")


@pytest.mark.django_db(databases=retrieve_current_databases())
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_wildcard_redirect_uris_invalid_tld(oauth2_settings, application):
    _test_wildcard_redirect_uris_invalid(oauth2_settings, application, "https://*/path")


@pytest.mark.django_db(databases=retrieve_current_databases())
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_wildcard_redirect_uris_invalid_tld_partial(oauth2_settings, application):
    _test_wildcard_redirect_uris_invalid(oauth2_settings, application, "https://*-partial/path")


@pytest.mark.django_db(databases=retrieve_current_databases())
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_application_clean_wildcard_redirect_uris_invalid_tld_not_starting_with_wildcard(
    oauth2_settings, application
):
    _test_wildcard_redirect_uris_invalid(oauth2_settings, application, "https://invalid-*/path")


@pytest.mark.django_db(databases=retrieve_current_databases())
@pytest.mark.oauth2_settings(presets.ALLOWED_SCHEMES_DEFAULT)
def test_application_origin_allowed_default_https(oauth2_settings, cors_application):
    """Test that http schemes are not allowed because ALLOWED_SCHEMES allows only https"""
    assert cors_application.origin_allowed("https://example.com")
    assert not cors_application.origin_allowed("http://example.com")


@pytest.mark.django_db(databases=retrieve_current_databases())
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
