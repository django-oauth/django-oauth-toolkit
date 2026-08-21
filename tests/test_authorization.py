import datetime
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.admin.sites import AdminSite
from django.contrib.auth import get_user_model
from django.contrib.messages.storage.fallback import FallbackStorage
from django.db.models import RestrictedError
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone

from oauth2_provider.admin import AuthorizationAdmin
from oauth2_provider.models import (
    clear_expired,
    get_access_token_model,
    get_application_model,
    get_authorization_model,
    get_device_grant_model,
    get_grant_model,
    get_id_token_model,
    get_refresh_token_model,
)
from oauth2_provider.oauth2_validators import OAuth2Validator

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header


Application = get_application_model()
AccessToken = get_access_token_model()
Authorization = get_authorization_model()
DeviceGrant = get_device_grant_model()
Grant = get_grant_model()
IDToken = get_id_token_model()
RefreshToken = get_refresh_token_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.DEFAULT_SCOPES_RW)
class BaseAuthorizationTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.test_user = UserModel.objects.create_user("test_user", "test@example.com", "123456")
        cls.dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")

        cls.application = Application.objects.create(
            name="Test Application",
            redirect_uris="http://example.org",
            user=cls.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
        )

    def setUp(self):
        self.oauth2_settings.PKCE_REQUIRED = False

    def get_authorization_code(self, scope="read write", response_type="code"):
        self.client.login(username="test_user", password="123456")
        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": self.application.client_id,
                "state": "random_state_string",
                "scope": scope,
                "redirect_uri": "http://example.org",
                "response_type": response_type,
                "allow": True,
            },
        )
        self.assertEqual(response.status_code, 302)
        query_dict = parse_qs(urlparse(response["Location"]).query)
        return query_dict["code"].pop()

    def exchange_authorization_code(self, authorization_code):
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        return self.client.post(
            reverse("oauth2_provider:token"),
            data={
                "grant_type": "authorization_code",
                "code": authorization_code,
                "redirect_uri": "http://example.org",
            },
            **auth_headers,
        )

    def refresh(self, refresh_token):
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        return self.client.post(
            reverse("oauth2_provider:token"),
            data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            **auth_headers,
        )


class TestAuthorizationCodeLineage(BaseAuthorizationTest):
    def test_authorize_creates_authorization(self):
        authorization_code = self.get_authorization_code()

        grant = Grant.objects.get(code=authorization_code)
        self.assertIsNotNone(grant.authorization)
        self.assertEqual(grant.authorization.user, self.test_user)
        self.assertEqual(grant.authorization.application, self.application)
        self.assertEqual(grant.authorization.client_id, self.application.client_id)
        self.assertEqual(grant.authorization.grant_type, Application.GRANT_AUTHORIZATION_CODE)
        self.assertEqual(set(grant.authorization.scope.split()), {"read", "write"})
        self.assertTrue(grant.authorization.is_active())

    def test_exchanged_tokens_inherit_authorization(self):
        authorization_code = self.get_authorization_code()
        grant = Grant.objects.get(code=authorization_code)

        response = self.exchange_authorization_code(authorization_code)
        self.assertEqual(response.status_code, 200)
        token_data = response.json()

        access_token = AccessToken.objects.get(token=token_data["access_token"])
        refresh_token = RefreshToken.objects.get(token=token_data["refresh_token"])
        self.assertEqual(access_token.authorization, grant.authorization)
        self.assertEqual(refresh_token.authorization, grant.authorization)

    def test_exchange_does_not_create_a_second_authorization(self):
        authorization_code = self.get_authorization_code()
        self.assertEqual(self.exchange_authorization_code(authorization_code).status_code, 200)

        self.assertEqual(Authorization.objects.count(), 1)

    def test_grant_persists_after_exchange(self):
        authorization_code = self.get_authorization_code()
        response = self.exchange_authorization_code(authorization_code)
        self.assertEqual(response.status_code, 200)

        grant = Grant.objects.get(code=authorization_code)
        self.assertIsNotNone(grant.exchanged_at)

    def test_replayed_code_is_rejected_and_revokes_tokens(self):
        authorization_code = self.get_authorization_code()
        response = self.exchange_authorization_code(authorization_code)
        self.assertEqual(response.status_code, 200)
        token_data = response.json()

        replay_response = self.exchange_authorization_code(authorization_code)
        self.assertEqual(replay_response.status_code, 400)
        self.assertEqual(replay_response.json()["error"], "invalid_grant")

        # RFC 6749 section 4.1.2 / RFC 9700 section 4.5: the tokens issued on the
        # first exchange must be revoked.
        self.assertFalse(AccessToken.objects.filter(token=token_data["access_token"]).exists())
        refresh_token = RefreshToken.objects.get(token=token_data["refresh_token"])
        self.assertIsNotNone(refresh_token.revoked)

        grant = Grant.objects.get(code=authorization_code)
        self.assertIsNotNone(grant.authorization.revoked_at)

    def test_replayed_code_revokes_the_whole_refresh_chain(self):
        # The chain descending from a replayed code is what an attacker is after,
        # so revocation follows the authorization rather than only the tokens the
        # first exchange happened to mint.
        authorization_code = self.get_authorization_code()
        token_data = self.exchange_authorization_code(authorization_code).json()
        refreshed = self.refresh(token_data["refresh_token"]).json()

        self.assertEqual(self.exchange_authorization_code(authorization_code).status_code, 400)

        self.assertFalse(AccessToken.objects.filter(token=refreshed["access_token"]).exists())
        self.assertIsNotNone(RefreshToken.objects.get(token=refreshed["refresh_token"]).revoked)

    def test_unknown_code_is_rejected_without_touching_anything(self):
        authorization_code = self.get_authorization_code()
        token_data = self.exchange_authorization_code(authorization_code).json()

        response = self.exchange_authorization_code("a-code-that-was-never-issued")
        self.assertEqual(response.status_code, 400)

        self.assertTrue(AccessToken.objects.filter(token=token_data["access_token"]).exists())
        self.assertIsNone(Grant.objects.get(code=authorization_code).authorization.revoked_at)

    def test_refreshed_tokens_inherit_authorization(self):
        authorization_code = self.get_authorization_code()
        grant = Grant.objects.get(code=authorization_code)
        token_data = self.exchange_authorization_code(authorization_code).json()

        response = self.refresh(token_data["refresh_token"])
        self.assertEqual(response.status_code, 200)
        refreshed_data = response.json()

        access_token = AccessToken.objects.get(token=refreshed_data["access_token"])
        refresh_token = RefreshToken.objects.get(token=refreshed_data["refresh_token"], revoked__isnull=True)
        self.assertEqual(access_token.authorization, grant.authorization)
        self.assertEqual(refresh_token.authorization, grant.authorization)
        # Refreshing re-presents the original grant; it is not a new authorization.
        self.assertEqual(Authorization.objects.count(), 1)

    def test_authorization_revoke_revokes_token_chain(self):
        authorization_code = self.get_authorization_code()
        grant = Grant.objects.get(code=authorization_code)
        token_data = self.exchange_authorization_code(authorization_code).json()

        grant.authorization.revoke()

        self.assertFalse(AccessToken.objects.filter(token=token_data["access_token"]).exists())
        refresh_token = RefreshToken.objects.get(token=token_data["refresh_token"])
        self.assertIsNotNone(refresh_token.revoked)
        self.assertIsNotNone(grant.authorization.revoked_at)

        # Revoked tokens can no longer be refreshed.
        self.assertEqual(self.refresh(token_data["refresh_token"]).status_code, 400)

    def test_revoke_is_idempotent(self):
        authorization_code = self.get_authorization_code()
        authorization = Grant.objects.get(code=authorization_code).authorization
        self.exchange_authorization_code(authorization_code)

        authorization.revoke()
        revoked_at = Authorization.objects.get(pk=authorization.pk).revoked_at
        authorization.revoke()

        self.assertEqual(Authorization.objects.get(pk=authorization.pk).revoked_at, revoked_at)

    def test_allow_scopes(self):
        authorization = Authorization.objects.create(
            user=self.test_user,
            client_id=self.application.client_id,
            application=self.application,
            grant_type=Application.GRANT_AUTHORIZATION_CODE,
            scope="read write",
        )

        self.assertTrue(authorization.allow_scopes(None))
        self.assertTrue(authorization.allow_scopes([]))
        self.assertTrue(authorization.allow_scopes(["read"]))
        self.assertTrue(authorization.allow_scopes(["read", "write"]))
        self.assertFalse(authorization.allow_scopes(["read", "delete"]))


class TestClientPrincipalIsDurable(BaseAuthorizationTest):
    """
    The client identity on an Authorization is a value (``client_id``), not the
    Application foreign key: the registration backing a client is optional, and
    deleting it must not destroy the record of what was consented to.
    """

    def test_deleting_the_application_keeps_the_authorization(self):
        self.get_authorization_code()
        client_id = self.application.client_id

        self.application.delete()

        authorization = Authorization.objects.get()
        self.assertIsNone(authorization.application)
        self.assertEqual(authorization.client_id, client_id)

    def test_client_id_is_recorded_for_every_flow(self):
        self.get_authorization_code()
        self.assertEqual(Authorization.objects.get().client_id, self.application.client_id)


class TestOIDCLineage(BaseAuthorizationTest):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.application.algorithm = Application.RS256_ALGORITHM
        cls.application.save()

    def setUp(self):
        super().setUp()
        self.oauth2_settings.update(presets.OIDC_SETTINGS_RW)

    def test_id_token_inherits_authorization(self):
        authorization_code = self.get_authorization_code(scope="openid")
        grant = Grant.objects.get(code=authorization_code)

        response = self.exchange_authorization_code(authorization_code)
        self.assertEqual(response.status_code, 200)

        id_token = IDToken.objects.get()
        self.assertEqual(id_token.authorization, grant.authorization)

    def test_hybrid_flow_creates_one_authorization(self):
        self.application.authorization_grant_type = Application.GRANT_OPENID_HYBRID
        self.application.save()

        self.client.login(username="test_user", password="123456")
        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": self.application.client_id,
                "state": "random_state_string",
                "scope": "openid",
                "redirect_uri": "http://example.org",
                "response_type": "code token",
                "nonce": "random_nonce_string",
                "allow": True,
            },
        )
        self.assertEqual(response.status_code, 302)

        # oauthlib runs the code modifiers -- which mint the tokens -- before it
        # saves the authorization code, so the tokens are issued first. Both must
        # still land on one Authorization, labelled for the hybrid flow rather
        # than as implicit.
        authorization = Authorization.objects.get()
        self.assertEqual(authorization.grant_type, Application.GRANT_OPENID_HYBRID)
        for access_token in AccessToken.objects.all():
            self.assertEqual(access_token.authorization, authorization)
        for grant in Grant.objects.all():
            self.assertEqual(grant.authorization, authorization)


class TestPasswordGrantLineage(BaseAuthorizationTest):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.application.authorization_grant_type = Application.GRANT_PASSWORD
        cls.application.save()

    def request_password_token(self):
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        return self.client.post(
            reverse("oauth2_provider:token"),
            data={
                "grant_type": "password",
                "username": "test_user",
                "password": "123456",
            },
            **auth_headers,
        )

    def test_each_password_login_is_a_distinct_authorization(self):
        first = self.request_password_token()
        second = self.request_password_token()
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)

        authorizations = Authorization.objects.filter(
            client_id=self.application.client_id, grant_type=Application.GRANT_PASSWORD
        )
        self.assertEqual(authorizations.count(), 2)
        for authorization in authorizations:
            self.assertEqual(authorization.user, self.test_user)

        first_token = AccessToken.objects.get(token=first.json()["access_token"])
        second_token = AccessToken.objects.get(token=second.json()["access_token"])
        self.assertNotEqual(first_token.authorization, second_token.authorization)


class TestClientCredentialsLineage(BaseAuthorizationTest):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.application.authorization_grant_type = Application.GRANT_CLIENT_CREDENTIALS
        cls.application.save()

    def request_client_credentials_token(self, scope):
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        return self.client.post(
            reverse("oauth2_provider:token"),
            data={"grant_type": "client_credentials", "scope": scope},
            **auth_headers,
        )

    def test_single_authorization_per_client(self):
        first = self.request_client_credentials_token("read")
        second = self.request_client_credentials_token("read write")
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)

        authorizations = Authorization.objects.filter(client_id=self.application.client_id)
        self.assertEqual(authorizations.count(), 1)
        authorization = authorizations.get()
        self.assertIsNone(authorization.user)
        self.assertEqual(authorization.grant_type, Application.GRANT_CLIENT_CREDENTIALS)
        # The recorded scope is a superset of everything granted so far.
        self.assertEqual(set(authorization.scope.split()), {"read", "write"})

        first_token = AccessToken.objects.get(token=first.json()["access_token"])
        second_token = AccessToken.objects.get(token=second.json()["access_token"])
        self.assertEqual(first_token.authorization, authorization)
        self.assertEqual(second_token.authorization, authorization)

    def test_revoked_authorization_is_not_reused(self):
        self.assertEqual(self.request_client_credentials_token("read").status_code, 200)
        revoked = Authorization.objects.get()
        revoked.revoke()

        self.assertEqual(self.request_client_credentials_token("read").status_code, 200)

        self.assertEqual(Authorization.objects.filter(revoked_at__isnull=True).count(), 1)


class TestImplicitGrantLineage(BaseAuthorizationTest):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.application.authorization_grant_type = Application.GRANT_IMPLICIT
        cls.application.client_type = Application.CLIENT_PUBLIC
        cls.application.save()

    def test_implicit_tokens_are_linked_to_an_authorization(self):
        self.client.login(username="test_user", password="123456")
        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": self.application.client_id,
                "state": "random_state_string",
                "scope": "read write",
                "redirect_uri": "http://example.org",
                "response_type": "token",
                "allow": True,
            },
        )
        self.assertEqual(response.status_code, 302)
        fragment_dict = parse_qs(urlparse(response["Location"]).fragment)
        access_token = AccessToken.objects.get(token=fragment_dict["access_token"].pop())

        # The implicit flow mints no authorization code, which is why lineage
        # cannot hang off the code table.
        self.assertIsNotNone(access_token.authorization)
        self.assertEqual(access_token.authorization.grant_type, Application.GRANT_IMPLICIT)
        self.assertEqual(access_token.authorization.user, self.test_user)


class TestDeviceFlowLineage(BaseAuthorizationTest):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.application.authorization_grant_type = Application.GRANT_DEVICE_CODE
        cls.application.client_type = Application.CLIENT_PUBLIC
        cls.application.save()

    def approve_device(self, user_code="USERCODE"):
        self.client.login(username="test_user", password="123456")
        self.client.post(reverse("oauth2_provider:device"), data={"user_code": user_code})
        return self.client.post(
            reverse(
                "oauth2_provider:device-confirm",
                kwargs={"client_id": self.application.client_id, "user_code": user_code},
            ),
            data={"action": "accept"},
        )

    def test_device_approval_creates_authorization_and_tokens_inherit_it(self):
        device_grant = DeviceGrant.objects.create(
            client_id=self.application.client_id,
            device_code="device-code-abc",
            user_code="USERCODE",
            scope="read",
            expires=timezone.now() + datetime.timedelta(minutes=10),
            status=DeviceGrant.AUTHORIZATION_PENDING,
        )

        self.assertEqual(self.approve_device().status_code, 302)

        device_grant.refresh_from_db()
        self.assertEqual(device_grant.status, DeviceGrant.AUTHORIZED)
        self.assertIsNotNone(device_grant.authorization)
        self.assertEqual(device_grant.authorization.grant_type, Application.GRANT_DEVICE_CODE)
        self.assertEqual(device_grant.authorization.user, self.test_user)
        self.assertEqual(device_grant.authorization.client_id, self.application.client_id)
        self.assertEqual(device_grant.authorization.scope, "read")

        token_response = self.client.post(
            reverse("oauth2_provider:token"),
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": "device-code-abc",
                "client_id": self.application.client_id,
            },
        )
        self.assertEqual(token_response.status_code, 200)
        token_data = token_response.json()

        access_token = AccessToken.objects.get(token=token_data["access_token"])
        self.assertEqual(access_token.authorization, device_grant.authorization)


class TestUnknownGrantTypesGetLineage(BaseAuthorizationTest):
    """
    A grant type this validator does not know about -- a subclass's custom
    grant, or one added by a later RFC -- must still leave a lineage record
    rather than silently issuing tokens attributable to nothing.
    """

    def test_unrecognized_grant_type_is_recorded_by_its_protocol_name(self):
        validator = OAuth2Validator()
        request = RequestFactory().post("/")
        request.client = self.application
        request.user = self.test_user
        request.grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
        request.scopes = ["read"]

        authorization = validator._resolve_authorization(request)

        self.assertEqual(authorization.grant_type, "urn:ietf:params:oauth:grant-type:jwt-bearer")
        self.assertEqual(authorization.client_id, self.application.client_id)
        self.assertEqual(authorization.scope, "read")

    def test_a_request_without_a_client_resolves_to_nothing(self):
        validator = OAuth2Validator()
        request = RequestFactory().post("/")
        request.client = None
        request.grant_type = "client_credentials"

        self.assertIsNone(validator._resolve_authorization(request))


class TestClearExpiredAuthorizations(BaseAuthorizationTest):
    def make_authorization(self, **kwargs):
        return Authorization.objects.create(
            user=self.test_user,
            client_id=self.application.client_id,
            application=self.application,
            grant_type=Application.GRANT_AUTHORIZATION_CODE,
            scope="read",
            **kwargs,
        )

    def test_revoked_authorization_without_tokens_is_purged(self):
        authorization = self.make_authorization(revoked_at=timezone.now())

        clear_expired()

        self.assertFalse(Authorization.objects.filter(pk=authorization.pk).exists())

    def test_active_authorization_is_kept(self):
        authorization = self.make_authorization()

        clear_expired()

        self.assertTrue(Authorization.objects.filter(pk=authorization.pk).exists())

    def test_revoked_authorization_with_live_tokens_is_kept(self):
        authorization = self.make_authorization(revoked_at=timezone.now())
        AccessToken.objects.create(
            user=self.test_user,
            application=self.application,
            authorization=authorization,
            token="lineage-token",
            expires=timezone.now() + datetime.timedelta(hours=1),
            scope="read",
        )

        clear_expired()

        self.assertTrue(Authorization.objects.filter(pk=authorization.pk).exists())

    def test_exchanged_code_is_purged_once_expired(self):
        authorization_code = self.get_authorization_code()
        self.exchange_authorization_code(authorization_code)
        Grant.objects.filter(code=authorization_code).update(
            expires=timezone.now() - datetime.timedelta(seconds=1)
        )

        clear_expired()

        self.assertFalse(Grant.objects.filter(code=authorization_code).exists())


class TestAuthorizationDeleteSemantics(BaseAuthorizationTest):
    """
    Deletion is not a domain action: revoke() is. The ORM enforces the model
    semantics through the on_delete choices.
    """

    def test_delete_with_tokens_is_restricted(self):
        authorization_code = self.get_authorization_code()
        grant = Grant.objects.get(code=authorization_code)
        self.exchange_authorization_code(authorization_code)

        with self.assertRaises(RestrictedError):
            grant.authorization.delete()

    def test_delete_with_tokens_is_restricted_even_after_revoke(self):
        # Revoked refresh tokens are retained (for rotation-reuse detection), so
        # the authorization stays undeletable until cleanup removes them.
        authorization_code = self.get_authorization_code()
        grant = Grant.objects.get(code=authorization_code)
        self.exchange_authorization_code(authorization_code)

        grant.authorization.revoke()

        with self.assertRaises(RestrictedError):
            grant.authorization.delete()

    def test_user_delete_cascades_through_restrict(self):
        # RESTRICT permits deletion when the referencing tokens are deleted
        # through the same cascade -- here, deleting the user.
        authorization_code = self.get_authorization_code()
        token_data = self.exchange_authorization_code(authorization_code).json()

        self.test_user.delete()

        self.assertFalse(Authorization.objects.exists())
        self.assertFalse(AccessToken.objects.filter(token=token_data["access_token"]).exists())
        self.assertFalse(RefreshToken.objects.filter(token=token_data["refresh_token"]).exists())

    def test_delete_cascades_to_unexchanged_code(self):
        # A code is only a claim ticket on its authorization: deleting the
        # (token-less) authorization must delete the code with it.
        authorization_code = self.get_authorization_code()
        grant = Grant.objects.get(code=authorization_code)

        grant.authorization.delete()

        self.assertFalse(Grant.objects.filter(code=authorization_code).exists())

    def test_revoke_invalidates_unexchanged_code(self):
        authorization_code = self.get_authorization_code()
        grant = Grant.objects.get(code=authorization_code)

        grant.authorization.revoke()

        response = self.exchange_authorization_code(authorization_code)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Grant.objects.filter(code=authorization_code).exists())

    def test_revoke_denies_approved_but_unredeemed_device(self):
        self.application.authorization_grant_type = Application.GRANT_DEVICE_CODE
        self.application.client_type = Application.CLIENT_PUBLIC
        self.application.save()

        authorization = Authorization.objects.create(
            user=self.test_user,
            client_id=self.application.client_id,
            application=self.application,
            grant_type=Application.GRANT_DEVICE_CODE,
            scope="read",
        )
        device_grant = DeviceGrant.objects.create(
            client_id=self.application.client_id,
            device_code="device-code-abc",
            user_code="USERCODE",
            scope="read",
            expires=timezone.now() + datetime.timedelta(minutes=10),
            status=DeviceGrant.AUTHORIZED,
            user=self.test_user,
            authorization=authorization,
        )

        authorization.revoke()

        device_grant.refresh_from_db()
        self.assertEqual(device_grant.status, DeviceGrant.DENIED)

        token_response = self.client.post(
            reverse("oauth2_provider:token"),
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": "device-code-abc",
                "client_id": self.application.client_id,
            },
        )
        self.assertEqual(token_response.status_code, 400)
        self.assertEqual(token_response.json()["error"], "access_denied")


class TestAuthorizationAdmin(BaseAuthorizationTest):
    def get_model_admin(self):
        return AuthorizationAdmin(Authorization, AdminSite())

    def get_admin_request(self):
        request = RequestFactory().post("/")
        request.session = {}
        request._messages = FallbackStorage(request)
        return request

    def test_add_change_and_delete_are_not_available(self):
        model_admin = self.get_model_admin()
        request = self.get_admin_request()
        self.assertFalse(model_admin.has_add_permission(request))
        self.assertFalse(model_admin.has_change_permission(request))
        self.assertFalse(model_admin.has_delete_permission(request))

    def test_revoke_action_revokes_token_chains(self):
        authorization_code = self.get_authorization_code()
        token_data = self.exchange_authorization_code(authorization_code).json()

        model_admin = self.get_model_admin()
        model_admin.revoke_authorizations(self.get_admin_request(), Authorization.objects.all())

        authorization = Authorization.objects.get()
        self.assertIsNotNone(authorization.revoked_at)
        self.assertFalse(AccessToken.objects.filter(token=token_data["access_token"]).exists())
        refresh_token = RefreshToken.objects.get(token=token_data["refresh_token"])
        self.assertIsNotNone(refresh_token.revoked)
