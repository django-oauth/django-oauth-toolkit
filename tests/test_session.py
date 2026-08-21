import datetime
import json
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.admin.sites import AdminSite
from django.contrib.auth import get_user_model
from django.contrib.messages.storage.fallback import FallbackStorage
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone
from jwcrypto import jwt

from oauth2_provider.authorization_server.admin import SessionAdmin
from oauth2_provider.models import (
    SESSION_SID_KEY,
    clear_expired,
    get_application_model,
    get_authorization_model,
    get_device_grant_model,
    get_grant_model,
    get_or_create_oauth2_session,
    get_session_model,
)

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header


Application = get_application_model()
Authorization = get_authorization_model()
DeviceGrant = get_device_grant_model()
Grant = get_grant_model()
Session = get_session_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"


@pytest.mark.usefixtures("oauth2_settings")
class BaseSessionTest(TestCase):
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

    def authorize(self, application=None, scope="read write", response_type="code"):
        application = application or self.application
        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": application.client_id,
                "state": "random_state_string",
                "scope": scope,
                "redirect_uri": "http://example.org",
                "response_type": response_type,
                "allow": True,
            },
        )
        self.assertEqual(response.status_code, 302)
        if response_type != "code":
            return response
        query_dict = parse_qs(urlparse(response["Location"]).query)
        return query_dict["code"].pop()


@pytest.mark.oauth2_settings(presets.DEFAULT_SCOPES_RW)
class TestSessionMinting(BaseSessionTest):
    def test_session_minted_at_first_authorization(self):
        self.client.login(username="test_user", password="123456")
        authorization_code = self.authorize()

        session = Session.objects.get()
        self.assertEqual(session.user, self.test_user)
        self.assertTrue(session.is_active())
        self.assertIsNotNone(session.authenticated_at)

        grant = Grant.objects.get(code=authorization_code)
        self.assertEqual(grant.authorization.session, session)

    def test_no_session_is_minted_before_an_authorization(self):
        # Logging in is not, by itself, an OP session: nothing is recorded
        # until the user actually authorizes a client.
        self.client.login(username="test_user", password="123456")

        self.assertEqual(Session.objects.count(), 0)

    def test_sid_is_not_the_django_session_key(self):
        # The Django session key is the authentication cookie value; handing it
        # to a relying party as the sid claim would leak a credential.
        self.client.login(username="test_user", password="123456")
        self.authorize()

        session = Session.objects.get()
        self.assertNotEqual(str(session.sid), session.session_key)
        self.assertNotEqual(str(session.sid), self.client.session.session_key)

    def test_session_reused_across_authorizations_in_same_user_agent(self):
        other_application = Application.objects.create(
            name="Other Application",
            redirect_uris="http://example.org",
            user=self.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
        )

        self.client.login(username="test_user", password="123456")
        first_code = self.authorize()
        second_code = self.authorize(application=other_application)

        # One session spans every application authorized during it.
        self.assertEqual(Session.objects.count(), 1)
        session = Session.objects.get()
        first_grant = Grant.objects.get(code=first_code)
        second_grant = Grant.objects.get(code=second_code)
        self.assertEqual(first_grant.authorization.session, session)
        self.assertEqual(second_grant.authorization.session, session)
        # Distinct authorizations (consent axis), one session (session axis).
        self.assertNotEqual(first_grant.authorization, second_grant.authorization)

    def test_new_login_gets_a_new_session(self):
        self.client.login(username="test_user", password="123456")
        self.authorize()

        self.client.logout()
        self.client.login(username="test_user", password="123456")
        self.authorize()

        self.assertEqual(Session.objects.count(), 2)
        self.assertEqual(len(set(Session.objects.values_list("sid", flat=True))), 2)

    def test_implicit_flow_authorization_carries_the_session(self):
        self.application.authorization_grant_type = Application.GRANT_IMPLICIT
        self.application.client_type = Application.CLIENT_PUBLIC
        self.application.save()

        self.client.login(username="test_user", password="123456")
        self.authorize(response_type="token")

        session = Session.objects.get()
        self.assertEqual(Authorization.objects.get().session, session)

    def test_django_logout_terminates_the_session(self):
        self.client.login(username="test_user", password="123456")
        self.authorize()

        self.client.logout()

        session = Session.objects.get()
        self.assertIsNotNone(session.terminated_at)
        self.assertEqual(session.termination_reason, Session.TERMINATION_LOGOUT)
        self.assertFalse(session.is_active())

    def test_logout_does_not_overwrite_prior_termination_reason(self):
        # RP-initiated logout terminates with its own reason before calling
        # logout(); the receiver must not clobber it.
        self.client.login(username="test_user", password="123456")
        self.authorize()

        session = Session.objects.get()
        session.terminate(reason=Session.TERMINATION_RP_LOGOUT)

        self.client.logout()

        session.refresh_from_db()
        self.assertEqual(session.termination_reason, Session.TERMINATION_RP_LOGOUT)

    def test_logout_without_op_session_is_a_noop(self):
        # Logging out of a Django session that never reached the authorization
        # endpoint must neither error nor create anything.
        self.client.login(username="test_user", password="123456")
        self.client.logout()

        self.assertEqual(Session.objects.count(), 0)

    def test_terminated_session_is_not_reused(self):
        self.client.login(username="test_user", password="123456")
        self.authorize()

        session = Session.objects.get()
        session.terminate(reason=Session.TERMINATION_LOGOUT)

        self.authorize()

        self.assertEqual(Session.objects.count(), 2)

    def test_expired_session_is_not_reused(self):
        self.client.login(username="test_user", password="123456")
        self.authorize()

        Session.objects.update(expires=timezone.now() - datetime.timedelta(seconds=1))
        self.assertFalse(Session.objects.get().is_active())

        self.authorize()

        self.assertEqual(Session.objects.count(), 2)

    def test_anonymous_request_mints_nothing(self):
        request = RequestFactory().get("/")
        request.session = self.client.session
        request.user = UserModel.objects.none().first()  # None: no authenticated user

        self.assertIsNone(get_or_create_oauth2_session(request))
        self.assertEqual(Session.objects.count(), 0)

    def test_password_grant_has_no_session(self):
        self.application.authorization_grant_type = Application.GRANT_PASSWORD
        self.application.save()

        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        response = self.client.post(
            reverse("oauth2_provider:token"),
            data={
                "grant_type": "password",
                "username": "test_user",
                "password": "123456",
            },
            **auth_headers,
        )
        self.assertEqual(response.status_code, 200)

        self.assertIsNone(Authorization.objects.get().session)

    def test_client_credentials_has_no_session(self):
        self.application.authorization_grant_type = Application.GRANT_CLIENT_CREDENTIALS
        self.application.save()

        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        response = self.client.post(
            reverse("oauth2_provider:token"),
            data={"grant_type": "client_credentials", "scope": "read"},
            **auth_headers,
        )
        self.assertEqual(response.status_code, 200)

        self.assertIsNone(Authorization.objects.get().session)

    def test_device_authorization_is_bound_to_the_approving_browser_session(self):
        self.application.authorization_grant_type = Application.GRANT_DEVICE_CODE
        self.application.client_type = Application.CLIENT_PUBLIC
        self.application.save()

        device_grant = DeviceGrant.objects.create(
            client_id=self.application.client_id,
            device_code="device-code-abc",
            user_code="USERCODE",
            scope="read",
            expires=timezone.now() + datetime.timedelta(minutes=10),
            status=DeviceGrant.AUTHORIZATION_PENDING,
        )

        self.client.login(username="test_user", password="123456")
        self.client.post(reverse("oauth2_provider:device"), data={"user_code": "USERCODE"})
        response = self.client.post(
            reverse(
                "oauth2_provider:device-confirm",
                kwargs={"client_id": self.application.client_id, "user_code": "USERCODE"},
            ),
            data={"action": "accept"},
        )
        self.assertEqual(response.status_code, 302)

        device_grant.refresh_from_db()
        session = Session.objects.get()
        # The session is the approving browser's, not the device's -- the
        # device is not a user agent the user is authenticated in.
        self.assertEqual(device_grant.authorization.session, session)
        self.assertEqual(session.user, self.test_user)


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestSessionIDTokenClaims(BaseSessionTest):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.application.algorithm = Application.HS256_ALGORITHM
        # HS256 signs with the plaintext client secret as the HMAC key, so this
        # application cannot hash it (see AbstractApplication.jwk_key).
        cls.application.hash_client_secret = False
        cls.application.client_secret = CLEARTEXT_SECRET
        cls.application.save()

    def setUp(self):
        super().setUp()
        self.oauth2_settings.OIDC_RSA_PRIVATE_KEY = None

    def get_id_token_claims(self, authorization_code):
        response = self.client.post(
            reverse("oauth2_provider:token"),
            data={
                "grant_type": "authorization_code",
                "code": authorization_code,
                "redirect_uri": "http://example.org",
                "client_id": self.application.client_id,
                "client_secret": CLEARTEXT_SECRET,
                "scope": "openid",
            },
        )
        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertIn("id_token", content)
        jwt_token = jwt.JWT(key=self.application.jwk_key, jwt=content["id_token"])
        return json.loads(jwt_token.claims)

    def test_id_token_carries_sid_claim(self):
        self.client.login(username="test_user", password="123456")
        authorization_code = self.authorize(scope="openid")

        claims = self.get_id_token_claims(authorization_code)

        self.assertEqual(claims["sid"], str(Session.objects.get().sid))

    def test_auth_time_is_per_session_not_user_global(self):
        self.client.login(username="test_user", password="123456")
        authorization_code = self.authorize(scope="openid")
        session = Session.objects.get()

        # A later login on another device refreshes the user-global last_login.
        # The freshness asserted to this relying party must not move with it.
        self.test_user.last_login = timezone.now() + datetime.timedelta(hours=1)
        self.test_user.save(update_fields=["last_login"])

        claims = self.get_id_token_claims(authorization_code)

        self.assertEqual(claims["auth_time"], int(session.authenticated_at.timestamp()))

    def test_sid_is_absent_when_there_is_no_session(self):
        # A flow that never touched a user agent issues no sid. Back-channel
        # logout falls back to sub-only for those.
        self.client.login(username="test_user", password="123456")
        authorization_code = self.authorize(scope="openid")
        Authorization.objects.update(session=None)
        Session.objects.all().delete()

        claims = self.get_id_token_claims(authorization_code)

        self.assertNotIn("sid", claims)


@pytest.mark.oauth2_settings(presets.DEFAULT_SCOPES_RW)
class TestSessionAdmin(BaseSessionTest):
    def get_model_admin(self):
        return SessionAdmin(Session, AdminSite())

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

    def test_session_key_is_never_rendered(self):
        self.client.login(username="test_user", password="123456")
        self.authorize()

        model_admin = self.get_model_admin()
        session = Session.objects.get()

        self.assertIn("session_key", model_admin.get_exclude(self.get_admin_request(), session))
        self.assertNotIn("session_key", model_admin.list_display)
        self.assertNotIn("session_key", model_admin.search_fields)

    def test_terminate_action(self):
        self.client.login(username="test_user", password="123456")
        self.authorize()

        model_admin = self.get_model_admin()
        model_admin.terminate_sessions(self.get_admin_request(), Session.objects.all())

        session = Session.objects.get()
        self.assertIsNotNone(session.terminated_at)
        self.assertEqual(session.termination_reason, Session.TERMINATION_ADMIN)

    def test_terminating_a_session_does_not_revoke_consent(self):
        # The two axes are distinct: ending a user agent's authentication is
        # not the same operation as withdrawing consent.
        self.client.login(username="test_user", password="123456")
        self.authorize()

        self.get_model_admin().terminate_sessions(self.get_admin_request(), Session.objects.all())

        self.assertTrue(Authorization.objects.get().is_active())


@pytest.mark.oauth2_settings(presets.DEFAULT_SCOPES_RW)
class TestClearExpiredSessions(BaseSessionTest):
    def create_session(self, **kwargs):
        defaults = {
            "user": self.test_user,
            "authenticated_at": timezone.now(),
            "expires": timezone.now() + datetime.timedelta(hours=1),
        }
        defaults.update(kwargs)
        return Session.objects.create(**defaults)

    def test_terminated_session_without_authorizations_is_purged(self):
        session = self.create_session(terminated_at=timezone.now())

        clear_expired()

        self.assertFalse(Session.objects.filter(pk=session.pk).exists())

    def test_expired_session_without_authorizations_is_purged(self):
        session = self.create_session(expires=timezone.now() - datetime.timedelta(hours=1))

        clear_expired()

        self.assertFalse(Session.objects.filter(pk=session.pk).exists())

    def test_active_session_is_kept(self):
        session = self.create_session()

        clear_expired()

        self.assertTrue(Session.objects.filter(pk=session.pk).exists())

    def test_ended_session_with_authorizations_is_kept(self):
        # The sid linkage survives as long as the authorizations granted during
        # the session do -- offline_access chains outlive the session by design.
        session = self.create_session(terminated_at=timezone.now())
        Authorization.objects.create(
            user=self.test_user,
            client_id=self.application.client_id,
            application=self.application,
            session=session,
            grant_type=Application.GRANT_AUTHORIZATION_CODE,
            scope="read",
        )

        clear_expired()

        self.assertTrue(Session.objects.filter(pk=session.pk).exists())


@pytest.mark.oauth2_settings(presets.DEFAULT_SCOPES_RW)
class TestSessionStateInDjangoSession(BaseSessionTest):
    def test_sid_is_stored_in_the_django_session(self):
        self.client.login(username="test_user", password="123456")
        self.authorize()

        self.assertEqual(self.client.session[SESSION_SID_KEY], str(Session.objects.get().sid))
