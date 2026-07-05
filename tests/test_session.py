import datetime
import json
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from jwcrypto import jwt

from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_authorization_model,
    get_device_grant_model,
    get_grant_model,
    get_session_model,
)

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header


Application = get_application_model()
AccessToken = get_access_token_model()
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

    def authorize(self, application=None, scope="read write"):
        application = application or self.application
        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": application.client_id,
                "state": "random_state_string",
                "scope": scope,
                "redirect_uri": "http://example.org",
                "response_type": "code",
                "allow": True,
            },
        )
        self.assertEqual(response.status_code, 302)
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
        # Distinct authorizations (consent axis), same session (session axis).
        self.assertNotEqual(first_grant.authorization, second_grant.authorization)

    def test_new_login_gets_a_new_session(self):
        self.client.login(username="test_user", password="123456")
        self.authorize()

        self.client.logout()
        self.client.login(username="test_user", password="123456")
        self.authorize()

        self.assertEqual(Session.objects.count(), 2)
        sids = set(Session.objects.values_list("sid", flat=True))
        self.assertEqual(len(sids), 2)

    def test_terminate_marks_session_inactive(self):
        self.client.login(username="test_user", password="123456")
        self.authorize()

        session = Session.objects.get()
        session.terminate(reason=Session.TERMINATION_LOGOUT)

        session.refresh_from_db()
        self.assertIsNotNone(session.terminated_at)
        self.assertEqual(session.termination_reason, Session.TERMINATION_LOGOUT)
        self.assertFalse(session.is_active())

        # A terminated session is not reused: the next authorization mints a
        # fresh one.
        self.authorize()
        self.assertEqual(Session.objects.count(), 2)

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

        authorization = Authorization.objects.get()
        self.assertIsNone(authorization.session)

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
        self.assertEqual(device_grant.authorization.session, session)
        self.assertEqual(session.user, self.test_user)


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
class TestSessionIDTokenClaims(BaseSessionTest):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.application.algorithm = Application.HS256_ALGORITHM
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

        session = Session.objects.get()
        self.assertEqual(claims["sid"], str(session.sid))

    def test_auth_time_is_per_session_not_user_global(self):
        self.client.login(username="test_user", password="123456")
        authorization_code = self.authorize(scope="openid")
        session = Session.objects.get()

        # Simulate a later login on another device, which refreshes the
        # user-global last_login.
        self.test_user.last_login = timezone.now() + datetime.timedelta(hours=1)
        self.test_user.save(update_fields=["last_login"])

        claims = self.get_id_token_claims(authorization_code)

        self.assertEqual(claims["auth_time"], int(session.authenticated_at.timestamp()))
