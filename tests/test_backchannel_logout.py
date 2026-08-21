import datetime
import json
from unittest.mock import patch

import pytest
import requests
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone
from jwcrypto import jwt as jwcrypto_jwt

from oauth2_provider.authorization_server.oidc.handlers import (
    on_user_logged_out_maybe_send_backchannel_logout,
    send_backchannel_logout_request,
)
from oauth2_provider.authorization_server.views.application import ApplicationRegistration
from oauth2_provider.core.exceptions import BackchannelLogoutRequestError
from oauth2_provider.models import (
    get_application_model,
    get_id_token_model,
)

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase


HANDLERS_MODULE = "oauth2_provider.authorization_server.oidc.handlers"

Application = get_application_model()
IDToken = get_id_token_model()
User = get_user_model()


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_BACKCHANNEL_LOGOUT)
class TestBackchannelLogout(TestCase):
    def setUp(self):
        self.developer = User.objects.create_user(username="app_developer", password="123456")
        self.user = User.objects.create_user(username="app_user", password="654321")
        # An ID Token is only ever issued by a flow that authenticates a user, so the
        # fixture uses the authorization code grant rather than client credentials.
        self.application = Application.objects.create(
            name="test_authorization_code_app",
            user=self.developer,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="http://rp.example.com/callback",
            algorithm=Application.RS256_ALGORITHM,
            client_secret="1234567890asdfghjkqwertyuiopzxcvbnm",
            backchannel_logout_uri="http://rp.example.com/logout",
        )
        now = timezone.now()
        expiration_date = now + datetime.timedelta(minutes=180)
        self.id_token = IDToken.objects.create(
            application=self.application,
            user=self.user,
            expires=expiration_date,
            scope="openid profile",  # No offline_access scope
        )

    def test_on_logout_handler_is_called_for_user(self):
        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as backchannel_handler:
            self.client.login(username="app_user", password="654321")
            self.client.logout()
            backchannel_handler.assert_called_once()
            _, kwargs = backchannel_handler.call_args
            self.assertEqual(kwargs["id_token"], self.id_token)

    def _posted_logout_token(self, mocked_post):
        """Decode and verify the logout token handed to requests.post."""
        _, kwargs = mocked_post.call_args
        serialized = kwargs["data"]["logout_token"]
        verified = jwcrypto_jwt.JWT(jwt=serialized, key=self.application.jwk_key)
        return json.loads(verified.header), json.loads(verified.claims)

    def test_logout_token_is_signed_for_user(self):
        with patch("requests.post") as mocked_post:
            self.client.login(username="app_user", password="654321")
            self.client.logout()
            mocked_post.assert_called_once()

        header, claims = self._posted_logout_token(mocked_post)
        # Back-Channel Logout 1.0 section 2.4.
        self.assertEqual(header["typ"], "logout+jwt")
        self.assertEqual(header["alg"], Application.RS256_ALGORITHM)
        self.assertEqual(header["kid"], self.application.jwk_key.thumbprint())
        self.assertEqual(claims["events"], {"http://schemas.openid.net/event/backchannel-logout": {}})
        self.assertEqual(claims["iss"], self.oauth2_settings.OIDC_ISS_ENDPOINT)
        self.assertEqual(claims["aud"], self.application.client_id)
        self.assertEqual(claims["sub"], str(self.user.pk))
        self.assertLess(claims["iat"], claims["exp"])
        # Section 2.4 prohibits a nonce in a Logout Token.
        self.assertNotIn("nonce", claims)

    def test_logout_token_jti_is_unique_per_token(self):
        # The jti identifies the Logout Token, not the ID Token that prompted it: RPs may
        # drop a jti they have already seen (section 2.6 step 8).
        jtis = []
        for _ in range(2):
            with patch("requests.post") as mocked_post:
                send_backchannel_logout_request(self.id_token)
                jtis.append(self._posted_logout_token(mocked_post)[1]["jti"])

        self.assertNotEqual(jtis[0], jtis[1])
        self.assertNotIn(str(self.id_token.jti), jtis)

    def test_raises_exception_on_bad_application(self):
        self.application.algorithm = Application.NO_ALGORITHM
        self.application.save()
        with self.assertRaises(BackchannelLogoutRequestError):
            send_backchannel_logout_request(self.id_token)

    def test_new_application_form_has_backchannel_logout_field(self):
        factory = RequestFactory()
        url = reverse("oauth2_provider:register")
        request = factory.get(url)
        request.user = self.user
        view = ApplicationRegistration(request=request)
        form = view.get_form()
        self.assertTrue("backchannel_logout_uri" in form.fields.keys())

    def test_logout_sender_does_not_crash_on_backchannel_error(self):
        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as mock_func:
            mock_func.side_effect = BackchannelLogoutRequestError("Bad Gateway")
            on_user_logged_out_maybe_send_backchannel_logout(sender=User, user=self.user)

    def test_logout_sent_when_scope_merely_contains_offline_access(self):
        # Scope is a space-separated list of case-sensitive values, so a scope whose *name*
        # contains the substring is a different scope and must not suppress the logout.
        self.id_token.scope = "openid profile not_offline_access"
        self.id_token.save()

        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as backchannel_handler:
            on_user_logged_out_maybe_send_backchannel_logout(sender=User, user=self.user)
            backchannel_handler.assert_called_once()

    def test_logout_sent_when_scope_differs_only_in_case(self):
        self.id_token.scope = "openid profile OFFLINE_ACCESS"
        self.id_token.save()

        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as backchannel_handler:
            on_user_logged_out_maybe_send_backchannel_logout(sender=User, user=self.user)
            backchannel_handler.assert_called_once()

    def test_no_logout_sent_when_id_token_has_offline_access(self):
        # Add offline_access scope to the ID token
        self.id_token.scope = "openid profile offline_access"
        self.id_token.save()

        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as backchannel_handler:
            on_user_logged_out_maybe_send_backchannel_logout(sender=User, user=self.user)
            backchannel_handler.assert_not_called()

    def test_logout_sent_when_id_token_without_offline_access(self):
        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as backchannel_handler:
            on_user_logged_out_maybe_send_backchannel_logout(sender=User, user=self.user)
            backchannel_handler.assert_called_once()
            _, kwargs = backchannel_handler.call_args
            self.assertEqual(kwargs["id_token"], self.id_token)

    def test_only_one_logout_per_application_with_multiple_id_tokens(self):
        # Create another ID token for the same application
        IDToken.objects.create(
            application=self.application,
            user=self.user,
            expires=timezone.now() + datetime.timedelta(minutes=180),
            scope="openid profile",
        )

        # Should still be called only once despite having 2 ID tokens
        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as backchannel_handler:
            on_user_logged_out_maybe_send_backchannel_logout(sender=User, user=self.user)
            backchannel_handler.assert_called_once()

    def test_logout_sent_for_multiple_applications(self):
        # Create another application with backchannel logout URI
        another_app = Application.objects.create(
            name="test_app_2",
            user=self.developer,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="http://rp2.example.com/callback",
            algorithm=Application.RS256_ALGORITHM,
            client_secret="another_secret",
            backchannel_logout_uri="http://rp2.example.com/logout",
        )

        # Create ID token for the second application
        another_id_token = IDToken.objects.create(
            application=another_app,
            user=self.user,
            expires=timezone.now() + datetime.timedelta(minutes=180),
            scope="openid profile",
        )

        # Should be called twice - once for each application - and both ID tokens were used
        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as backchannel_handler:
            on_user_logged_out_maybe_send_backchannel_logout(sender=User, user=self.user)
            self.assertEqual(backchannel_handler.call_count, 2)

            call_args_list = backchannel_handler.call_args_list
            id_tokens_called = [call.kwargs["id_token"] for call in call_args_list]
            self.assertIn(self.id_token, id_tokens_called)
            self.assertIn(another_id_token, id_tokens_called)

    def test_no_logout_sent_when_application_has_no_backchannel_uri(self):
        # Create an application without backchannel logout URI
        app_without_logout = Application.objects.create(
            name="test_app_no_logout",
            user=self.developer,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="http://rp3.example.com/callback",
            algorithm=Application.RS256_ALGORITHM,
            client_secret="another_secret",
            backchannel_logout_uri="",
        )

        # Create ID token for this application
        IDToken.objects.create(
            application=app_without_logout,
            user=self.user,
            expires=timezone.now() + datetime.timedelta(minutes=180),
            scope="openid profile",
        )

        # Delete the main ID token so only the one without backchannel URI remains
        self.id_token.delete()

        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as backchannel_handler:
            on_user_logged_out_maybe_send_backchannel_logout(sender=User, user=self.user)
            backchannel_handler.assert_not_called()

    def test_logout_completes_when_handler_raises_unexpected_error(self):
        # Notifying an RP is best-effort: the handler is user-supplied, so nothing it
        # raises may escape into the logout view.
        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as mock_func:
            mock_func.side_effect = ValueError("something the handler did not anticipate")
            on_user_logged_out_maybe_send_backchannel_logout(sender=User, user=self.user)
            mock_func.assert_called_once()

    def test_signing_failure_does_not_escape_as_its_own_exception(self):
        with patch(f"{HANDLERS_MODULE}.jwt.JWT") as mocked_jwt:
            mocked_jwt.side_effect = ValueError("bad key")
            with self.assertRaises(BackchannelLogoutRequestError) as context:
                send_backchannel_logout_request(self.id_token)
            self.assertIn("bad key", str(context.exception))

    def test_no_logout_sent_for_anonymous_logout(self):
        # django.contrib.auth.logout() sends user=None when the request was not
        # authenticated; IDToken.user is nullable, so filtering on it would match the
        # user-less ID Tokens of unrelated applications.
        IDToken.objects.create(
            application=self.application,
            user=None,
            expires=timezone.now() + datetime.timedelta(minutes=180),
            scope="openid profile",
        )

        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as backchannel_handler:
            on_user_logged_out_maybe_send_backchannel_logout(sender=User, user=None)
            backchannel_handler.assert_not_called()

    def test_no_logout_sent_for_id_token_without_application(self):
        # IDToken.application is nullable, and there is no one to notify for such a row.
        self.id_token.delete()
        IDToken.objects.create(
            application=None,
            user=self.user,
            expires=timezone.now() + datetime.timedelta(minutes=180),
            scope="openid profile",
        )

        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as backchannel_handler:
            on_user_logged_out_maybe_send_backchannel_logout(sender=User, user=self.user)
            backchannel_handler.assert_not_called()

    def test_raises_exception_when_backchannel_logout_not_enabled(self):
        """Test that BackchannelLogoutRequestError is raised when backchannel logout is disabled."""
        with patch(f"{HANDLERS_MODULE}.oauth2_settings") as mock_settings:
            mock_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED = False
            with self.assertRaises(BackchannelLogoutRequestError) as context:
                send_backchannel_logout_request(self.id_token)
            self.assertIn("Backchannel logout not enabled", str(context.exception))

    def test_raises_exception_when_iss_endpoint_not_set(self):
        """A logout token carries the issuer as an absolute URL, so it cannot be minted."""
        self.oauth2_settings.OIDC_ISS_ENDPOINT = ""
        with self.assertRaises(BackchannelLogoutRequestError) as context:
            send_backchannel_logout_request(self.id_token)
        self.assertIn("OIDC_ISS_ENDPOINT is not set", str(context.exception))

    def test_raises_exception_when_backchannel_logout_uri_not_provided(self):
        """BackchannelLogoutRequestError is raised for an application with no logout URI."""
        self.application.backchannel_logout_uri = ""
        self.application.save()
        with self.assertRaises(BackchannelLogoutRequestError) as context:
            send_backchannel_logout_request(self.id_token)
        self.assertIn("URL for backchannel logout not provided", str(context.exception))

    def test_raises_exception_on_request_failure(self):
        """Test that BackchannelLogoutRequestError is raised when the HTTP request fails."""
        with patch("requests.post") as mocked_post:
            mocked_post.side_effect = requests.RequestException("Connection error")
            with self.assertRaises(BackchannelLogoutRequestError) as context:
                send_backchannel_logout_request(self.id_token)
            self.assertIn("Connection error", str(context.exception))
