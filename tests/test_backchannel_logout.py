import datetime
from unittest.mock import patch

import pytest
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django.urls import reverse

from oauth2_provider.exceptions import BackchannelLogoutRequestError
from oauth2_provider.models import (
    get_application_model,
    get_id_token_model,
)
from oauth2_provider.handlers import (
    on_user_logged_out_maybe_send_backchannel_logout,
    send_backchannel_logout_request,
)
from oauth2_provider.views import ApplicationRegistration

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()
IDToken = get_id_token_model()
User = get_user_model()


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_BACKCHANNEL_LOGOUT)
class TestBackchannelLogout(TestCase):
    def setUp(self):
        self.developer = User.objects.create_user(username="app_developer", password="123456")
        self.user = User.objects.create_user(username="app_user", password="654321")
        self.application = Application.objects.create(
            name="test_client_credentials_app",
            user=self.developer,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
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
        with patch("oauth2_provider.handlers.send_backchannel_logout_request") as backchannel_handler:
            self.client.login(username="app_user", password="654321")
            self.client.logout()
            backchannel_handler.assert_called_once()
            _, kwargs = backchannel_handler.call_args
            self.assertEqual(kwargs["id_token"], self.id_token)

    def test_logout_token_is_signed_for_user(self):
        with patch("requests.post") as mocked_post:
            self.client.login(username="app_user", password="654321")
            self.client.logout()
            mocked_post.assert_called_once()

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
        with patch("oauth2_provider.handlers.send_backchannel_logout_request") as mock_func:
            mock_func.side_effect = BackchannelLogoutRequestError("Bad Gateway")
            on_user_logged_out_maybe_send_backchannel_logout(sender=User, user=self.user)

    def test_no_logout_sent_when_id_token_has_offline_access(self):
        # Add offline_access scope to the ID token
        self.id_token.scope = "openid profile offline_access"
        self.id_token.save()

        with patch("oauth2_provider.handlers.send_backchannel_logout_request") as backchannel_handler:
            on_user_logged_out_maybe_send_backchannel_logout(sender=User, user=self.user)
            backchannel_handler.assert_not_called()

    def test_logout_sent_when_id_token_without_offline_access(self):
        with patch("oauth2_provider.handlers.send_backchannel_logout_request") as backchannel_handler:
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
        with patch("oauth2_provider.handlers.send_backchannel_logout_request") as backchannel_handler:
            on_user_logged_out_maybe_send_backchannel_logout(sender=User, user=self.user)
            backchannel_handler.assert_called_once()

    def test_logout_sent_for_multiple_applications(self):
        # Create another application with backchannel logout URI
        another_app = Application.objects.create(
            name="test_app_2",
            user=self.developer,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
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
        with patch("oauth2_provider.handlers.send_backchannel_logout_request") as backchannel_handler:
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
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            algorithm=Application.RS256_ALGORITHM,
            client_secret="another_secret",
            backchannel_logout_uri=None,
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

        with patch("oauth2_provider.handlers.send_backchannel_logout_request") as backchannel_handler:
            on_user_logged_out_maybe_send_backchannel_logout(sender=User, user=self.user)
            backchannel_handler.assert_not_called()
