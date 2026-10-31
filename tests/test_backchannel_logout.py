import datetime
import json
import os
import subprocess
import sys
import threading
from contextlib import ExitStack
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.core.exceptions import ValidationError
from django.db import DatabaseError, connections, router, transaction
from django.test import Client, RequestFactory
from django.urls import reverse
from django.utils import timezone
from jwcrypto import jwt as jwcrypto_jwt

from oauth2_provider.authorization_server.oidc.handlers import (
    build_logout_token,
    collect_backchannel_logout_targets,
    on_user_logged_out_maybe_send_backchannel_logout,
    send_backchannel_logout_request,
    send_backchannel_logout_requests,
)
from oauth2_provider.authorization_server.views.application import ApplicationRegistration
from oauth2_provider.core import safe_fetch
from oauth2_provider.core.exceptions import BackchannelLogoutRequestError
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_id_token_model,
)
from oauth2_provider.oauth2_validators import OAuth2Validator

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .common_testing import OAuth2ProviderTransactionTestCase as TransactionTestCase
from .conftest import generate_access_token


HANDLERS_MODULE = "oauth2_provider.authorization_server.oidc.handlers"
POST_FORM = "oauth2_provider.core.safe_fetch.post_form"
ISSUER = presets.OIDC_SETTINGS_BACKCHANNEL_LOGOUT["OIDC_ISS_ENDPOINT"]

AccessToken = get_access_token_model()
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
            backchannel_logout_uri="https://rp.example.com/logout",
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
        """Decode and verify the logout token handed to the transport."""
        args, _ = mocked_post.call_args
        serialized = args[1]["logout_token"]
        verified = jwcrypto_jwt.JWT(jwt=serialized, key=self.application.jwk_key)
        return json.loads(verified.header), json.loads(verified.claims)

    def test_logout_token_is_signed_for_user(self):
        with patch(POST_FORM, return_value=(204, {})) as mocked_post:
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
            with patch(POST_FORM, return_value=(204, {})) as mocked_post:
                send_backchannel_logout_request(self.id_token)
                jtis.append(self._posted_logout_token(mocked_post)[1]["jti"])

        self.assertNotEqual(jtis[0], jtis[1])
        self.assertNotIn(str(self.id_token.jti), jtis)

    def test_raises_exception_on_bad_application(self):
        self.application.algorithm = Application.NO_ALGORITHM
        self.application.save()
        with self.assertRaises(BackchannelLogoutRequestError):
            send_backchannel_logout_request(self.id_token)
        # And from build_logout_token itself, which a custom handler calls directly.
        with self.assertRaisesMessage(BackchannelLogoutRequestError, "must provide signing algorithm"):
            build_logout_token(self.id_token)

    def test_hs256_application_gets_an_hs256_logout_token(self):
        # Signed like its ID Tokens: with the client secret, and no kid, since there is no
        # published key to point at.
        self.application.algorithm = Application.HS256_ALGORITHM
        self.application.client_secret = "hs256-client-secret-long-enough-for-hmac-1234567890"
        self.application.hash_client_secret = False
        self.application.save()
        token = jwcrypto_jwt.JWT(jwt=build_logout_token(self.id_token), key=self.application.jwk_key)
        header = json.loads(token.header)
        self.assertEqual(header["alg"], "HS256")
        self.assertNotIn("kid", header)

    def test_new_application_form_has_backchannel_logout_field(self):
        factory = RequestFactory()
        url = reverse("oauth2_provider:register")
        request = factory.get(url)
        request.user = self.user
        view = ApplicationRegistration(request=request)
        form = view.get_form()
        self.assertTrue("backchannel_logout_uri" in form.fields.keys())

    def test_new_application_form_has_no_backchannel_logout_field_while_disabled(self):
        # Offered under the same condition as clean() validates it: otherwise the form would
        # store a URI nothing had checked.
        request = RequestFactory().get(reverse("oauth2_provider:register"))
        request.user = self.user
        for setting in ("OIDC_BACKCHANNEL_LOGOUT_ENABLED", "OIDC_ENABLED"):
            with self.subTest(setting=setting), patch.object(self.oauth2_settings, setting, False):
                form = ApplicationRegistration(request=request).get_form()
                self.assertNotIn("backchannel_logout_uri", form.fields)

    def test_logout_uri_field_completes_a_bare_host_with_https(self):
        # A URL the server will contact is not completed to plaintext -- the default
        # Django 6.0 adopts, which until then warns on every URLField that does not opt in.
        request = RequestFactory().get(reverse("oauth2_provider:register"))
        request.user = self.user
        field = ApplicationRegistration(request=request).get_form().fields["backchannel_logout_uri"]
        self.assertEqual(field.clean("rp.example.com/logout"), "https://rp.example.com/logout")

    def test_logout_sender_does_not_crash_on_backchannel_error(self):
        # The receiver runs before the session is flushed, so an exception escaping it
        # would leave the user logged in.
        self.client.login(username="app_user", password="654321")
        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as mock_func:
            mock_func.side_effect = BackchannelLogoutRequestError("Bad Gateway")
            with self.assertLogs(HANDLERS_MODULE, "WARNING") as logs:
                self.client.logout()
        mock_func.assert_called_once()
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertIn("Bad Gateway", logs.output[0])
        # Which relying party failed, so an operator can find it.
        self.assertIn(self.application.client_id, logs.output[0])
        self.assertIn(self.application.backchannel_logout_uri, logs.output[0])

    def test_logout_completes_when_collecting_targets_fails(self):
        # Collecting runs outside the dispatch's own error handling, before the flush.
        self.client.login(username="app_user", password="654321")
        with patch(
            f"{HANDLERS_MODULE}.collect_backchannel_logout_targets", side_effect=DatabaseError("down")
        ):
            with self.assertLogs(HANDLERS_MODULE, "WARNING") as logs:
                self.client.logout()
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertIn("down", logs.output[0])

    def test_logout_with_nothing_to_notify_logs_nothing(self):
        self.application.backchannel_logout_uri = ""
        self.application.save()
        self.client.login(username="app_user", password="654321")
        with self.assertNoLogs(HANDLERS_MODULE, "WARNING"):
            self.client.logout()

    def test_a_malformed_logout_uri_does_not_stop_the_others_being_notified(self):
        # Forms and registration refuse such a URI, but one can still be stored through the
        # ORM. Logging its failure must not raise, or the relying parties after it in the
        # sequential loop would silently go un-notified.
        second = self._add_second_relying_party()
        Application.objects.filter(pk=self.application.pk).update(
            backchannel_logout_uri="https://[::1/logout"
        )
        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_MAX_WORKERS = 1
        targets = collect_backchannel_logout_targets(self.user)
        self.assertEqual([t.application_id for t in targets], [self.application.pk, second.application_id])

        real_post_form = safe_fetch.post_form

        def deliver(uri, *args, **kwargs):
            # The malformed URI goes to the real transport, which refuses it; the healthy
            # relying party is answered here.
            if "[" in uri:
                return real_post_form(uri, *args, **kwargs)
            return 204, {}

        with patch(POST_FORM, side_effect=deliver) as mocked_post:
            with self.assertLogs(HANDLERS_MODULE, "WARNING") as logs:
                send_backchannel_logout_requests(targets)

        self.assertEqual(
            [c.args[0] for c in mocked_post.call_args_list],
            ["https://[::1/logout", second.application.backchannel_logout_uri],
        )
        self.assertEqual(len(logs.output), 1)
        self.assertIn("https://[::1/logout", logs.output[0])
        self.assertIn(self.application.client_id, logs.output[0])
        self.assertIn("URL is invalid", logs.output[0])

    def test_dispatch_sends_nothing_once_the_feature_is_off(self):
        # RPInitiatedLogoutView collects its targets first and sends once the logout commits;
        # nothing is sent if back-channel logout has been turned off in between.
        targets = collect_backchannel_logout_targets(self.user)
        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED = False
        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as handler:
            send_backchannel_logout_requests(targets)
        handler.assert_not_called()

    def test_dispatch_survives_a_bad_worker_count(self):
        # RPInitiatedLogoutView dispatches after the logout has happened, where anything
        # raised would turn it into a server error.
        targets = [self.id_token, self._add_second_relying_party()]
        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_MAX_WORKERS = None
        with self.assertLogs(HANDLERS_MODULE, "WARNING") as logs:
            send_backchannel_logout_requests(targets)
        self.assertIn("dispatch failed", logs.output[0])

    def test_dispatch_survives_an_unimportable_handler(self):
        # update() reloads the settings, so the import string is resolved -- and fails --
        # on access, as it would in a deployment with a typo in it.
        self.oauth2_settings.update(
            {
                **presets.OIDC_SETTINGS_BACKCHANNEL_LOGOUT,
                "OIDC_BACKCHANNEL_LOGOUT_HANDLER": "does.not.exist.handler",
            }
        )
        with self.assertLogs(HANDLERS_MODULE, "WARNING") as logs:
            send_backchannel_logout_requests([self.id_token])
        self.assertIn("does.not.exist.handler", logs.output[0])

    def test_expired_id_token_is_not_a_logout_target(self):
        # An expired ID Token no longer represents a session the RP is relying on.
        self.id_token.expires = timezone.now() - datetime.timedelta(seconds=1)
        self.id_token.save()
        self.assertEqual(collect_backchannel_logout_targets(self.user), [])

    def test_logout_target_is_the_most_recently_issued_id_token(self):
        # One logout token per relying party, for its latest live ID Token.
        newer = IDToken.objects.create(
            application=self.application,
            user=self.user,
            expires=self.id_token.expires + datetime.timedelta(minutes=5),
            scope="openid",
        )
        self.assertEqual(collect_backchannel_logout_targets(self.user), [newer])

    def test_logout_sent_when_id_token_has_offline_access(self):
        # Back-Channel Logout 1.0 section 2.7 addresses offline_access to the RP receiving
        # the token -- it keeps its refresh token and clears the session -- so the OP must
        # not withhold the request and decide on the RP's behalf.
        self.id_token.scope = "openid profile offline_access"
        self.id_token.save()

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
            backchannel_logout_uri="https://rp2.example.com/logout",
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

    def test_logout_does_not_notify_relying_parties_of_other_users(self):
        # Section 2.3: an RP is notified of the sessions the logging-out user had with it.
        # Another user's live ID Token at a back-channel RP is no reason to notify that RP.
        other_rp_token = self._add_second_relying_party()
        other_rp_token.user = User.objects.create_user(username="other_user", password="x")
        other_rp_token.save()

        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as handler:
            self.client.login(username="app_user", password="654321")
            self.client.logout()

        self.assertEqual([c.kwargs["id_token"] for c in handler.call_args_list], [self.id_token])

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

    def test_application_less_id_token_does_not_escape_as_its_own_exception(self):
        # IDToken.application is nullable. collect_backchannel_logout_targets() filters
        # those out, but the function is public and documented as raising exactly one
        # exception type, so a direct caller must get that type too.
        orphan = IDToken.objects.create(
            application=None,
            user=self.user,
            expires=timezone.now() + datetime.timedelta(minutes=180),
            scope="openid profile",
        )
        with self.assertRaises(BackchannelLogoutRequestError):
            send_backchannel_logout_request(orphan)

    def test_signing_failure_does_not_escape_as_its_own_exception(self):
        with patch(f"{HANDLERS_MODULE}.jwt.JWT") as mocked_jwt:
            mocked_jwt.side_effect = ValueError("bad key")
            with self.assertRaises(BackchannelLogoutRequestError) as context:
                send_backchannel_logout_request(self.id_token)
            self.assertIn("bad key", str(context.exception))

    def _add_second_relying_party(self):
        another_app = Application.objects.create(
            name="rp_two",
            user=self.developer,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="https://rp2.example.com/callback",
            algorithm=Application.RS256_ALGORITHM,
            client_secret="another_secret_value_for_rp_two_application",
            backchannel_logout_uri="https://rp2.example.com/logout",
        )
        return IDToken.objects.create(
            application=another_app,
            user=self.user,
            expires=timezone.now() + datetime.timedelta(minutes=180),
            scope="openid profile",
        )

    def _commit_callbacks(self):
        # RPInitiatedLogoutView sends once the tokens' database commits, which a TestCase
        # never does; run what it deferred, on the database it deferred it on.
        return self.captureOnCommitCallbacks(using=router.db_for_write(IDToken), execute=True)

    def _enable_rp_initiated_logout(self):
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED = True
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT = False
        AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token="access-token-for-logout",
            id_token=self.id_token,
            scope="openid profile",
            expires=timezone.now() + datetime.timedelta(minutes=180),
        )
        self.client.login(username="app_user", password="654321")

    def test_rp_initiated_logout_notifies_relying_parties(self):
        # Regression: do_logout() deletes the ID Tokens the receiver reads, so the targets
        # have to be collected before deletion and dispatched after the session is flushed.
        self._enable_rp_initiated_logout()

        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as handler:
            with self._commit_callbacks():
                response = self.client.post(
                    reverse("oauth2_provider:rp-initiated-logout"), data={"allow": True}
                )

        self.assertEqual(response.status_code, 302)
        handler.assert_called_once()
        self.assertEqual(IDToken.objects.count(), 0)

    def test_rp_initiated_logout_notifies_exactly_once_when_tokens_are_kept(self):
        # With the rows left in place the user_logged_out receiver would fire as well as
        # the view, sending two logout tokens with different jti values per relying party.
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_DELETE_TOKENS = False
        self._enable_rp_initiated_logout()

        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as handler:
            with self._commit_callbacks():
                response = self.client.post(
                    reverse("oauth2_provider:rp-initiated-logout"), data={"allow": True}
                )

        self.assertEqual(response.status_code, 302)
        handler.assert_called_once()
        self.assertEqual(IDToken.objects.count(), 1)

    def test_rp_initiated_logout_completes_when_every_notification_fails(self):
        # A relying party must never be able to hold up, or prevent, the logout itself.
        self._enable_rp_initiated_logout()

        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as handler:
            handler.side_effect = ValueError("the relying party exploded")
            with self._commit_callbacks():
                response = self.client.post(
                    reverse("oauth2_provider:rp-initiated-logout"), data={"allow": True}
                )

        self.assertEqual(response.status_code, 302)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertEqual(IDToken.objects.count(), 0)

    def _id_token_hint(self, id_token):
        """A signed ID Token for *id_token*'s row, as a relying party would send it back."""
        now = int(timezone.now().timestamp())
        token = jwcrypto_jwt.JWT(
            header=json.dumps({"alg": "RS256", "kid": self.application.jwk_key.thumbprint()}),
            claims=json.dumps(
                {
                    "iss": self.oauth2_settings.OIDC_ISS_ENDPOINT,
                    "aud": self.application.client_id,
                    "sub": str(id_token.user.pk),
                    "jti": str(id_token.jti),
                    "iat": now,
                    "exp": now + 600,
                }
            ),
        )
        token.make_signed_token(self.application.jwk_key)
        return token.serialize()

    def test_rp_initiated_logout_defers_nothing_while_disabled(self):
        # A deployment that never turned back-channel logout on leaves no commit callback
        # behind on every logout.
        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED = False
        self._enable_rp_initiated_logout()

        with self._commit_callbacks() as callbacks:
            response = self.client.post(reverse("oauth2_provider:rp-initiated-logout"), data={"allow": True})

        self.assertEqual(response.status_code, 302)
        self.assertEqual(callbacks, [])

    def test_rp_initiated_logout_without_a_session_notifies_nobody(self):
        # No OP session ends, so no relying party is owed a notification. Otherwise anyone
        # holding the user's ID Token -- accepted even once expired -- could log the user
        # out of every relying party without being asked.
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED = True
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT = False
        self._add_second_relying_party()

        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as handler:
            with self._commit_callbacks():
                response = self.client.get(
                    reverse("oauth2_provider:rp-initiated-logout"),
                    {"id_token_hint": self._id_token_hint(self.id_token)},
                )

        self.assertEqual(response.status_code, 302)
        handler.assert_not_called()

    def test_rp_initiated_logout_notifies_the_user_whose_session_ends(self):
        # The hint names app_user, but the OP session that ends is other_user's, so it is
        # other_user's relying parties that have to hear about it.
        other_user = User.objects.create_user(username="other_user", password="other_password")
        other_users_id_token = IDToken.objects.create(
            application=self.application,
            user=other_user,
            expires=timezone.now() + datetime.timedelta(minutes=180),
            scope="openid",
        )
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED = True
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT = False
        self.client.login(username="other_user", password="other_password")

        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as handler:
            with self._commit_callbacks():
                response = self.client.post(
                    reverse("oauth2_provider:rp-initiated-logout"),
                    data={"id_token_hint": self._id_token_hint(self.id_token), "allow": True},
                )

        self.assertEqual(response.status_code, 302)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertEqual([c.kwargs["id_token"] for c in handler.call_args_list], [other_users_id_token])

    def test_rp_initiated_logout_notifies_the_initiating_rp_whose_id_token_expired(self):
        # RP-Initiated Logout 1.0 section 2: "The RP initiating the logout is to be included
        # in these notifications". Its session is known for certain, so an expired ID Token
        # row does not exclude it; another RP still needs a live one.
        self.id_token.expires = timezone.now() - datetime.timedelta(minutes=5)
        self.id_token.save()
        other_rp_token = self._add_second_relying_party()
        other_rp_token.expires = timezone.now() - datetime.timedelta(minutes=5)
        other_rp_token.save()
        # Neither an earlier ID Token of the same user nor another user's token at the
        # initiating RP is the one to notify it from.
        IDToken.objects.create(
            application=self.application,
            user=self.user,
            expires=timezone.now() - datetime.timedelta(hours=2),
            scope="openid profile",
        )
        IDToken.objects.create(
            application=self.application,
            user=User.objects.create_user(username="someone_else", password="x"),
            expires=timezone.now() + datetime.timedelta(hours=1),
            scope="openid profile",
        )
        # The one that expired last is, created after the others so that only the ordering
        # by expiry -- not by primary key -- picks it.
        latest = IDToken.objects.create(
            application=self.application,
            user=self.user,
            expires=timezone.now() - datetime.timedelta(minutes=1),
            scope="openid profile",
        )
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED = True
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT = False
        self.client.login(username="app_user", password="654321")

        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as handler:
            with self._commit_callbacks():
                response = self.client.get(
                    reverse("oauth2_provider:rp-initiated-logout"),
                    {"id_token_hint": self._id_token_hint(self.id_token)},
                )

        self.assertEqual(response.status_code, 302)
        self.assertEqual([c.kwargs["id_token"] for c in handler.call_args_list], [latest])

    def test_initiating_rp_is_notified_only_when_it_can_be(self):
        # Without a logout URI there is nowhere to send to; without an ID Token of the
        # user's there is nothing to mint a logout token from.
        self.id_token.expires = timezone.now() - datetime.timedelta(minutes=5)
        self.id_token.save()
        no_token_rp = self._add_second_relying_party().application
        IDToken.objects.filter(application=no_token_rp).delete()
        self.application.backchannel_logout_uri = ""
        self.application.save()
        for initiating_application in (self.application, no_token_rp):
            with self.subTest(application=initiating_application.name):
                targets = collect_backchannel_logout_targets(
                    self.user, initiating_application=initiating_application
                )
                self.assertEqual(targets, [])

    def test_disabled_backchannel_logout_costs_no_query(self):
        # RPInitiatedLogoutView collects targets on every logout, before it knows whether
        # anything will be dispatched. A deployment that never turned back-channel logout
        # on must not pay for an ID Token query on each RP-initiated logout.
        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED = False

        with self.assertNumQueries(0):
            self.assertEqual(collect_backchannel_logout_targets(self.user), [])

    def test_logout_tokens_are_dispatched_in_parallel(self):
        # Back-Channel Logout 1.0 section 2.3 encourages contacting RPs in parallel. The
        # barrier only clears if both dispatches are in flight at once; sequential
        # dispatch would block on it until it times out.
        self._add_second_relying_party()
        barrier = threading.Barrier(2, timeout=5)
        cleared = []

        def rendezvous(id_token):
            barrier.wait()
            cleared.append(id_token)

        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request", side_effect=rendezvous):
            on_user_logged_out_maybe_send_backchannel_logout(sender=User, user=self.user)
        self.assertEqual(len(cleared), 2)

    def test_worker_threads_release_their_database_connection(self):
        # A pool worker never receives request_finished, so nothing else closes a
        # connection a handler opened on it. Leaking one per worker per logout would
        # exhaust a connection-limited server under logout load.
        self._add_second_relying_party()

        def queries_the_database(id_token):
            # What a custom handler plausibly does: look something up before sending.
            IDToken.objects.filter(pk=id_token.pk).exists()

        with patch.object(connections, "close_all") as close_all:
            with patch(
                f"{HANDLERS_MODULE}.send_backchannel_logout_request",
                side_effect=queries_the_database,
            ):
                on_user_logged_out_maybe_send_backchannel_logout(sender=User, user=self.user)

        self.assertEqual(close_all.call_count, 2)

    def test_connections_are_left_alone_when_dispatching_on_the_request_thread(self):
        # With one worker the dispatch runs inline, where the connection belongs to the
        # request and closing it would be both wrong and someone else's job.
        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_MAX_WORKERS = 1
        self._add_second_relying_party()

        with patch.object(connections, "close_all") as close_all:
            with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as handler:
                on_user_logged_out_maybe_send_backchannel_logout(sender=User, user=self.user)

        self.assertEqual(handler.call_count, 2)
        close_all.assert_not_called()

    def test_max_workers_of_one_dispatches_sequentially(self):
        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_MAX_WORKERS = 1
        threads = set()

        with patch(
            f"{HANDLERS_MODULE}.send_backchannel_logout_request",
            side_effect=lambda id_token: threads.add(threading.current_thread().name),
        ):
            on_user_logged_out_maybe_send_backchannel_logout(sender=User, user=self.user)
        self.assertEqual(threads, {threading.current_thread().name})

    def test_logout_token_expiry_follows_its_setting(self):
        with patch(POST_FORM, return_value=(204, {})) as mocked_post:
            send_backchannel_logout_request(self.id_token)
        claims = self._posted_logout_token(mocked_post)[1]
        self.assertEqual(claims["exp"] - claims["iat"], 120)

        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_TOKEN_EXPIRE_SECONDS = 30
        with patch(POST_FORM, return_value=(204, {})) as mocked_post:
            send_backchannel_logout_request(self.id_token)
        claims = self._posted_logout_token(mocked_post)[1]
        self.assertEqual(claims["exp"] - claims["iat"], 30)

    def test_redirected_logout_uri_is_a_delivery_failure(self):
        # A 301/302/303 would turn the POST into a bodyless GET, which most endpoints
        # answer 200 -- so following it would record a logout that never happened.
        with patch(POST_FORM, return_value=(302, {"Location": "https://rp.example.com/logout/"})):
            with self.assertRaises(BackchannelLogoutRequestError) as context:
                send_backchannel_logout_request(self.id_token)
        self.assertIn("https://rp.example.com/logout/", str(context.exception))

    def test_error_status_is_a_delivery_failure(self):
        # Section 2.8: the RP answers 400 when it could not log the user out.
        with patch(POST_FORM, return_value=(400, {})):
            with self.assertRaises(BackchannelLogoutRequestError) as context:
                send_backchannel_logout_request(self.id_token)
        self.assertIn("HTTP 400", str(context.exception))

    def test_any_2xx_is_a_delivered_logout(self):
        for status in (200, 204):
            with patch(POST_FORM, return_value=(status, {})):
                send_backchannel_logout_request(self.id_token)

    def test_logout_is_posted_through_the_hardened_transport(self):
        # The documented default, then a value that is not it, so the setting is shown to
        # reach the transport rather than to coincide with a constant.
        self.assertEqual(self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_TIMEOUT, 5)
        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_TIMEOUT = 2.5
        with patch(POST_FORM, return_value=(200, {})) as mocked_post:
            send_backchannel_logout_request(self.id_token)
        args, kwargs = mocked_post.call_args
        self.assertEqual(args[0], self.application.backchannel_logout_uri)
        self.assertEqual(set(args[1]), {"logout_token"})
        self.assertEqual(kwargs["timeout"], 2.5)
        self.assertIs(kwargs["require_public_address"], True)
        self.assertIs(kwargs["exc_class"], BackchannelLogoutRequestError)

    def test_logout_uri_on_an_internal_address_is_refused(self):
        # No mock: the stock handler resolves the URI and refuses before connecting.
        for uri in (
            "https://169.254.169.254/latest/meta-data/",
            "https://10.0.0.1/logout",
            "https://127.0.0.1/logout",
            "https://[::1]/logout",
        ):
            self.application.backchannel_logout_uri = uri
            self.application.save()
            with self.subTest(uri=uri), self.assertRaises(BackchannelLogoutRequestError) as context:
                send_backchannel_logout_request(self.id_token)
            self.assertIn("non-public address", str(context.exception))

    def test_logout_token_sub_is_the_one_the_id_token_was_issued_with(self):
        # Section 2.6 step 10: the RP checks sub against the ID Token it holds, so a
        # deployment's customised sub has to come back unchanged.
        self.id_token.sub = "opaque-subject-identifier"
        self.id_token.save()
        with patch(POST_FORM, return_value=(204, {})) as mocked_post:
            send_backchannel_logout_request(self.id_token)
        self.assertEqual(self._posted_logout_token(mocked_post)[1]["sub"], "opaque-subject-identifier")

    def test_logout_token_sub_falls_back_to_the_primary_key(self):
        # Rows issued before the column existed, which is what the default sub was.
        self.assertEqual(self.id_token.sub, "")
        with patch(POST_FORM, return_value=(204, {})) as mocked_post:
            send_backchannel_logout_request(self.id_token)
        self.assertEqual(self._posted_logout_token(mocked_post)[1]["sub"], str(self.user.pk))

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

    def _validate_uri(self, uri, client_type=Application.CLIENT_CONFIDENTIAL):
        """Run Application.clean() for one backchannel_logout_uri, returning its errors."""
        app = Application(
            name="uri_probe",
            user=self.developer,
            client_type=client_type,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="https://rp.example.com/callback",
            backchannel_logout_uri=uri,
        )
        try:
            app.clean()
        except ValidationError as exc:
            return exc.message_dict.get("backchannel_logout_uri", [])
        return []

    def test_https_backchannel_logout_uri_is_accepted(self):
        # Section 2.2 allows port, path and query components.
        for uri in (
            "https://rp.example.com",
            "https://rp.example.com/logout",
            "https://rp.example.com:8443/logout?tenant=1",
        ):
            with self.subTest(uri=uri):
                self.assertEqual(self._validate_uri(uri), [])

    def test_backchannel_logout_uri_rejects_other_schemes(self):
        # Django's URLField alone would accept ftp/ftps, which the OP cannot POST to.
        for uri in ("ftp://rp.example.com/logout", "ftps://rp.example.com/logout"):
            with self.subTest(uri=uri):
                self.assertIn("invalid_scheme", " ".join(self._validate_uri(uri)))

    def test_backchannel_logout_uri_rejects_userinfo(self):
        # The transport refuses to deliver to such a URI, so it is refused when registered
        # rather than stored and then never delivered to.
        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_URI_ALLOWED_SCHEMES = ["https", "http"]
        for uri in (
            "https://user:pw@rp.example.com/logout",
            "https://user@rp.example.com/logout",
            "http://rp.example.com@127.0.0.1/logout",
        ):
            for client_type in (Application.CLIENT_CONFIDENTIAL, Application.CLIENT_PUBLIC):
                with self.subTest(uri=uri, client_type=client_type):
                    errors = self._validate_uri(uri, client_type)
                    self.assertIn("userinfo", " ".join(errors))

    def test_backchannel_logout_uri_rejects_fragment(self):
        errors = self._validate_uri("https://rp.example.com/logout#frag")
        self.assertIn("fragment not allowed", " ".join(errors))

    def test_backchannel_logout_uri_rejects_http_by_default(self):
        # OIDC_BACKCHANNEL_LOGOUT_URI_ALLOWED_SCHEMES defaults to ["https"].
        errors = self._validate_uri("http://rp.example.com/logout")
        self.assertIn("invalid_scheme", " ".join(errors))

    def test_stored_logout_uri_is_not_validated_while_the_feature_is_off(self):
        # A URI stored under an earlier policy must not block every other edit to the
        # application once back-channel logout is turned off and the field is no longer offered.
        for setting in ("OIDC_BACKCHANNEL_LOGOUT_ENABLED", "OIDC_ENABLED"):
            with self.subTest(setting=setting), patch.object(self.oauth2_settings, setting, False):
                self.assertEqual(self._validate_uri("http://rp.example.com/logout"), [])

    def test_http_backchannel_logout_uri_allowed_for_confidential_client(self):
        # Section 2.2: http "MAY" be used "provided that the Client Type is confidential".
        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_URI_ALLOWED_SCHEMES = ["https", "http"]
        self.assertEqual(
            self._validate_uri("http://rp.example.com/logout", Application.CLIENT_CONFIDENTIAL), []
        )

    def test_http_backchannel_logout_uri_rejected_for_public_client(self):
        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_URI_ALLOWED_SCHEMES = ["https", "http"]
        errors = self._validate_uri("http://rp.example.com/logout", Application.CLIENT_PUBLIC)
        self.assertIn("only allowed for a confidential", " ".join(errors))

    def test_http_backchannel_logout_uri_allowed_on_loopback_for_public_client(self):
        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_URI_ALLOWED_SCHEMES = ["https", "http"]
        for uri in ("http://127.0.0.1:5173/api/backchannel-logout", "http://[::1]:5173/logout"):
            with self.subTest(uri=uri):
                self.assertEqual(self._validate_uri(uri, Application.CLIENT_PUBLIC), [])

    def test_localhost_backchannel_logout_uri_follows_allow_localhost_loopback(self):
        # The localhost hostname resolves through DNS and can point off-box, so it is
        # opt-in -- the same rule redirect_to_uri_allowed() applies to RFC 8252 loopback.
        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_URI_ALLOWED_SCHEMES = ["https", "http"]
        uri = "http://localhost:5173/api/backchannel-logout"

        self.oauth2_settings.ALLOW_LOCALHOST_LOOPBACK = False
        self.assertIn(
            "only allowed for a confidential",
            " ".join(self._validate_uri(uri, Application.CLIENT_PUBLIC)),
        )

        self.oauth2_settings.ALLOW_LOCALHOST_LOOPBACK = True
        self.assertEqual(self._validate_uri(uri, Application.CLIENT_PUBLIC), [])

    def test_valid_backchannel_logout_uri_reports_no_error(self):
        # Regression: field_errors is a defaultdict, so touching the key with an empty
        # list would make clean() raise a ValidationError carrying no messages.
        self.application.full_clean(exclude=["client_secret", "client_id", "user"])

    def test_logout_token_iss_is_the_one_the_id_token_was_issued_with(self):
        # Section 2.6 step 9: the RP matches iss against the ID Token's. The row records
        # it, so the Logout Token restates it even where the setting now says otherwise.
        self.id_token.iss = "https://idp.internal/o"
        self.id_token.sub = str(self.user.pk)
        self.id_token.save()
        with patch(POST_FORM, return_value=(204, {})) as mocked_post:
            send_backchannel_logout_request(self.id_token)
        self.assertEqual(self._posted_logout_token(mocked_post)[1]["iss"], "https://idp.internal/o")

    def test_logout_token_iss_falls_back_to_the_setting(self):
        # Rows issued before the column existed.
        self.assertEqual(self.id_token.iss, "")
        with patch(POST_FORM, return_value=(204, {})) as mocked_post:
            send_backchannel_logout_request(self.id_token)
        self.assertEqual(self._posted_logout_token(mocked_post)[1]["iss"], ISSUER)

    def test_raises_exception_without_any_issuer(self):
        """With no recorded issuer and no setting to fall back to, there is nothing to name."""
        self.oauth2_settings.OIDC_ISS_ENDPOINT = ""
        with self.assertRaises(BackchannelLogoutRequestError) as context:
            send_backchannel_logout_request(self.id_token)
        self.assertIn("No issuer recorded", str(context.exception))

    def test_nothing_is_sent_when_the_sub_could_not_be_recorded(self):
        # A row with an iss but no sub was issued without a sub that could be recorded --
        # none, or one too long. No substitute could match what the RP holds (section 2.6
        # step 10).
        self.id_token.iss = ISSUER
        self.id_token.save()
        with patch(POST_FORM) as mocked_post:
            with self.assertRaises(BackchannelLogoutRequestError) as context:
                send_backchannel_logout_request(self.id_token)
        mocked_post.assert_not_called()
        self.assertIn("issued without a sub that could be recorded", str(context.exception))

    def test_raises_exception_when_backchannel_logout_uri_not_provided(self):
        """BackchannelLogoutRequestError is raised for an application with no logout URI."""
        self.application.backchannel_logout_uri = ""
        self.application.save()
        with self.assertRaises(BackchannelLogoutRequestError) as context:
            send_backchannel_logout_request(self.id_token)
        self.assertIn("URL for backchannel logout not provided", str(context.exception))

    def test_raises_exception_on_request_failure(self):
        """Test that BackchannelLogoutRequestError is raised when the HTTP request fails."""
        # Anything the transport raises reaches the caller as the one documented exception.
        with patch(POST_FORM, side_effect=ConnectionError("Connection error")):
            with self.assertRaises(BackchannelLogoutRequestError) as context:
                send_backchannel_logout_request(self.id_token)
            self.assertIn("Connection error", str(context.exception))


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_BACKCHANNEL_LOGOUT)
class TestRPInitiatedLogoutDispatchOrder(TransactionTestCase):
    """When RPInitiatedLogoutView sends, against real commits.

    A TestCase cannot show this: it never commits, so the view's deferred dispatch only
    runs once the whole request has returned, whatever order the view asked for.
    """

    def setUp(self):
        self.user = User.objects.create_user(username="app_user", password="654321")
        application = Application.objects.create(
            name="dispatch_order_app",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="https://rp.example.com/callback",
            algorithm=Application.RS256_ALGORITHM,
            client_secret="dispatch_order_app_client_secret_value",
            backchannel_logout_uri="https://rp.example.com/logout",
        )
        expires = timezone.now() + datetime.timedelta(minutes=180)
        id_token = IDToken.objects.create(
            application=application, user=self.user, expires=expires, scope="openid"
        )
        AccessToken.objects.create(
            user=self.user,
            application=application,
            token="access-token-for-dispatch-order",
            id_token=id_token,
            scope="openid",
            expires=expires,
        )
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED = True
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT = False
        self.client.login(username="app_user", password="654321")

    def _logout(self):
        return self.client.post(reverse("oauth2_provider:rp-initiated-logout"), data={"allow": True})

    def test_logout_tokens_are_sent_only_after_the_logout(self):
        # The headline guarantee of this path: a relying party can neither delay nor, if
        # the worker dies while it answers, prevent the flush or the token revocation.
        session_key = self.client.session.session_key
        observed = []

        def record(id_token):
            observed.append(
                {
                    "session_alive": Session.objects.filter(session_key=session_key).exists(),
                    "access_tokens": AccessToken.objects.count(),
                }
            )

        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request", side_effect=record):
            response = self._logout()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(observed, [{"session_alive": False, "access_tokens": 0}])

    def test_logout_tokens_are_sent_once_the_logout_is_committed(self):
        # Sent from inside the view's transaction, a logout token would go out while the
        # revocation and the flush could still be rolled back -- by a worker killed while a
        # relying party answers -- and while every other request still saw them undone.
        alias = router.db_for_write(IDToken)
        observed = []

        def record(id_token):
            observed.append(
                {
                    "in_transaction": connections[alias].in_atomic_block,
                    "access_tokens": AccessToken.objects.count(),
                }
            )

        atomic_requests = [
            patch.dict(settings, ATOMIC_REQUESTS=True) for settings in connections.settings.values()
        ]
        with ExitStack() as stack:
            for patcher in atomic_requests:
                stack.enter_context(patcher)
            stack.enter_context(
                patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request", side_effect=record)
            )
            response = self._logout()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(observed, [{"in_transaction": False, "access_tokens": 0}])

    def _logout_under_manual_transaction_management(self):
        # AUTOCOMMIT off, no atomic block: Django refuses on_commit() there.
        alias = router.db_for_write(IDToken)
        transaction.set_autocommit(False, using=alias)
        try:
            return self._logout()
        finally:
            transaction.rollback(using=alias)
            transaction.set_autocommit(True, using=alias)

    def test_manual_transaction_management_is_left_alone_with_nothing_to_send(self):
        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED = False
        self.assertEqual(self._logout_under_manual_transaction_management().status_code, 302)

    def test_manual_transaction_management_sends_at_once(self):
        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as handler:
            response = self._logout_under_manual_transaction_management()

        self.assertEqual(response.status_code, 302)
        handler.assert_called_once()


RECEIVER_PROBE = """
import weakref

import django

django.setup()
from django.contrib.auth.signals import user_logged_out

names = set()
for entry in user_logged_out.receivers:
    receiver = entry[1]
    if isinstance(receiver, weakref.ReferenceType):
        receiver = receiver()
    names.add((receiver.__module__, receiver.__qualname__))
handlers = "oauth2_provider.authorization_server.oidc.handlers"
print((handlers, "on_user_logged_out_maybe_send_backchannel_logout") in names)
"""


def test_the_logout_receiver_is_connected_at_startup():
    # By DOTConfig.ready(), not by whichever module happens to import the handlers first:
    # a project that never imports them would otherwise never send a logout token. Checked
    # in a fresh interpreter, since this module has imported them already.
    result = subprocess.run(
        [sys.executable, "-c", RECEIVER_PROBE],
        capture_output=True,
        text=True,
        timeout=60,
        env={
            **os.environ,
            "DJANGO_SETTINGS_MODULE": os.environ.get("DJANGO_SETTINGS_MODULE", "tests.settings"),
        },
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "True"


class SubjectValidator(OAuth2Validator):
    """Customises ``sub`` the way ``docs/oidc.rst`` documents."""

    def get_additional_claims(self, request):
        return {"sub": f"user-{request.user.get_username()}"}


SUBJECT_SETTINGS = dict(presets.OIDC_SETTINGS_BACKCHANNEL_LOGOUT)
SUBJECT_SETTINGS["OAUTH2_VALIDATOR_CLASS"] = SubjectValidator


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SUBJECT_SETTINGS)
def test_customised_sub_reaches_the_logout_token(oauth2_settings, client, application, test_user):
    # The ID Token records the sub it was issued with, so a Logout Token restates it
    # without the deployment having to customise it a second time (section 2.6 step 10).
    application.backchannel_logout_uri = "https://rp.example.com/logout"
    application.save()
    tokens = generate_access_token(
        oauth2_settings, application, test_user, client, SUBJECT_SETTINGS, "openid", "http://example.org"
    )
    issued_sub = json.loads(jwcrypto_jwt.JWT(jwt=tokens.id_token, key=application.jwk_key).claims)["sub"]
    assert issued_sub == f"user-{test_user.get_username()}"
    assert IDToken.objects.get(user=test_user).sub == issued_sub

    client.force_login(test_user)
    with patch(POST_FORM, return_value=(204, {})) as mocked_post:
        client.logout()
    logout_token = mocked_post.call_args.args[1]["logout_token"]
    assert json.loads(jwcrypto_jwt.JWT(jwt=logout_token, key=application.jwk_key).claims)["sub"] == issued_sub


UNPINNED_ISSUER_SETTINGS = dict(presets.OIDC_SETTINGS_BACKCHANNEL_LOGOUT)
UNPINNED_ISSUER_SETTINGS.update(
    OIDC_ISS_ENDPOINT="",
    OIDC_RP_INITIATED_LOGOUT_ENABLED=True,
    OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT=False,
)


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(UNPINNED_ISSUER_SETTINGS)
def test_logout_token_names_the_id_tokens_issuer_across_hosts(
    oauth2_settings, settings, application, test_user, django_capture_on_commit_callbacks
):
    # Without OIDC_ISS_ENDPOINT, an ID Token's iss is derived from the request that issued
    # it: the RP's own token request, here to an internal hostname. The user logs out
    # through the public one. Section 2.6 step 9 has the RP match the two iss values, so
    # the Logout Token has to restate the ID Token's rather than derive its own.
    settings.ALLOWED_HOSTS = ["idp.internal", "login.example.com"]
    application.backchannel_logout_uri = "https://rp.example.com/logout"
    application.save()
    tokens = generate_access_token(
        oauth2_settings,
        application,
        test_user,
        Client(HTTP_HOST="idp.internal"),
        UNPINNED_ISSUER_SETTINGS,
        "openid",
        "http://example.org",
    )
    id_token_iss = json.loads(jwcrypto_jwt.JWT(jwt=tokens.id_token, key=application.jwk_key).claims)["iss"]
    assert id_token_iss == "http://idp.internal/o"

    browser = Client(HTTP_HOST="login.example.com")
    browser.force_login(test_user)
    with (
        patch(POST_FORM, return_value=(204, {})) as mocked_post,
        django_capture_on_commit_callbacks(using=router.db_for_write(IDToken), execute=True),
    ):
        response = browser.post(reverse("oauth2_provider:rp-initiated-logout"), data={"allow": True})
    assert response.status_code == 302
    logout_token = mocked_post.call_args.args[1]["logout_token"]
    assert (
        json.loads(jwcrypto_jwt.JWT(jwt=logout_token, key=application.jwk_key).claims)["iss"] == id_token_iss
    )


@pytest.mark.parametrize(
    "claimed, recorded",
    [("opaque-subject", "opaque-subject"), (42, "42"), (None, ""), ("x" * 255, "x" * 255)],
)
def test_recorded_sub(claimed, recorded):
    assert OAuth2Validator._recorded_sub(claimed) == recorded


@pytest.mark.parametrize(
    "claimed, recorded",
    [
        ("https://idp.example.com/o", "https://idp.example.com/o"),
        (None, ""),
        ("x" * 1024, "x" * 1024),
        ("x" * 1025, ""),
    ],
    ids=["url", "none", "at-the-column-width", "over-the-column-width"],
)
def test_recorded_iss(claimed, recorded):
    # 1024 is the column's width, which Oracle's NVARCHAR2 can hold.
    assert OAuth2Validator._recorded_iss(claimed) == recorded


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_BACKCHANNEL_LOGOUT)
def test_recorded_sub_over_the_oidc_limit_is_not_recorded(oauth2_settings, caplog):
    # OpenID Connect Core 1.0 section 2 caps sub at 255 characters, the column's width;
    # the ID Token is still issued, and the warning says no logout token will follow.
    with caplog.at_level("WARNING", logger="oauth2_provider"):
        assert OAuth2Validator._recorded_sub("x" * 256) == ""
    assert "256 characters" in caplog.text
    assert "no back-channel logout token will be sent" in caplog.text


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_BACKCHANNEL_LOGOUT)
def test_recorded_iss_over_the_column_is_not_recorded(oauth2_settings, caplog):
    with caplog.at_level("WARNING", logger="oauth2_provider"):
        assert OAuth2Validator._recorded_iss("x" * 1025) == ""
    assert "1025 characters, over the column's 1024" in caplog.text


def test_values_too_long_to_record_are_not_warned_about_while_the_feature_is_off(caplog):
    # A deployment that never turned back-channel logout on has nothing to be told about it.
    with caplog.at_level("WARNING", logger="oauth2_provider"):
        assert OAuth2Validator._recorded_sub("x" * 256) == ""
        assert OAuth2Validator._recorded_iss("x" * 1025) == ""
    assert caplog.records == []


class LongSubjectValidator(OAuth2Validator):
    def get_additional_claims(self, request):
        return {"sub": "x" * 300}


LONG_SUBJECT_SETTINGS = dict(presets.OIDC_SETTINGS_BACKCHANNEL_LOGOUT)
LONG_SUBJECT_SETTINGS["OAUTH2_VALIDATOR_CLASS"] = LongSubjectValidator


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(LONG_SUBJECT_SETTINGS)
def test_an_over_long_sub_still_issues_the_id_token(oauth2_settings, client, application, test_user):
    # Recording sub must never cost the ID Token: one over the column's width (and the
    # OpenID Connect limit) is issued as claimed and simply not recorded.
    tokens = generate_access_token(
        oauth2_settings, application, test_user, client, LONG_SUBJECT_SETTINGS, "openid", "http://example.org"
    )
    assert (
        json.loads(jwcrypto_jwt.JWT(jwt=tokens.id_token, key=application.jwk_key).claims)["sub"] == "x" * 300
    )
    assert IDToken.objects.get(user=test_user).sub == ""


class NoSubjectValidator(OAuth2Validator):
    """Removes sub the way docs/oidc.rst describes: by overriding get_claim_dict."""

    def get_claim_dict(self, request):
        claims = super().get_claim_dict(request)
        claims.pop("sub")
        return claims


NO_SUBJECT_SETTINGS = dict(presets.OIDC_SETTINGS_BACKCHANNEL_LOGOUT)
NO_SUBJECT_SETTINGS["OAUTH2_VALIDATOR_CLASS"] = NoSubjectValidator


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(NO_SUBJECT_SETTINGS)
def test_no_logout_token_for_an_id_token_issued_without_sub(
    oauth2_settings, client, application, test_user, caplog
):
    # OpenID Connect Core 1.0 section 2 makes sub REQUIRED; an ID Token issued without one
    # gives the RP nothing a Logout Token could match, so none is sent -- and it says why.
    application.backchannel_logout_uri = "https://rp.example.com/logout"
    application.save()
    tokens = generate_access_token(
        oauth2_settings, application, test_user, client, NO_SUBJECT_SETTINGS, "openid", "http://example.org"
    )
    assert "sub" not in json.loads(jwcrypto_jwt.JWT(jwt=tokens.id_token, key=application.jwk_key).claims)

    client.force_login(test_user)
    with patch(POST_FORM) as mocked_post, caplog.at_level("WARNING"):
        client.logout()
    mocked_post.assert_not_called()
    assert "issued without a sub that could be recorded" in caplog.text
