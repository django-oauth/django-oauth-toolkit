import datetime
import json
import threading
from unittest.mock import patch

import pytest
import requests
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone
from jwcrypto import jwt as jwcrypto_jwt

from oauth2_provider.authorization_server.oidc.handlers import (
    collect_backchannel_logout_targets,
    on_user_logged_out_maybe_send_backchannel_logout,
    send_backchannel_logout_request,
)
from oauth2_provider.authorization_server.views.application import ApplicationRegistration
from oauth2_provider.core.exceptions import BackchannelLogoutRequestError
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_id_token_model,
)
from oauth2_provider.oauth2_validators import OAuth2Validator

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase


HANDLERS_MODULE = "oauth2_provider.authorization_server.oidc.handlers"

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
        """Decode and verify the logout token handed to requests.post."""
        _, kwargs = mocked_post.call_args
        serialized = kwargs["data"]["logout_token"]
        verified = jwcrypto_jwt.JWT(jwt=serialized, key=self.application.jwk_key)
        return json.loads(verified.header), json.loads(verified.claims)

    def test_logout_token_is_signed_for_user(self):
        with patch("requests.post") as mocked_post:
            mocked_post.return_value.is_redirect = False
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
                mocked_post.return_value.is_redirect = False
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
            response = self.client.post(reverse("oauth2_provider:rp-initiated-logout"), data={"allow": True})

        self.assertEqual(response.status_code, 302)
        handler.assert_called_once()
        self.assertEqual(IDToken.objects.count(), 0)

    def test_rp_initiated_logout_notifies_exactly_once_when_tokens_are_kept(self):
        # With the rows left in place the user_logged_out receiver would fire as well as
        # the view, sending two logout tokens with different jti values per relying party.
        self.oauth2_settings.OIDC_RP_INITIATED_LOGOUT_DELETE_TOKENS = False
        self._enable_rp_initiated_logout()

        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as handler:
            response = self.client.post(reverse("oauth2_provider:rp-initiated-logout"), data={"allow": True})

        self.assertEqual(response.status_code, 302)
        handler.assert_called_once()
        self.assertEqual(IDToken.objects.count(), 1)

    def test_rp_initiated_logout_completes_when_every_notification_fails(self):
        # A relying party must never be able to hold up, or prevent, the logout itself.
        self._enable_rp_initiated_logout()

        with patch(f"{HANDLERS_MODULE}.send_backchannel_logout_request") as handler:
            handler.side_effect = ValueError("the relying party exploded")
            response = self.client.post(reverse("oauth2_provider:rp-initiated-logout"), data={"allow": True})

        self.assertEqual(response.status_code, 302)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertEqual(IDToken.objects.count(), 0)

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
        with patch("requests.post") as mocked_post:
            mocked_post.return_value.is_redirect = False
            send_backchannel_logout_request(self.id_token)
        claims = self._posted_logout_token(mocked_post)[1]
        self.assertEqual(claims["exp"] - claims["iat"], 120)

        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_TOKEN_EXPIRE_SECONDS = 30
        with patch("requests.post") as mocked_post:
            mocked_post.return_value.is_redirect = False
            send_backchannel_logout_request(self.id_token)
        claims = self._posted_logout_token(mocked_post)[1]
        self.assertEqual(claims["exp"] - claims["iat"], 30)

    def test_redirected_logout_uri_is_a_delivery_failure(self):
        # requests turns a 301/302/303 POST into a bodyless GET, which most endpoints
        # answer 200 -- so without this the OP would record a logout that never happened.
        with patch("requests.post") as mocked_post:
            mocked_post.return_value.is_redirect = True
            mocked_post.return_value.headers = {"Location": "https://rp.example.com/logout/"}
            with self.assertRaises(BackchannelLogoutRequestError) as context:
                send_backchannel_logout_request(self.id_token)
        self.assertIn("https://rp.example.com/logout/", str(context.exception))
        self.assertIs(mocked_post.call_args.kwargs["allow_redirects"], False)

    def test_logout_token_sub_follows_the_validator(self):
        # A deployment customising sub on ID Tokens must be able to customise it here too,
        # or a conformant RP rejects the Logout Token (section 2.6 step 10).
        class CustomValidator(OAuth2Validator):
            def get_logout_token_sub(self, id_token):
                return "opaque-subject-identifier"

        self.oauth2_settings.OAUTH2_VALIDATOR_CLASS = CustomValidator
        with patch("requests.post") as mocked_post:
            mocked_post.return_value.is_redirect = False
            send_backchannel_logout_request(self.id_token)
        self.assertEqual(self._posted_logout_token(mocked_post)[1]["sub"], "opaque-subject-identifier")

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

    def test_backchannel_logout_uri_rejects_fragment(self):
        errors = self._validate_uri("https://rp.example.com/logout#frag")
        self.assertIn("fragment not allowed", " ".join(errors))

    def test_backchannel_logout_uri_rejects_http_by_default(self):
        # OIDC_LOGOUT_URI_ALLOWED_SCHEMES defaults to ["https"].
        errors = self._validate_uri("http://rp.example.com/logout")
        self.assertIn("invalid_scheme", " ".join(errors))

    def test_http_backchannel_logout_uri_allowed_for_confidential_client(self):
        # Section 2.2: http "MAY" be used "provided that the Client Type is confidential".
        self.oauth2_settings.OIDC_LOGOUT_URI_ALLOWED_SCHEMES = ["https", "http"]
        self.assertEqual(
            self._validate_uri("http://rp.example.com/logout", Application.CLIENT_CONFIDENTIAL), []
        )

    def test_http_backchannel_logout_uri_rejected_for_public_client(self):
        self.oauth2_settings.OIDC_LOGOUT_URI_ALLOWED_SCHEMES = ["https", "http"]
        errors = self._validate_uri("http://rp.example.com/logout", Application.CLIENT_PUBLIC)
        self.assertIn("only allowed for a confidential", " ".join(errors))

    def test_http_backchannel_logout_uri_allowed_on_loopback_for_public_client(self):
        self.oauth2_settings.OIDC_LOGOUT_URI_ALLOWED_SCHEMES = ["https", "http"]
        for uri in ("http://127.0.0.1:5173/api/backchannel-logout", "http://[::1]:5173/logout"):
            with self.subTest(uri=uri):
                self.assertEqual(self._validate_uri(uri, Application.CLIENT_PUBLIC), [])

    def test_localhost_backchannel_logout_uri_follows_allow_localhost_loopback(self):
        # The localhost hostname resolves through DNS and can point off-box, so it is
        # opt-in -- the same rule redirect_to_uri_allowed() applies to RFC 8252 loopback.
        self.oauth2_settings.OIDC_LOGOUT_URI_ALLOWED_SCHEMES = ["https", "http"]
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
