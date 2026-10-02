"""The OpenID Connect ``max_age`` authentication request parameter (OpenID
Connect Core 1.0 section 3.1.2.1)."""

import json
import time
from datetime import timedelta
from unittest import mock
from urllib.parse import parse_qs, urlparse

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in
from django.test import Client
from django.urls import reverse
from django.utils import timezone
from jwcrypto import jwt

from oauth2_provider.authorization_server.sessions import (
    AUTH_EVENT_SESSION_KEY,
    AUTH_TIME_SESSION_KEY,
    get_session_authentication_time,
)
from oauth2_provider.authorization_server.views import base
from oauth2_provider.oauth2_validators import OAuth2Validator

from . import presets
from .utils import get_basic_auth_header, post_form


UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"
REDIRECT_URI = "http://example.org"
PASSWORD = "123456"

pytestmark = [
    pytest.mark.django_db(databases="__all__"),
    pytest.mark.usefixtures("oauth2_settings"),
    pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW),
]


def authorize(client, application, **extra):
    query = {
        "client_id": application.client_id,
        "response_type": "code",
        "state": "random_state_string",
        "scope": "openid",
        "redirect_uri": REDIRECT_URI,
    }
    query.update(extra)
    return client.get(reverse("oauth2_provider:authorize"), data=query)


def login_next(response):
    """The ``next`` URL of a redirect to the login page, failing for any other response."""
    assert response.status_code == 302
    location = urlparse(response["Location"])
    assert location.path == settings.LOGIN_URL
    return parse_qs(location.query)["next"][0]


def login_required(response):
    """The query of a login_required error redirected to the client."""
    assert response.status_code == 302
    location = urlparse(response["Location"])
    assert f"{location.scheme}://{location.netloc}" == REDIRECT_URI
    query = parse_qs(location.query)
    assert query["error"] == ["login_required"]
    return query


def log_in(client, user):
    """Log in with a password, the way a person does: Django's login() runs."""
    assert client.login(username=user.get_username(), password=PASSWORD)
    user.refresh_from_db()


def age_session_login(client, seconds):
    """Make the login that authenticated the client's session ``seconds`` old."""
    session = client.session
    session[AUTH_TIME_SESSION_KEY] = time.time() - seconds
    session.save()


@pytest.fixture
def stale_client(client, test_user):
    """A client with a session whose login was an hour ago."""
    log_in(client, test_user)
    age_session_login(client, 3600)
    test_user.last_login = timezone.now() - timedelta(hours=1)
    test_user.save(update_fields=["last_login"])
    return client


def test_expired_max_age_sends_the_user_to_log_in(stale_client, application):
    next_url = login_next(authorize(stale_client, application, max_age="60"))

    next_query = parse_qs(urlparse(next_url).query)
    # max_age is kept, so the request is checked again when the user is back.
    assert next_query["max_age"] == ["60"]
    assert next_query["state"] == ["random_state_string"]
    assert next_query["client_id"] == [application.client_id]


def test_recent_login_satisfies_max_age(stale_client, application):
    age_session_login(stale_client, 30)

    response = authorize(stale_client, application, max_age="60")

    assert response.status_code == 200
    assert response.context_data["form"].initial["state"] == "random_state_string"


def test_session_without_a_recorded_login_counts_as_expired(stale_client, application):
    # A session authenticated before the login time was recorded, or other
    # than through Django's login().
    session = stale_client.session
    del session[AUTH_TIME_SESSION_KEY]
    session.save()

    login_next(authorize(stale_client, application, max_age="86400"))


def test_login_in_the_same_clock_tick_is_told_apart(stale_client, application, test_user):
    # Logins are told apart by identifier, not time: with the clock frozen, a
    # stale session that follows the return URL without logging in is refused,
    # and one that logs in is let through.
    frozen = time.time()
    with mock.patch.object(time, "time", return_value=frozen):
        log_in(stale_client, test_user)
        next_url = login_next(authorize(stale_client, application, prompt="login"))
        login_required(stale_client.get(next_url))

        next_url = login_next(authorize(stale_client, application, state="again", prompt="login"))
        log_in(stale_client, test_user)
        assert stale_client.get(next_url).status_code == 200


def test_max_age_zero_needs_a_new_login_even_in_the_same_clock_tick(client, application, test_user):
    # max_age=0 is prompt=login: a login a moment ago, with no time elapsed by
    # the clock, does not meet it.
    frozen = time.time()
    with mock.patch.object(time, "time", return_value=frozen):
        log_in(client, test_user)
        login_next(authorize(client, application, max_age="0"))


def test_a_session_without_a_login_identifier_has_not_logged_in_again(stale_client, application):
    next_url = login_next(authorize(stale_client, application, prompt="login"))
    # Authenticated by some means that does not record logins.
    session = stale_client.session
    session.pop(AUTH_EVENT_SESSION_KEY)
    session.save()

    login_required(stale_client.get(next_url))


@pytest.mark.parametrize("authenticated", [True, False])
@pytest.mark.parametrize("name, values", [("max_age", ["0", "999999"]), ("prompt", ["login", "consent"])])
def test_repeated_parameters_are_invalid_request(stale_client, application, authenticated, name, values):
    # RFC 6749 section 3.1: a parameter must not be included more than once,
    # and neither of these may silently pick one of its values.
    query = {
        "client_id": application.client_id,
        "response_type": "code",
        "state": "random_state_string",
        "scope": "openid",
        "redirect_uri": REDIRECT_URI,
        name: values,
    }
    browser = stale_client if authenticated else Client()
    response = browser.get(reverse("oauth2_provider:authorize"), data=query)

    assert response.status_code == 302
    location = urlparse(response["Location"])
    assert f"{location.scheme}://{location.netloc}" == REDIRECT_URI
    assert parse_qs(location.query)["error"] == ["invalid_request"]


def test_pending_requests_in_two_tabs_are_both_kept(stale_client, application, test_user):
    first = login_next(authorize(stale_client, application, state="first", max_age="0"))
    second = login_next(authorize(stale_client, application, state="second", max_age="0"))

    log_in(stale_client, test_user)

    assert stale_client.get(first).status_code == 200
    assert stale_client.get(second).status_code == 200


def test_login_in_another_browser_does_not_count(stale_client, application, test_user):
    other_browser = Client()
    log_in(other_browser, test_user)

    # last_login is now fresh, but this session's login is still an hour old.
    next_url = login_next(authorize(stale_client, application, max_age="60"))

    # Nor does a login elsewhere satisfy the login this session was sent to.
    log_in(other_browser, test_user)
    login_required(stale_client.get(next_url))


def test_oversized_max_age_is_no_limit(stale_client, application):
    response = authorize(stale_client, application, max_age="9" * 5000)

    assert response.status_code == 200


def test_leading_zeros_do_not_make_max_age_unlimited(stale_client, application):
    login_next(authorize(stale_client, application, max_age="0" * 5000 + "1"))


def test_logging_in_again_satisfies_max_age(stale_client, application, test_user):
    next_url = login_next(authorize(stale_client, application, max_age="60"))

    log_in(stale_client, test_user)
    response = stale_client.get(next_url)

    assert response.status_code == 200


@pytest.mark.parametrize("max_age", ["0", "1"])
def test_max_age_no_login_can_meet_does_not_loop(stale_client, application, test_user, max_age):
    next_url = login_next(authorize(stale_client, application, max_age=max_age))

    log_in(stale_client, test_user)
    # Even a login a moment ago is older than 0 seconds (or, with a slow
    # redirect, 1 second); the login this request asked for satisfies it.
    with mock.patch.object(base.time, "time", return_value=base.time.time() + 2):
        response = stale_client.get(next_url)

    assert response.status_code == 200


def test_anonymous_max_age_zero_logs_in_once(client, application, test_user):
    next_url = login_next(authorize(client, application, max_age="0"))

    log_in(client, test_user)
    response = client.get(next_url)

    assert response.status_code == 200


@pytest.mark.parametrize("extra", [{"max_age": "60"}, {"prompt": "login"}])
def test_returning_without_logging_in_is_login_required(stale_client, application, extra):
    next_url = login_next(authorize(stale_client, application, **extra))

    # A stale session that skips the login page has not re-authenticated. It is
    # not sent to log in again, which could loop: the client gets the error.
    query = login_required(stale_client.get(next_url))
    assert query["state"] == ["random_state_string"]


@pytest.mark.parametrize("extra", [{"max_age": "0"}, {"prompt": "login"}])
def test_login_for_another_request_does_not_count(client, application, test_user, extra):
    # The user is sent to log in for one request, logs in, and never returns
    # to it; the login does not satisfy a different request that follows.
    login_next(authorize(client, application, state="first", max_age="0"))
    log_in(client, test_user)

    login_next(authorize(client, application, state="second", **extra))


def test_another_request_while_logging_in_does_not_drop_the_record(stale_client, application, test_user):
    # A second tab, another relying party or a silent renew reaching the
    # endpoint while the user is on the login page must not cost them a
    # second login for the request they are logging in for.
    next_url = login_next(authorize(stale_client, application, state="first", max_age="0"))
    assert authorize(stale_client, application, state="other").status_code == 200

    log_in(stale_client, test_user)

    assert stale_client.get(next_url).status_code == 200


def test_anonymous_request_without_max_age_stores_no_session(client, application):
    response = authorize(client, application)

    login_next(response)
    assert settings.SESSION_COOKIE_NAME not in response.cookies


def test_login_page_on_another_origin_gets_an_absolute_next(stale_client, application, settings):
    settings.LOGIN_URL = "https://login.example.com/login/"

    response = authorize(stale_client, application, max_age="60")

    assert response.status_code == 302
    location = urlparse(response["Location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == settings.LOGIN_URL
    next_url = urlparse(parse_qs(location.query)["next"][0])
    assert f"{next_url.scheme}://{next_url.netloc}{next_url.path}" == (
        f"http://testserver{reverse('oauth2_provider:authorize')}"
    )
    assert parse_qs(next_url.query)["max_age"] == ["60"]


def test_logging_in_as_another_user_asks_again(stale_client, application, other_user):
    # Django flushes the session when another user logs in, which drops the
    # record that a login was asked for, so a max_age the new login cannot
    # meet asks once more; the login that follows satisfies it.
    next_url = login_next(authorize(stale_client, application, max_age="0"))

    log_in(stale_client, other_user)
    next_url = login_next(stale_client.get(next_url))
    log_in(stale_client, other_user)

    assert stale_client.get(next_url).status_code == 200


def test_login_long_after_the_redirect_does_not_count(stale_client, application, test_user):
    next_url = login_next(authorize(stale_client, application, max_age="0"))

    log_in(stale_client, test_user)
    later = base.time.time() + base.REAUTHENTICATION_WINDOW_SECONDS + 1
    with mock.patch.object(base.time, "time", return_value=later):
        login_next(stale_client.get(next_url))


def test_prompt_login_with_max_age_zero_logs_in_once(stale_client, application, test_user):
    next_url = login_next(authorize(stale_client, application, prompt="login", max_age="0"))
    # The prompt stays in the request until the login has been verified.
    assert parse_qs(urlparse(next_url).query)["prompt"] == ["login"]

    log_in(stale_client, test_user)
    response = stale_client.get(next_url)

    assert response.status_code == 200


# OAuth2Validator leaves the OIDC silent-login hooks unimplemented; deployments
# (like tests/app/idp) supply them.
@mock.patch.object(OAuth2Validator, "validate_silent_authorization", return_value=True, create=True)
@mock.patch.object(OAuth2Validator, "validate_silent_login", return_value=True, create=True)
def test_prompt_none_with_expired_max_age_is_login_required(
    _login, _authorization, stale_client, application, oauth2_settings
):
    oauth2_settings.COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS = True

    response = authorize(stale_client, application, prompt="none", max_age="60")

    query = login_required(response)
    assert query["state"] == ["random_state_string"]
    assert "iss" in query


@mock.patch.object(OAuth2Validator, "validate_silent_authorization", return_value=True, create=True)
@mock.patch.object(OAuth2Validator, "validate_silent_login", return_value=True, create=True)
def test_prompt_none_with_expired_max_age_hybrid_error_in_fragment(
    _login, _authorization, stale_client, hybrid_application
):
    response = authorize(
        stale_client,
        hybrid_application,
        response_type="code id_token",
        nonce="random_nonce_string",
        prompt="none",
        max_age="60",
    )

    assert response.status_code == 302
    location = urlparse(response["Location"])
    assert location.query == ""
    fragment = parse_qs(location.fragment)
    assert fragment["error"] == ["login_required"]
    assert fragment["state"] == ["random_state_string"]


@pytest.mark.parametrize("authenticated", [True, False])
@pytest.mark.parametrize("max_age", ["abc", "-1", "1.5", "１"])
def test_invalid_max_age_is_invalid_request(stale_client, application, max_age, authenticated):
    # The request is validated before the user is asked to log in.
    response = authorize(stale_client if authenticated else Client(), application, max_age=max_age)

    assert response.status_code == 302
    location = urlparse(response["Location"])
    assert f"{location.scheme}://{location.netloc}" == REDIRECT_URI
    query = parse_qs(location.query)
    assert query["error"] == ["invalid_request"]
    assert query["state"] == ["random_state_string"]


def test_invalid_max_age_is_reported_before_a_login_prompt(stale_client, application):
    # Validated before prompt=login sends the user to log in.
    response = authorize(stale_client, application, prompt="login", max_age="abc")

    assert response.status_code == 302
    location = urlparse(response["Location"])
    assert f"{location.scheme}://{location.netloc}" == REDIRECT_URI
    assert parse_qs(location.query)["error"] == ["invalid_request"]


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RP_REGISTRATION)
def test_registering_satisfies_max_age(client, application, test_user):
    # prompt=create sends an anonymous user to register; the login that ends
    # the registration is the one max_age=0 asked for.
    response = authorize(client, application, prompt="create", max_age="0")
    assert response.status_code == 302
    next_url = parse_qs(urlparse(response["Location"]).query)["next"][0]

    log_in(client, test_user)

    assert client.get(next_url).status_code == 200


def test_invalid_max_age_from_an_unknown_client_is_not_redirected(client, application):
    # The client is validated first; with no registered redirect URI to send
    # the error to, it is shown to the user instead.
    response = client.get(
        reverse("oauth2_provider:authorize"),
        data={
            "client_id": "unknown",
            "response_type": "code",
            "scope": "openid",
            "redirect_uri": REDIRECT_URI,
            "max_age": "abc",
        },
    )

    assert response.status_code == 400


def test_corrupt_reauthentication_record_is_ignored(stale_client, application):
    next_url = login_next(authorize(stale_client, application, max_age="60"))
    session = stale_client.session
    records = session[base.REAUTHENTICATION_SESSION_KEY]
    session[base.REAUTHENTICATION_SESSION_KEY] = {binding: {"at": "not a time"} for binding in records}
    session.save()

    # Treated as no record: the stale session is sent to log in, not refused.
    login_next(stale_client.get(next_url))


def test_max_age_is_ignored_without_openid_scope(stale_client, application):
    # Only an OpenID Connect request defines max_age; OAuth 2.0 ignores
    # parameters it does not know (RFC 6749 section 3.1).
    response = authorize(stale_client, application, scope="read", max_age="0")

    assert response.status_code == 200


def test_max_age_is_ignored_with_oidc_disabled(stale_client, application, oauth2_settings):
    oauth2_settings.OIDC_ENABLED = False

    response = authorize(stale_client, application, scope="openid read", max_age="0")

    assert response.status_code == 200


def test_login_without_a_request_or_session_records_nothing(test_user, rf):
    # Logins sent without a request, or with one that has no session, are
    # left alone.
    user_logged_in.send(sender=type(test_user), request=None, user=test_user)
    request = rf.get("/")
    user_logged_in.send(sender=type(test_user), request=request, user=test_user)

    assert not hasattr(request, "session")
    assert get_session_authentication_time(request) is None


def test_auth_time_reflects_the_new_login(stale_client, application, test_user):
    stale_login = test_user.last_login
    next_url = login_next(authorize(stale_client, application, max_age="60"))

    log_in(stale_client, test_user)
    consent = stale_client.get(next_url)
    assert consent.status_code == 200
    form_data = {
        key: value for key, value in consent.context_data["form"].initial.items() if value is not None
    }
    form_data["allow"] = True
    approved = stale_client.post(next_url, data=form_data)
    assert approved.status_code == 302
    code = parse_qs(urlparse(approved["Location"]).query)["code"][0]

    token_response = post_form(
        stale_client,
        reverse("oauth2_provider:token"),
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI},
        **get_basic_auth_header(application.client_id, CLEARTEXT_SECRET),
    )
    assert token_response.status_code == 200
    id_token = token_response.json()["id_token"]
    claims = json.loads(jwt.JWT(jwt=id_token).token.objects["payload"])

    assert claims["auth_time"] == int(test_user.last_login.timestamp())
    assert claims["auth_time"] > stale_login.timestamp()
