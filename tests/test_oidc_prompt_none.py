"""``prompt=none`` OpenID Connect authentication requests (OpenID Connect Core
1.0 section 3.1.2.1) with the stock ``OAuth2Validator``, which must answer them
rather than fail on oauthlib's silent-login hooks. The consent outcomes for a
logged-in user (#1928) are tested in ``test_authorization_code.py``."""

from unittest import mock
from urllib.parse import parse_qs, urlparse

import pytest
from django.urls import reverse

from oauth2_provider.models import get_application_model, get_grant_model
from oauth2_provider.oauth2_validators import OAuth2Validator

from . import presets
from .conftest import CLEARTEXT_SECRET
from .utils import get_basic_auth_header, post_form


Application = get_application_model()
Grant = get_grant_model()

REDIRECT_URI = "http://example.org"

pytestmark = [
    pytest.mark.django_db(databases="__all__"),
    pytest.mark.usefixtures("oauth2_settings"),
    pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW),
]


def request_parameters(application, **extra):
    parameters = {
        "client_id": application.client_id,
        "response_type": "code",
        "state": "random_state_string",
        "scope": "openid",
        "redirect_uri": REDIRECT_URI,
        "prompt": "none",
    }
    parameters.update(extra)
    return parameters


def authorize(client, application, **extra):
    return client.get(reverse("oauth2_provider:authorize"), data=request_parameters(application, **extra))


def redirected_to_client(response, component="query"):
    """The parameters of a response redirected to the client, in *component* of the URI."""
    assert response.status_code == 302
    location = urlparse(response["Location"])
    assert f"{location.scheme}://{location.netloc}" == REDIRECT_URI
    return parse_qs(getattr(location, component))


def test_anonymous_request_is_login_required(client, application):
    params = redirected_to_client(authorize(client, application))

    assert params["error"] == ["login_required"]
    assert params["state"] == ["random_state_string"]


def test_anonymous_implicit_request_is_login_required_in_the_fragment(client, application):
    application.authorization_grant_type = Application.GRANT_IMPLICIT
    application.save()

    response = authorize(client, application, response_type="id_token", nonce="random_nonce_string")

    params = redirected_to_client(response, "fragment")
    assert params["error"] == ["login_required"]
    assert params["state"] == ["random_state_string"]


def test_pushed_request_is_accepted(client, application):
    response = post_form(
        client,
        reverse("oauth2_provider:pushed-authorization-request"),
        data=request_parameters(application),
        **get_basic_auth_header(application.client_id, CLEARTEXT_SECRET),
    )

    assert response.status_code == 201
    assert "request_uri" in response.json()


@mock.patch.object(OAuth2Validator, "validate_silent_authorization", return_value=False)
def test_a_validator_can_still_require_consent(_validate_silent_authorization, logged_in_client, application):
    application.skip_authorization = True
    application.save()

    params = redirected_to_client(authorize(logged_in_client, application))

    assert params["error"] == ["consent_required"]
    assert not Grant.objects.exists()


def test_a_validator_can_decide_once_the_user_is_known(logged_in_client, application, test_user):
    # oauthlib asks the hooks while the request is validated, with no user on
    # its request, and again when the response is created, with request.user
    # set: a per-user override allows the first call and decides on the second.
    application.skip_authorization = True
    application.save()

    with mock.patch.object(
        OAuth2Validator,
        "validate_silent_authorization",
        autospec=True,
        side_effect=lambda validator, request: request.user is None,
    ) as validate_silent_authorization:
        params = redirected_to_client(authorize(logged_in_client, application))

    assert params["error"] == ["consent_required"]
    assert params["state"] == ["random_state_string"]
    assert not Grant.objects.exists()
    users = [call.args[1].user for call in validate_silent_authorization.call_args_list]
    assert users == [None, test_user]
