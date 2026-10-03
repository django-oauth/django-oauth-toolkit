"""
OpenID Connect Core 1.0 section 2 and 3.1.2.1: the ``acr`` claim of the ID Token,
reported by ``OAuth2Validator.get_acr`` when the End-User authenticates at the
authorization endpoint, and the ``acr_values`` the client requested.
"""

import json
from copy import deepcopy
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from django.urls import reverse
from jwcrypto import jwt

from oauth2_provider.models import get_grant_model
from oauth2_provider.oauth2_validators import OAuth2Validator

from . import presets
from .conftest import CLEARTEXT_SECRET
from .utils import get_basic_auth_header, post_form


Grant = get_grant_model()

ACR = "urn:example:acr:mfa"


class AcrValidator(OAuth2Validator):
    """Reports ``ACR`` and records the context of every call."""

    calls = []

    def get_acr(self, request):
        AcrValidator.calls.append(
            {"acr_values": request.acr_values, "grant_type": request.grant_type, "user": request.user}
        )
        return ACR


ACR_SETTINGS = deepcopy(presets.OIDC_SETTINGS_RW)
ACR_SETTINGS["OAUTH2_VALIDATOR_CLASS"] = AcrValidator


@pytest.fixture(autouse=True)
def reset_calls():
    AcrValidator.calls = []


def _claims(token, key):
    return json.loads(jwt.JWT(key=key, jwt=token).claims)


def _params(response):
    assert response.status_code == 302, response.content
    location = urlparse(response["Location"])
    return parse_qs(location.fragment or location.query)


def _consent(client, user, application, response_type, **extra):
    """Submit the consent form, as the stock authorize.html posts it back."""
    client.force_login(user)
    response = client.post(
        reverse("oauth2_provider:authorize"),
        data={
            "client_id": application.client_id,
            "state": "random_state_string",
            "nonce": "random_nonce_string",
            "scope": "openid",
            "redirect_uri": "http://example.org",
            "response_type": response_type,
            "allow": True,
            **extra,
        },
    )
    return _params(response)


def _authorize_get(client, user, application, response_type, **extra):
    """Send the authorization request for an application that skips consent."""
    application.skip_authorization = True
    application.save()
    client.force_login(user)
    query = {
        "client_id": application.client_id,
        "state": "random_state_string",
        "nonce": "random_nonce_string",
        "scope": "openid",
        "redirect_uri": "http://example.org",
        "response_type": response_type,
        **extra,
    }
    return _params(client.get(reverse("oauth2_provider:authorize"), query))


def _token(client, application, **data):
    response = post_form(
        client,
        reverse("oauth2_provider:token"),
        data={"client_id": application.client_id, "client_secret": CLEARTEXT_SECRET, **data},
    )
    assert response.status_code == 200, response.content
    return response.json()


def _exchange(client, application, code, **extra):
    client.logout()
    return _token(
        client,
        application,
        grant_type="authorization_code",
        code=code,
        redirect_uri="http://example.org",
        **extra,
    )


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_default_validator_omits_acr(oauth2_settings, test_user, application, client, oidc_key):
    params = _consent(client, test_user, application, "code", acr_values="1 2")
    token_data = _exchange(client, application, params["code"][0])

    assert "acr" not in _claims(token_data["id_token"], oidc_key)
    assert Grant.objects.count() == 0


def test_default_get_acr_returns_none():
    assert OAuth2Validator().get_acr(None) is None


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(ACR_SETTINGS)
def test_code_flow_acr_determined_at_authorization(oauth2_settings, test_user, application, client, oidc_key):
    params = _consent(client, test_user, application, "code", acr_values="1 2")
    code = params["code"][0]

    assert Grant.objects.get(code=code).acr == ACR
    assert AcrValidator.calls == [{"acr_values": "1 2", "grant_type": None, "user": test_user}]

    token_data = _exchange(client, application, code)

    assert _claims(token_data["id_token"], oidc_key)["acr"] == ACR
    # The token endpoint reuses the value stored with the code.
    assert len(AcrValidator.calls) == 1


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(ACR_SETTINGS)
def test_code_flow_without_consent_screen(oauth2_settings, test_user, application, client, oidc_key):
    params = _authorize_get(client, test_user, application, "code", acr_values="urn:example:acr:mfa")
    token_data = _exchange(client, application, params["code"][0])

    assert _claims(token_data["id_token"], oidc_key)["acr"] == ACR
    assert AcrValidator.calls[0]["acr_values"] == "urn:example:acr:mfa"


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(ACR_SETTINGS)
def test_hook_called_without_acr_values(oauth2_settings, test_user, application, client, oidc_key):
    params = _consent(client, test_user, application, "code")
    token_data = _exchange(client, application, params["code"][0])

    assert AcrValidator.calls[0]["acr_values"] is None
    assert _claims(token_data["id_token"], oidc_key)["acr"] == ACR


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(ACR_SETTINGS)
@pytest.mark.parametrize("response_type", ["id_token", "id_token token"])
def test_implicit_id_token_carries_acr(
    oauth2_settings, test_user, application, client, oidc_key, response_type
):
    application.authorization_grant_type = application.GRANT_IMPLICIT
    application.save()

    params = _consent(client, test_user, application, response_type, acr_values="1 2")

    assert _claims(params["id_token"][0], oidc_key)["acr"] == ACR
    assert AcrValidator.calls == [{"acr_values": "1 2", "grant_type": None, "user": test_user}]


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(ACR_SETTINGS)
@pytest.mark.parametrize("response_type", ["code id_token", "code id_token token"])
def test_hybrid_id_tokens_carry_acr(
    oauth2_settings, test_user, hybrid_application, client, oidc_key, response_type
):
    params = _consent(client, test_user, hybrid_application, response_type, acr_values="1 2")
    assert _claims(params["id_token"][0], oidc_key)["acr"] == ACR

    token_data = _exchange(client, hybrid_application, params["code"][0])

    assert _claims(token_data["id_token"], oidc_key)["acr"] == ACR
    # One call serves the code and the ID Token of the authorization response.
    assert len(AcrValidator.calls) == 1


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(ACR_SETTINGS)
def test_pushed_request_keeps_acr_values_through_consent(
    oauth2_settings, test_user, application, client, oidc_key
):
    """With a stored request, the consent form posts back to a URL carrying only request_uri."""
    push = post_form(
        client,
        reverse("oauth2_provider:pushed-authorization-request"),
        data={
            "client_id": application.client_id,
            "response_type": "code",
            "redirect_uri": "http://example.org",
            "scope": "openid",
            "state": "random_state_string",
            "acr_values": "1 2",
        },
        **get_basic_auth_header(application.client_id, CLEARTEXT_SECRET),
    )
    assert push.status_code == 201, push.content
    query = {"client_id": application.client_id, "request_uri": push.json()["request_uri"]}

    client.force_login(test_user)
    authorize_url = reverse("oauth2_provider:authorize")
    consent = client.get(authorize_url, query)
    assert consent.status_code == 200
    form_data = {k: v for k, v in consent.context_data["form"].initial.items() if v is not None}
    assert form_data["acr_values"] == "1 2"
    form_data["allow"] = True
    params = _params(client.post(f"{authorize_url}?{urlencode(query)}", data=form_data))

    assert AcrValidator.calls[0]["acr_values"] == "1 2"
    token_data = _exchange(client, application, params["code"][0])
    assert _claims(token_data["id_token"], oidc_key)["acr"] == ACR


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(ACR_SETTINGS)
def test_refresh_token_id_token_omits_acr(oauth2_settings, test_user, application, client, oidc_key):
    params = _consent(client, test_user, application, "code", acr_values="1 2")
    token_data = _exchange(client, application, params["code"][0])

    refreshed = _token(
        client, application, grant_type="refresh_token", refresh_token=token_data["refresh_token"]
    )

    assert "acr" not in _claims(refreshed["id_token"], oidc_key)
    assert len(AcrValidator.calls) == 1


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_client_cannot_inject_acr_at_authorization(oauth2_settings, test_user, application, client, oidc_key):
    """oauthlib exposes any request parameter as a request attribute, "acr" included."""
    params = _authorize_get(client, test_user, application, "code", acr="evil")

    assert Grant.objects.get(code=params["code"][0]).acr == ""
    token_data = _exchange(client, application, params["code"][0])
    assert "acr" not in _claims(token_data["id_token"], oidc_key)


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_client_cannot_inject_acr_in_implicit_id_token(
    oauth2_settings, test_user, application, client, oidc_key
):
    application.authorization_grant_type = application.GRANT_IMPLICIT
    application.save()

    params = _authorize_get(client, test_user, application, "id_token", acr="evil")

    assert "acr" not in _claims(params["id_token"][0], oidc_key)


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_client_cannot_inject_acr_at_token_endpoint(
    oauth2_settings, test_user, application, client, oidc_key
):
    params = _consent(client, test_user, application, "code")
    token_data = _exchange(client, application, params["code"][0], acr="evil")
    assert "acr" not in _claims(token_data["id_token"], oidc_key)

    refreshed = _token(
        client,
        application,
        grant_type="refresh_token",
        refresh_token=token_data["refresh_token"],
        acr="evil",
    )
    assert "acr" not in _claims(refreshed["id_token"], oidc_key)


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_discovery_omits_acr_values_supported_by_default(oauth2_settings, client):
    response = client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))

    assert "acr_values_supported" not in response.json()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_discovery_publishes_acr_values_supported(oauth2_settings, client):
    oauth2_settings.OIDC_ACR_VALUES_SUPPORTED = ["0", ACR]

    response = client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))

    assert response.json()["acr_values_supported"] == ["0", ACR]
