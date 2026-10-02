"""
OIDC Core §5.4: the claims requested by the ``profile``, ``email``, ``address`` and
``phone`` scope values are returned from the UserInfo endpoint when the response type
issues an access token, and in the ID Token only when none is issued
(``response_type=id_token``). Gated by ``OIDC_COMPLIANT_SCOPE_CLAIMS``.
"""

import json
from copy import deepcopy
from unittest import mock
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from jwcrypto import jwt
from oauthlib.common import Request

from oauth2_provider.oauth2_validators import OAuth2Validator

from . import presets
from .conftest import CLEARTEXT_SECRET
from .utils import post_form


UserModel = get_user_model()


class ScopeClaimsValidator(OAuth2Validator):
    def get_additional_claims(self, request):
        return {
            "name": request.user.get_username(),
            "email": request.user.email,
        }


COMPLIANT_SETTINGS = deepcopy(presets.OIDC_SETTINGS_EMAIL_SCOPE)
COMPLIANT_SETTINGS["SCOPES"].update({"profile": "return profile claims"})
COMPLIANT_SETTINGS["OAUTH2_VALIDATOR_CLASS"] = ScopeClaimsValidator
COMPLIANT_SETTINGS["OIDC_COMPLIANT_SCOPE_CLAIMS"] = True

LEGACY_SETTINGS = deepcopy(COMPLIANT_SETTINGS)
LEGACY_SETTINGS["OIDC_COMPLIANT_SCOPE_CLAIMS"] = False

SCOPE = "openid profile email"


def _claims(token, key):
    return json.loads(jwt.JWT(key=key, jwt=token).claims)


def _authorize(client, user, application, response_type):
    client.force_login(user)
    rsp = client.post(
        reverse("oauth2_provider:authorize"),
        data={
            "client_id": application.client_id,
            "state": "random_state_string",
            "nonce": "random_nonce_string",
            "scope": SCOPE,
            "redirect_uri": "http://example.org",
            "response_type": response_type,
            "allow": True,
        },
    )
    assert rsp.status_code == 302
    location = urlparse(rsp["Location"])
    return parse_qs(location.fragment or location.query)


def _token(client, application, data):
    rsp = post_form(
        client,
        reverse("oauth2_provider:token"),
        data={"client_id": application.client_id, "client_secret": CLEARTEXT_SECRET, **data},
    )
    assert rsp.status_code == 200
    return rsp.json()


def _code_flow(client, user, application):
    code = _authorize(client, user, application, "code")["code"][0]
    client.logout()
    return _token(
        client,
        application,
        {"grant_type": "authorization_code", "code": code, "redirect_uri": "http://example.org"},
    )


def _userinfo(client, access_token):
    rsp = client.get(reverse("oauth2_provider:user-info"), HTTP_AUTHORIZATION=f"Bearer {access_token}")
    assert rsp.status_code == 200
    return rsp.json()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(COMPLIANT_SETTINGS)
def test_code_flow_scope_claims_only_in_userinfo(oauth2_settings, test_user, application, client, oidc_key):
    token_data = _code_flow(client, test_user, application)

    id_claims = _claims(token_data["id_token"], oidc_key)
    assert id_claims["sub"] == str(test_user.pk)
    assert "email" not in id_claims
    assert "name" not in id_claims

    userinfo = _userinfo(client, token_data["access_token"])
    assert userinfo["sub"] == str(test_user.pk)
    assert userinfo["email"] == test_user.email
    assert userinfo["name"] == test_user.get_username()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(COMPLIANT_SETTINGS)
def test_refresh_token_id_token_omits_scope_claims(oauth2_settings, test_user, application, client, oidc_key):
    token_data = _code_flow(client, test_user, application)
    refreshed = _token(
        client,
        application,
        {"grant_type": "refresh_token", "refresh_token": token_data["refresh_token"]},
    )

    id_claims = _claims(refreshed["id_token"], oidc_key)
    assert id_claims["sub"] == str(test_user.pk)
    assert "email" not in id_claims


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(LEGACY_SETTINGS)
def test_code_flow_legacy_scope_claims_in_id_token(oauth2_settings, test_user, application, client, oidc_key):
    token_data = _code_flow(client, test_user, application)

    id_claims = _claims(token_data["id_token"], oidc_key)
    assert id_claims["email"] == test_user.email
    assert id_claims["name"] == test_user.get_username()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(COMPLIANT_SETTINGS)
@pytest.mark.parametrize(
    "response_type,in_id_token",
    [
        ("id_token", True),
        ("id_token token", False),
    ],
)
def test_implicit_scope_claims(
    oauth2_settings, test_user, application, client, oidc_key, response_type, in_id_token
):
    application.authorization_grant_type = application.GRANT_IMPLICIT
    application.save()

    params = _authorize(client, test_user, application, response_type)

    id_claims = _claims(params["id_token"][0], oidc_key)
    assert ("email" in id_claims) is in_id_token
    assert ("name" in id_claims) is in_id_token
    if in_id_token:
        assert id_claims["email"] == test_user.email


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(COMPLIANT_SETTINGS)
@pytest.mark.parametrize("response_type", ["code id_token", "code id_token token"])
def test_hybrid_scope_claims_omitted_from_id_tokens(
    oauth2_settings, test_user, hybrid_application, client, oidc_key, response_type
):
    params = _authorize(client, test_user, hybrid_application, response_type)
    assert "email" not in _claims(params["id_token"][0], oidc_key)

    client.logout()
    token_data = _token(
        client,
        hybrid_application,
        {"grant_type": "authorization_code", "code": params["code"][0], "redirect_uri": "http://example.org"},
    )
    assert "email" not in _claims(token_data["id_token"], oidc_key)
    assert _userinfo(client, token_data["access_token"])["email"] == test_user.email


def _validator_request(rf, response_type):
    request = Request("/", headers=rf.get("/").META)
    request.scopes = ["openid", "profile", "email", "custom"]
    request.response_type = response_type
    request.client = mock.MagicMock()
    request.user = mock.MagicMock(pk=1, last_login=None)
    return request


class UngatedClaimsValidator(OAuth2Validator):
    oidc_claim_scope = None

    def get_additional_claims(self, request):
        return {"email": "user@example.com", "nickname": "user", "custom": "value"}


@pytest.mark.oauth2_settings(COMPLIANT_SETTINGS)
@pytest.mark.parametrize(
    "response_type,in_id_token",
    [
        (None, False),
        ("code", False),
        ("id_token token", False),
        ("code id_token", False),
        ("code id_token token", False),
        ("id_token", True),
    ],
)
def test_get_id_token_dictionary_response_types(oauth2_settings, rf, response_type, in_id_token):
    request = _validator_request(rf, response_type)
    claims, _ = UngatedClaimsValidator().get_id_token_dictionary(None, None, request)

    # Standard scope claims are recognised even when scope gating is disabled.
    assert ("email" in claims) is in_id_token
    assert ("nickname" in claims) is in_id_token
    # sub and claims outside the §5.4 scope values are unaffected.
    assert claims["sub"] == "1"
    assert claims["custom"] == "value"


@pytest.mark.oauth2_settings(LEGACY_SETTINGS)
def test_get_id_token_dictionary_legacy_keeps_scope_claims(oauth2_settings, rf):
    claims, _ = UngatedClaimsValidator().get_id_token_dictionary(None, None, _validator_request(rf, None))

    assert claims["email"] == "user@example.com"
    assert claims["nickname"] == "user"
