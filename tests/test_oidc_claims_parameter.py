"""
OIDC Core §5.5: the ``claims`` request parameter requests individual claims for the
ID Token and the UserInfo response, in addition to the scope-derived ones. Gated by
``OIDC_CLAIMS_PARAMETER_ENABLED``.
"""

import json
import re
import uuid
from copy import deepcopy
from datetime import timedelta
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils import timezone
from jwcrypto import jwt
from oauthlib.oauth2.rfc6749.errors import InvalidRequestError

from oauth2_provider.authorization_server.oidc.claims import (
    claim_value_matches,
    normalize_claims_request,
    requested_claim_names,
    safe_normalize_claims_request,
)
from oauth2_provider.models import get_access_token_model, get_grant_model
from oauth2_provider.oauth2_validators import OAuth2Validator

from . import presets
from .conftest import CLEARTEXT_SECRET
from .utils import get_basic_auth_header, post_form


UserModel = get_user_model()
AccessToken = get_access_token_model()
Grant = get_grant_model()


class ClaimsValidator(OAuth2Validator):
    def get_additional_claims(self, request):
        return {
            "name": request.user.get_username(),
            "email": request.user.email,
        }


class AcrClaimsValidator(ClaimsValidator):
    def get_acr(self, request):
        return "urn:example:acr:pwd"


class CountingAcrValidator(AcrClaimsValidator):
    calls = 0

    def get_acr(self, request):
        CountingAcrValidator.calls += 1
        return super().get_acr(request)


class CountingClaimsValidator(ClaimsValidator):
    calls = 0

    def get_additional_claims(self, request):
        CountingClaimsValidator.calls += 1
        return super().get_additional_claims(request)


class NoNameValidator(ClaimsValidator):
    def get_requested_claims(self, request, target):
        requested = super().get_requested_claims(request, target)
        return {k: v for k, v in requested.items() if k != "name"}


SETTINGS = deepcopy(presets.OIDC_SETTINGS_EMAIL_SCOPE)
SETTINGS["SCOPES"].update({"profile": "return profile claims"})
SETTINGS["OAUTH2_VALIDATOR_CLASS"] = ClaimsValidator
SETTINGS["OIDC_CLAIMS_PARAMETER_ENABLED"] = True

COMPLIANT_SETTINGS = deepcopy(SETTINGS)
COMPLIANT_SETTINGS["OIDC_COMPLIANT_SCOPE_CLAIMS"] = True

DISABLED_SETTINGS = deepcopy(SETTINGS)
DISABLED_SETTINGS["OIDC_CLAIMS_PARAMETER_ENABLED"] = False

HOOK_SETTINGS = deepcopy(SETTINGS)
HOOK_SETTINGS["OAUTH2_VALIDATOR_CLASS"] = NoNameValidator

NON_ROTATING_SETTINGS = deepcopy(SETTINGS)
NON_ROTATING_SETTINGS["ROTATE_REFRESH_TOKEN"] = False

ACR_SETTINGS = deepcopy(SETTINGS)
ACR_SETTINGS["OAUTH2_VALIDATOR_CLASS"] = AcrClaimsValidator

COUNTING_ACR_SETTINGS = deepcopy(SETTINGS)
COUNTING_ACR_SETTINGS["OAUTH2_VALIDATOR_CLASS"] = CountingAcrValidator

COUNTING_SETTINGS = deepcopy(SETTINGS)
COUNTING_SETTINGS["OAUTH2_VALIDATOR_CLASS"] = CountingClaimsValidator

GRACE_SETTINGS = deepcopy(SETTINGS)
GRACE_SETTINGS["ROTATE_REFRESH_TOKEN"] = True
GRACE_SETTINGS["REFRESH_TOKEN_GRACE_PERIOD_SECONDS"] = 120


def _claims(token, key):
    return json.loads(jwt.JWT(key=key, jwt=token).claims)


def _params(application, response_type, claims, scope="openid", **extra):
    params = {
        "client_id": application.client_id,
        "state": "random_state_string",
        "nonce": "random_nonce_string",
        "scope": scope,
        "redirect_uri": "http://example.org",
        "response_type": response_type,
        **extra,
    }
    if claims is not None:
        params["claims"] = claims if isinstance(claims, str) else json.dumps(claims)
    return params


def _redirect_params(rsp):
    assert rsp.status_code == 302, rsp.content
    location = urlparse(rsp["Location"])
    return parse_qs(location.fragment or location.query)


def _consent_form(client, user, application, response_type, claims, scope="openid", **extra):
    """Load the consent page as a browser would; return the URL and the form's fields."""
    client.force_login(user)
    query = urlencode(_params(application, response_type, claims, scope, **extra))
    url = f"{reverse('oauth2_provider:authorize')}?{query}"
    rsp = client.get(url)
    assert rsp.status_code == 200, rsp.content
    fields = {name: value for name, value in rsp.context["form"].initial.items() if value is not None}
    return url, fields


def _authorize(client, user, application, response_type, claims, scope="openid", consented_claims=None):
    """Load the consent page and post its form back, ``consented_claims`` replacing the
    claims field (partial consent, or tampering)."""
    url, fields = _consent_form(client, user, application, response_type, claims, scope)
    if consented_claims is not None:
        fields["claims"] = consented_claims
    rsp = client.post(url, data={**fields, "allow": True})
    return _redirect_params(rsp)


def _token(client, application, data):
    rsp = post_form(
        client,
        reverse("oauth2_provider:token"),
        data={"client_id": application.client_id, "client_secret": CLEARTEXT_SECRET, **data},
    )
    assert rsp.status_code == 200, rsp.content
    return rsp.json()


def _code_flow(client, user, application, claims, scope="openid"):
    code = _authorize(client, user, application, "code", claims, scope)["code"][0]
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
@pytest.mark.oauth2_settings(SETTINGS)
def test_userinfo_claim_beyond_scopes(oauth2_settings, test_user, application, client, oidc_key):
    # The conformance suite's oidcc-claims-essential: name with only the openid scope.
    token_data = _code_flow(client, test_user, application, {"userinfo": {"name": {"essential": True}}})

    id_claims = _claims(token_data["id_token"], oidc_key)
    assert "name" not in id_claims
    assert "email" not in id_claims

    userinfo = _userinfo(client, token_data["access_token"])
    assert userinfo == {"sub": str(test_user.pk), "name": test_user.get_username()}


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(COMPLIANT_SETTINGS)
def test_id_token_claim_survives_compliant_scope_claims(
    oauth2_settings, test_user, application, client, oidc_key
):
    # email is a §5.4 UserInfo-only scope claim, but explicitly requested for the ID Token.
    token_data = _code_flow(
        client, test_user, application, {"id_token": {"email": None}}, scope="openid email profile"
    )

    id_claims = _claims(token_data["id_token"], oidc_key)
    assert id_claims["email"] == test_user.email
    assert "name" not in id_claims

    userinfo = _userinfo(client, token_data["access_token"])
    assert userinfo["email"] == test_user.email
    assert userinfo["name"] == test_user.get_username()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_access_token_stores_normalized_claims(oauth2_settings, test_user, application, client, oidc_key):
    requested = {"userinfo": {"name": None}, "id_token": {"email": {"essential": True}}, "other": {}}
    token_data = _code_flow(client, test_user, application, requested)

    access_token = AccessToken.objects.get(user=test_user)
    expected = {"userinfo": {"name": None}, "id_token": {"email": {"essential": True}}}
    assert access_token.claims == expected
    assert _claims(token_data["id_token"], oidc_key)["email"] == test_user.email


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
@pytest.mark.parametrize("response_type", ["id_token", "id_token token"])
def test_implicit_id_token_claim(oauth2_settings, test_user, application, client, oidc_key, response_type):
    # The conformance suite's oidcc-claims-essential for response_type=id_token.
    application.authorization_grant_type = application.GRANT_IMPLICIT
    application.save()

    params = _authorize(
        client, test_user, application, response_type, {"id_token": {"name": {"essential": True}}}
    )

    id_claims = _claims(params["id_token"][0], oidc_key)
    assert id_claims["name"] == test_user.get_username()
    assert "email" not in id_claims


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_implicit_userinfo_claim(oauth2_settings, test_user, application, client, oidc_key):
    application.authorization_grant_type = application.GRANT_IMPLICIT
    application.save()

    params = _authorize(client, test_user, application, "id_token token", {"userinfo": {"name": None}})

    assert "name" not in _claims(params["id_token"][0], oidc_key)
    assert _userinfo(client, params["access_token"][0])["name"] == test_user.get_username()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
@pytest.mark.parametrize("response_type", ["code id_token", "code id_token token", "code token"])
def test_hybrid_claims(oauth2_settings, test_user, hybrid_application, client, oidc_key, response_type):
    requested = {"userinfo": {"name": None}, "id_token": {"email": None}}
    params = _authorize(client, test_user, hybrid_application, response_type, requested)
    if "id_token" in params:
        front_channel = _claims(params["id_token"][0], oidc_key)
        assert front_channel["email"] == test_user.email
        assert "name" not in front_channel

    client.logout()
    token_data = _token(
        client,
        hybrid_application,
        {"grant_type": "authorization_code", "code": params["code"][0], "redirect_uri": "http://example.org"},
    )
    id_claims = _claims(token_data["id_token"], oidc_key)
    assert id_claims["email"] == test_user.email
    assert "name" not in id_claims
    assert _userinfo(client, token_data["access_token"])["name"] == test_user.get_username()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_refresh_carries_claims_forward(oauth2_settings, test_user, application, client, oidc_key):
    requested = {"userinfo": {"name": None}, "id_token": {"email": None}}
    token_data = _code_flow(client, test_user, application, requested)
    refreshed = _token(
        client,
        application,
        {"grant_type": "refresh_token", "refresh_token": token_data["refresh_token"]},
    )

    assert _claims(refreshed["id_token"], oidc_key)["email"] == test_user.email
    assert _userinfo(client, refreshed["access_token"])["name"] == test_user.get_username()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(NON_ROTATING_SETTINGS)
def test_refresh_without_rotation_keeps_claims(oauth2_settings, test_user, application, client, oidc_key):
    requested = {"userinfo": {"name": None}, "id_token": {"email": None}}
    token_data = _code_flow(client, test_user, application, requested)
    refreshed = _token(
        client,
        application,
        {"grant_type": "refresh_token", "refresh_token": token_data["refresh_token"]},
    )

    assert AccessToken.objects.count() == 1
    assert _claims(refreshed["id_token"], oidc_key)["email"] == test_user.email
    assert _userinfo(client, refreshed["access_token"])["name"] == test_user.get_username()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(GRACE_SETTINGS)
def test_refresh_within_grace_period_carries_claims_forward(
    oauth2_settings, test_user, application, client, oidc_key
):
    requested = {"userinfo": {"name": None}, "id_token": {"email": None}}
    token_data = _code_flow(client, test_user, application, requested)
    refresh = {"grant_type": "refresh_token", "refresh_token": token_data["refresh_token"]}
    _token(client, application, refresh)

    # A retry with the superseded refresh token, whose access token is gone.
    retried = _token(client, application, refresh)

    assert _claims(retried["id_token"], oidc_key)["email"] == test_user.email
    assert _userinfo(client, retried["access_token"])["name"] == test_user.get_username()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
@pytest.mark.parametrize(
    "spec,returned",
    [
        ({"value": "test@example.com"}, True),
        ({"value": "other@example.com"}, False),
        ({"values": ["other@example.com", "test@example.com"]}, True),
        ({"values": ["other@example.com"]}, False),
        ({"essential": True}, True),
    ],
)
def test_value_and_values(oauth2_settings, test_user, application, client, oidc_key, spec, returned):
    token_data = _code_flow(
        client, test_user, application, {"id_token": {"email": spec}, "userinfo": {"email": spec}}
    )

    assert ("email" in _claims(token_data["id_token"], oidc_key)) is returned
    assert ("email" in _userinfo(client, token_data["access_token"])) is returned


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(ACR_SETTINGS)
@pytest.mark.parametrize("values", [["urn:example:acr:pwd"], ["urn:example:acr:mfa"]])
def test_acr_values_keep_current_acr(oauth2_settings, test_user, application, client, oidc_key, values):
    # OIDC Core 5.5.1.1: when a requested acr cannot be provided, the session's current
    # acr is returned rather than left out.
    token_data = _code_flow(client, test_user, application, {"id_token": {"acr": {"values": values}}})

    assert _claims(token_data["id_token"], oidc_key)["acr"] == "urn:example:acr:pwd"


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(ACR_SETTINGS)
@pytest.mark.parametrize("response_type", ["code", "id_token", "code id_token"])
@pytest.mark.parametrize("spec", [{"values": ["urn:example:acr:mfa"]}, {"value": "urn:example:acr:mfa"}])
def test_unmet_essential_acr_fails_authorization(
    oauth2_settings, test_user, application, client, response_type, spec
):
    # OIDC Core 5.5.1.1 and Unmet Authentication Requirements 1.0: an essential acr the
    # authentication did not meet fails it with unmet_authentication_requirements.
    application.authorization_grant_type = {
        "code": application.GRANT_AUTHORIZATION_CODE,
        "id_token": application.GRANT_IMPLICIT,
        "code id_token": application.GRANT_OPENID_HYBRID,
    }[response_type]
    application.save()

    params = _authorize(
        client, test_user, application, response_type, {"id_token": {"acr": {"essential": True, **spec}}}
    )

    assert params["error"] == ["unmet_authentication_requirements"]
    assert params["state"] == ["random_state_string"]
    assert "code" not in params
    assert "id_token" not in params
    assert not Grant.objects.exists()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(ACR_SETTINGS)
@pytest.mark.parametrize(
    "spec",
    [
        {"essential": True, "values": ["urn:example:acr:mfa", "urn:example:acr:pwd"]},
        {"essential": True},
        {"essential": False, "values": ["urn:example:acr:mfa"]},
    ],
)
def test_met_or_voluntary_acr_succeeds(oauth2_settings, test_user, application, client, oidc_key, spec):
    token_data = _code_flow(client, test_user, application, {"id_token": {"acr": spec}})

    assert _claims(token_data["id_token"], oidc_key)["acr"] == "urn:example:acr:pwd"


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(ACR_SETTINGS)
@pytest.mark.parametrize("response_type", ["code", "code id_token"])
def test_unmet_essential_acr_fails_skipped_authorization(
    oauth2_settings, test_user, application, client, response_type
):
    application.authorization_grant_type = (
        application.GRANT_AUTHORIZATION_CODE if response_type == "code" else application.GRANT_OPENID_HYBRID
    )
    application.skip_authorization = True
    application.save()
    client.force_login(test_user)
    requested = {"id_token": {"acr": {"essential": True, "values": ["urn:example:acr:mfa"]}}}
    rsp = client.get(
        reverse("oauth2_provider:authorize"), data=_params(application, response_type, requested)
    )

    params = _redirect_params(rsp)
    assert params["error"] == ["unmet_authentication_requirements"]
    assert params["state"] == ["random_state_string"]
    assert not Grant.objects.exists()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(COUNTING_ACR_SETTINGS)
def test_essential_acr_check_reuses_get_acr(oauth2_settings, test_user, hybrid_application, client, oidc_key):
    # The essential check and the ID Token / grant share one get_acr() call.
    CountingAcrValidator.calls = 0
    requested = {"id_token": {"acr": {"essential": True, "values": ["urn:example:acr:pwd"]}}}
    params = _authorize(client, test_user, hybrid_application, "code id_token", requested)

    assert CountingAcrValidator.calls == 1
    assert _claims(params["id_token"][0], oidc_key)["acr"] == "urn:example:acr:pwd"
    assert Grant.objects.get(code=params["code"][0]).acr == "urn:example:acr:pwd"


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_essential_acr_without_acr_support_fails(oauth2_settings, test_user, application, client):
    # The default get_acr() reports no acr, so no requested value can be met.
    params = _authorize(
        client, test_user, application, "code", {"id_token": {"acr": {"essential": True, "values": ["x"]}}}
    )

    assert params["error"] == ["unmet_authentication_requirements"]


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_value_mismatch_drops_scope_claim(oauth2_settings, test_user, application, client, oidc_key):
    # A claim the scopes request is still left out when its requested value does not match.
    token_data = _code_flow(
        client,
        test_user,
        application,
        {"userinfo": {"email": {"value": "other@example.com"}}},
        scope="openid email",
    )

    assert "email" not in _userinfo(client, token_data["access_token"])


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
@pytest.mark.parametrize("key", ["value", "values"])
def test_sub_value_match(oauth2_settings, test_user, application, client, oidc_key, key):
    sub = str(test_user.pk)
    spec = {"value": sub} if key == "value" else {"values": ["nobody", sub]}
    token_data = _code_flow(client, test_user, application, {"id_token": {"sub": spec}})

    assert _claims(token_data["id_token"], oidc_key)["sub"] == sub


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
@pytest.mark.parametrize("response_type", ["code", "id_token"])
@pytest.mark.parametrize("spec", [{"value": "nobody"}, {"values": ["nobody"]}])
def test_sub_value_mismatch_fails_authorization(
    oauth2_settings, test_user, application, client, oidc_key, response_type, spec
):
    # OIDC Core 5.5.1: values is processed equivalently to value.
    application.authorization_grant_type = (
        application.GRANT_AUTHORIZATION_CODE if response_type == "code" else application.GRANT_IMPLICIT
    )
    application.save()

    params = _authorize(client, test_user, application, response_type, {"id_token": {"sub": spec}})

    assert params["error"] == ["login_required"]
    assert "code" not in params
    assert "id_token" not in params
    assert not Grant.objects.exists()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
@pytest.mark.parametrize("spec", [{"value": "nobody"}, {"values": ["nobody"]}])
def test_sub_value_mismatch_fails_skipped_authorization(
    oauth2_settings, test_user, application, client, spec
):
    application.skip_authorization = True
    application.save()
    client.force_login(test_user)
    params = _params(application, "code", {"id_token": {"sub": spec}})
    rsp = client.get(reverse("oauth2_provider:authorize"), data=params)

    assert _redirect_params(rsp)["error"] == ["login_required"]
    assert not Grant.objects.exists()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
@pytest.mark.parametrize("logged_in", [True, False])
def test_client_sent_user_parameter_ignored_by_sub_check(
    oauth2_settings, test_user, application, client, logged_in
):
    # oauthlib exposes a "user" query parameter as request.user; it must not reach the
    # sub check. Anonymous requests reach validation through a malformed max_age.
    params = _params(application, "code", {"id_token": {"sub": {"value": "1"}}}, user="mallory")
    if logged_in:
        client.force_login(test_user)
    else:
        params["max_age"] = "abc"
    rsp = client.get(reverse("oauth2_provider:authorize"), data=params)

    if logged_in:
        assert rsp.status_code == 200
    else:
        assert _redirect_params(rsp)["error"] == ["invalid_request"]


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_empty_claims_treated_as_omitted(oauth2_settings, test_user, application, client, oidc_key):
    client.force_login(test_user)
    rsp = client.get(reverse("oauth2_provider:authorize"), data=_params(application, "code", ""))
    assert rsp.status_code == 200
    assert rsp.context["requested_claims"] == []

    token_data = _code_flow(client, test_user, application, "")
    assert _userinfo(client, token_data["access_token"]) == {"sub": str(test_user.pk)}
    assert AccessToken.objects.get(user=test_user).claims == {}


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_malformed_stored_claims_ignored(oauth2_settings, test_user, application, client, oidc_key):
    # A grant stored while the setting was off holds whatever oauthlib parsed.
    code = _authorize(client, test_user, application, "code", None)["code"][0]
    Grant.objects.filter(code=code).update(claims=json.dumps({"id_token": {"email": {"values": "x"}}}))
    client.logout()
    token_data = _token(
        client,
        application,
        {"grant_type": "authorization_code", "code": code, "redirect_uri": "http://example.org"},
    )

    assert "email" not in _claims(token_data["id_token"], oidc_key)
    assert AccessToken.objects.get(user=test_user).claims == {}


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
@pytest.mark.parametrize(
    "raw",
    [
        '{"userinfo": {"name": {"value": NaN}}}',
        '{"userinfo": {"name": {"value": Infinity}}}',
        '{"id_token": {"name": {"value": -Infinity}}}',
        '{"userinfo": {"name": {"value": 1e999}}}',
        '{"userinfo": {"name": {"values": ["a", NaN]}}}',
        '{"userinfo": {"address": {"value": {"country": [NaN]}}}}',
        # Nested deeper than MAX_VALUE_DEPTH, and deep enough to exhaust recursion.
        '{"userinfo": {"name": {"value": ' + "[" * 17 + "1" + "]" * 17 + "}}}",
        '{"userinfo": {"name": {"values": ' + "[" * 600 + "1" + "]" * 600 + "}}}",
    ],
)
def test_unrepresentable_values_rejected(oauth2_settings, test_user, application, client, raw):
    # Python's JSON parser accepts these, but JSON cannot hold them, so storing the
    # request in AccessToken.claims would fail.
    client.force_login(test_user)
    rsp = client.get(reverse("oauth2_provider:authorize"), data=_params(application, "code", raw))

    assert _redirect_params(rsp)["error"] == ["invalid_request"]


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
@pytest.mark.parametrize(
    "stored",
    [
        '{"userinfo": {"name": {"value": NaN}}}',
        '{"userinfo": {"name": {"value": ' + "[" * 600 + "1" + "]" * 600 + "}}}",
    ],
)
def test_unrepresentable_stored_claims_ignored(
    oauth2_settings, test_user, application, client, oidc_key, stored
):
    # A grant stored before these were refused must not crash token issuance.
    code = _authorize(client, test_user, application, "code", None)["code"][0]
    Grant.objects.filter(code=code).update(claims=stored)
    client.logout()
    token_data = _token(
        client,
        application,
        {"grant_type": "authorization_code", "code": code, "redirect_uri": "http://example.org"},
    )

    assert _userinfo(client, token_data["access_token"]) == {"sub": str(test_user.pk)}
    assert AccessToken.objects.get(user=test_user).claims == {}


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
@pytest.mark.parametrize(
    "claims",
    [
        "[]",
        '"name"',
        {"userinfo": []},
        {"id_token": "name"},
        {"userinfo": {"name": "yes"}},
        {"userinfo": {"name": {"essential": "yes"}}},
        {"id_token": {"name": {"values": "x"}}},
    ],
)
def test_malformed_claims_rejected(oauth2_settings, test_user, application, client, claims):
    client.force_login(test_user)
    rsp = client.get(reverse("oauth2_provider:authorize"), data=_params(application, "code", claims))

    assert _redirect_params(rsp)["error"] == ["invalid_request"]


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_unsupplied_claim_ignored(oauth2_settings, test_user, application, client, oidc_key):
    requested = {"userinfo": {"phone_number": {"essential": True}}, "id_token": {"picture": None}}
    token_data = _code_flow(client, test_user, application, requested)

    assert "picture" not in _claims(token_data["id_token"], oidc_key)
    assert _userinfo(client, token_data["access_token"]) == {"sub": str(test_user.pk)}


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(HOOK_SETTINGS)
def test_get_requested_claims_override_narrows(oauth2_settings, test_user, application, client, oidc_key):
    token_data = _code_flow(client, test_user, application, {"userinfo": {"name": None, "email": None}})

    userinfo = _userinfo(client, token_data["access_token"])
    assert "name" not in userinfo
    assert userinfo["email"] == test_user.email


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(DISABLED_SETTINGS)
def test_disabled_ignores_claims(oauth2_settings, test_user, application, client, oidc_key):
    token_data = _code_flow(
        client, test_user, application, {"userinfo": {"name": None}, "id_token": {"email": None}}
    )

    assert "email" not in _claims(token_data["id_token"], oidc_key)
    assert _userinfo(client, token_data["access_token"]) == {"sub": str(test_user.pk)}
    assert AccessToken.objects.get(user=test_user).claims == {}


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(DISABLED_SETTINGS)
def test_disabled_accepts_malformed_claims(oauth2_settings, test_user, application, client):
    # Behaviour is unchanged while the setting is off: only invalid JSON is refused (by oauthlib).
    client.force_login(test_user)
    rsp = client.get(
        reverse("oauth2_provider:authorize"), data=_params(application, "code", {"userinfo": []})
    )

    assert rsp.status_code == 200
    assert rsp.context["requested_claims"] == []


@pytest.mark.django_db(databases="__all__")
@pytest.mark.parametrize("enabled", [True, False])
def test_discovery_claims_parameter_supported(oauth2_settings, client, enabled):
    oauth2_settings.update(presets.OIDC_SETTINGS_RW)
    oauth2_settings.OIDC_CLAIMS_PARAMETER_ENABLED = enabled

    rsp = client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))

    assert rsp.json()["claims_parameter_supported"] is enabled


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_consent_page_lists_requested_claims(oauth2_settings, test_user, application, client):
    client.force_login(test_user)
    requested = {
        "userinfo": {"name": None},
        "id_token": {"email": None, "name": None, "sub": {"value": str(test_user.pk)}},
    }
    rsp = client.get(reverse("oauth2_provider:authorize"), data=_params(application, "code", requested))

    assert rsp.status_code == 200
    assert rsp.context["requested_claims"] == ["email", "name"]
    content = rsp.content.decode()
    assert "<li>email</li>" in content
    assert "<li>name</li>" in content
    assert rsp.context["form"].initial["claims"] == json.dumps(requested)


def _prior_token(user, application, claims):
    return AccessToken.objects.create(
        user=user,
        application=application,
        token="prior-token",
        scope="openid",
        expires=timezone.now() + timedelta(hours=1),
        claims=claims,
    )


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
@pytest.mark.parametrize(
    "prior_claims,prompted",
    [
        ({}, True),
        ({"userinfo": {"email": None}}, True),
        ({"id_token": {"name": None}}, False),
    ],
)
def test_auto_approval_prompts_for_new_claims(
    oauth2_settings, test_user, application, client, prior_claims, prompted
):
    _prior_token(test_user, application, prior_claims)
    client.force_login(test_user)
    params = _params(application, "code", {"userinfo": {"name": None}}, approval_prompt="auto")
    rsp = client.get(f"{reverse('oauth2_provider:authorize')}?{urlencode(params)}")

    if prompted:
        assert rsp.status_code == 200
        assert rsp.context["requested_claims"] == ["name"]
    else:
        assert "code" in _redirect_params(rsp)


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_auto_approval_without_claims(oauth2_settings, test_user, application, client):
    _prior_token(test_user, application, {})
    client.force_login(test_user)
    params = _params(application, "code", None, approval_prompt="auto")
    rsp = client.get(reverse("oauth2_provider:authorize"), data=params)

    assert "code" in _redirect_params(rsp)


def test_normalize_claims_request():
    assert normalize_claims_request(None) == {}
    assert normalize_claims_request({}) == {}
    assert normalize_claims_request("") == {}
    deepest = json.loads("[" * 16 + "1" + "]" * 16)
    assert normalize_claims_request({"userinfo": {"a": {"value": deepest}}}) == {
        "userinfo": {"a": {"value": deepest}}
    }
    # claims=null parses to None, which is treated as omitted.
    assert normalize_claims_request(json.loads("null")) == {}
    claims = {
        "userinfo": {"name": None, "email": {"essential": True, "purpose": "x"}},
        "id_token": {"acr": {"values": ["a"]}, "sub": {"value": "1"}},
        "verified_claims": {"x": None},
    }
    assert normalize_claims_request(claims) == {
        "userinfo": {"name": None, "email": {"essential": True}},
        "id_token": {"acr": {"values": ["a"]}, "sub": {"value": "1"}},
    }


def test_safe_normalize_claims_request():
    assert safe_normalize_claims_request(None) == {}
    assert safe_normalize_claims_request("x") == {}
    assert safe_normalize_claims_request({"userinfo": []}) == {}
    assert safe_normalize_claims_request({"userinfo": {"a": None}}) == {"userinfo": {"a": None}}


@pytest.mark.parametrize(
    "claims",
    [
        [],
        "name",
        5,
        {"userinfo": None},
        {"userinfo": ["name"]},
        {"id_token": {"name": True}},
        {"id_token": {"name": {"essential": 1}}},
        {"userinfo": {"name": {"values": {"a": 1}}}},
        {"userinfo": {"name": {"value": float("nan")}}},
        {"userinfo": {"name": {"values": [1, float("inf")]}}},
        {"userinfo": {"name": {"value": {"a": [float("-inf")]}}}},
        {"userinfo": {"name": {"value": json.loads("[" * 17 + "1" + "]" * 17)}}},
    ],
)
def test_normalize_claims_request_rejects(claims):
    with pytest.raises(InvalidRequestError):
        normalize_claims_request(claims)


def test_requested_claim_names():
    assert requested_claim_names(None) == set()
    assert requested_claim_names("x") == set()
    assert requested_claim_names({"userinfo": {"a": None}, "id_token": {"b": None, "a": {}}}) == {"a", "b"}
    # sub is always returned, so it is never listed as an extra claim.
    assert requested_claim_names({"id_token": {"sub": {"value": "1"}, "a": None}}) == {"a"}


@pytest.mark.parametrize(
    "value,spec,expected",
    [
        ("a", None, True),
        ("a", {}, True),
        ("a", {"essential": True}, True),
        ("a", {"value": "a"}, True),
        ("a", {"value": "b"}, False),
        ("a", {"values": ["b", "a"]}, True),
        ("a", {"values": ["b"]}, False),
        (True, {"value": True}, True),
        # values is validated on the way in; a stored non-array is ignored.
        ("a@b", {"values": "xa@bx"}, True),
        (True, {"values": "x"}, True),
        # JSON true is not 1, and false is not 0.
        (True, {"value": 1}, False),
        (False, {"value": 0}, False),
        (1, {"value": True}, False),
        (True, {"values": [1, "true"]}, False),
        (False, {"values": [0, False]}, True),
        (1, {"value": 1.0}, True),
        ([True], {"value": [1]}, False),
        ({"a": True}, {"value": {"a": 1}}, False),
        ({"a": [True, "x"]}, {"value": {"a": [True, "x"]}}, True),
        ([1, 2], {"value": [1]}, False),
    ],
)
def test_claim_value_matches(value, spec, expected):
    assert claim_value_matches(value, spec) is expected


# Consent form tampering: the posted claims may only drop entries (partial consent).

ESSENTIAL_MFA = {"id_token": {"acr": {"essential": True, "values": ["urn:example:acr:mfa"]}}}


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(ACR_SETTINGS)
@pytest.mark.parametrize("tampered", ["{}", "null", ""])
def test_tampered_claims_keep_essential_acr_check(oauth2_settings, test_user, application, client, tampered):
    params = _authorize(client, test_user, application, "code", ESSENTIAL_MFA, consented_claims=tampered)

    assert params["error"] == ["unmet_authentication_requirements"]
    assert not Grant.objects.exists()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
@pytest.mark.parametrize("member", ["id_token", "userinfo"])
def test_tampered_claims_keep_sub_check(oauth2_settings, test_user, application, client, member):
    params = _authorize(
        client, test_user, application, "code", {member: {"sub": {"value": "nobody"}}}, consented_claims="{}"
    )

    assert params["error"] == ["login_required"]


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_dropping_a_claim_is_partial_consent(oauth2_settings, test_user, application, client, oidc_key):
    requested = {"userinfo": {"name": None, "email": None}}
    code = _authorize(
        client,
        test_user,
        application,
        "code",
        requested,
        consented_claims=json.dumps({"userinfo": {"email": None}}),
    )["code"][0]
    client.logout()
    token_data = _token(
        client,
        application,
        {"grant_type": "authorization_code", "code": code, "redirect_uri": "http://example.org"},
    )

    userinfo = _userinfo(client, token_data["access_token"])
    assert "name" not in userinfo
    assert userinfo["email"] == test_user.email
    assert AccessToken.objects.get(user=test_user).claims == {"userinfo": {"email": None}}


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
@pytest.mark.parametrize(
    "posted",
    [
        # Adds a claim that was not shown.
        {"userinfo": {"name": None, "email": None}},
        # Adds a member.
        {"userinfo": {"name": None}, "id_token": {"name": None}},
        # Alters a kept claim request.
        {"userinfo": {"name": {"essential": True}}},
        # Not a claims request at all.
        "[1]",
        "not json",
        # Nested deeper than the JSON parser can follow.
        pytest.param("[" * 100000 + "]" * 100000, id="excessive-nesting"),
    ],
)
def test_tampered_claims_refused(oauth2_settings, test_user, application, client, posted):
    url, fields = _consent_form(client, test_user, application, "code", {"userinfo": {"name": None}})
    fields["claims"] = posted if isinstance(posted, str) else json.dumps(posted)
    rsp = client.post(url, data={**fields, "allow": True})

    assert rsp.status_code == 400
    assert rsp.context["error"].error == "invalid_request"
    assert not Grant.objects.exists()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
@pytest.mark.parametrize("signature", [None, "", "forged"])
def test_missing_or_bad_claims_signature_refused(oauth2_settings, test_user, application, client, signature):
    url, fields = _consent_form(client, test_user, application, "code", {"userinfo": {"name": None}})
    fields.pop("claims_request")
    if signature is not None:
        fields["claims_request"] = signature
    rsp = client.post(url, data={**fields, "allow": True})

    assert rsp.status_code == 400
    assert not Grant.objects.exists()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(ACR_SETTINGS)
def test_claims_signature_from_another_request_refused(oauth2_settings, test_user, application, client):
    # A signature issued for a request without the essential acr, swapped into this one.
    _, other = _consent_form(client, test_user, application, "code", None, state="other_state")
    url, fields = _consent_form(client, test_user, application, "code", ESSENTIAL_MFA)
    rsp = client.post(
        url, data={**fields, "claims": "{}", "claims_request": other["claims_request"], "allow": True}
    )

    assert rsp.status_code == 400
    assert not Grant.objects.exists()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(ACR_SETTINGS)
def test_tampered_claims_keep_acr_check_for_pushed_request(oauth2_settings, test_user, application, client):
    # The client pushed the request (PAR), so its claims can't be changed in the browser either.
    oauth2_settings.PKCE_REQUIRED = False
    pushed = post_form(
        client,
        reverse("oauth2_provider:pushed-authorization-request"),
        data=_params(application, "code", ESSENTIAL_MFA),
        **get_basic_auth_header(application.client_id, CLEARTEXT_SECRET),
    )
    assert pushed.status_code == 201, pushed.content
    client.force_login(test_user)
    query = urlencode({"client_id": application.client_id, "request_uri": pushed.json()["request_uri"]})
    url = f"{reverse('oauth2_provider:authorize')}?{query}"
    rsp = client.get(url)
    assert rsp.status_code == 200, rsp.content
    fields = {name: value for name, value in rsp.context["form"].initial.items() if value is not None}
    rsp = client.post(url, data={**fields, "claims": "{}", "allow": True})

    assert _redirect_params(rsp)["error"] == ["unmet_authentication_requirements"]


# Spec and robustness checks on the request itself.


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
@pytest.mark.parametrize("key", ["value", "values"])
def test_userinfo_sub_mismatch_fails_authorization(oauth2_settings, test_user, application, client, key):
    spec = {"value": "nobody"} if key == "value" else {"values": ["nobody"]}
    params = _authorize(client, test_user, application, "code", {"userinfo": {"sub": spec}})

    assert params["error"] == ["login_required"]
    assert not Grant.objects.exists()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_userinfo_sub_mismatch_fails_skipped_authorization(oauth2_settings, test_user, application, client):
    application.skip_authorization = True
    application.save()
    client.force_login(test_user)
    params = _params(application, "code", {"userinfo": {"sub": {"value": "nobody"}}})
    rsp = client.get(reverse("oauth2_provider:authorize"), data=params)

    assert _redirect_params(rsp)["error"] == ["login_required"]


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_userinfo_sub_match_succeeds(oauth2_settings, test_user, application, client, oidc_key):
    token_data = _code_flow(
        client, test_user, application, {"userinfo": {"sub": {"value": str(test_user.pk)}}}
    )

    assert _userinfo(client, token_data["access_token"])["sub"] == str(test_user.pk)


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_userinfo_member_needs_access_token(oauth2_settings, test_user, application, client):
    # OIDC Core 5.5: the userinfo member needs a response type that issues an access token.
    application.authorization_grant_type = application.GRANT_IMPLICIT
    application.save()
    client.force_login(test_user)
    rsp = client.get(
        reverse("oauth2_provider:authorize"),
        data=_params(application, "id_token", {"userinfo": {"name": None}}),
    )

    assert _redirect_params(rsp)["error"] == ["invalid_request"]


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_repeated_claims_parameter_refused(oauth2_settings, test_user, application, client):
    client.force_login(test_user)
    query = urlencode(_params(application, "code", {"userinfo": {"name": None}}))
    rsp = client.get(f"{reverse('oauth2_provider:authorize')}?{query}&claims=%7B%7D")

    assert _redirect_params(rsp)["error"] == ["invalid_request"]


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
@pytest.mark.parametrize(
    "raw",
    [
        '{"userinfo": {"\\ud800": null}}',
        '{"userinfo": {"\\ud800": {"essential": true}}}',
        '{"userinfo": {"name\\u0000": null}}',
        '{"userinfo": {"name": {"value": "a\\u0000"}}}',
        '{"userinfo": {"name": {"values": ["\\udfff"]}}}',
        '{"userinfo": {"address": {"value": {"\\ud800": "x"}}}}',
    ],
)
def test_unstorable_strings_rejected(oauth2_settings, test_user, application, client, raw):
    # Lone surrogates and NUL can't be rendered, sent on, or stored in a jsonb column.
    client.force_login(test_user)
    rsp = client.get(reverse("oauth2_provider:authorize"), data=_params(application, "code", raw))

    assert _redirect_params(rsp)["error"] == ["invalid_request"]


# RFC 6749 section 4.1.2.1: error_description is limited to these characters.
ERROR_DESCRIPTION = re.compile(r"[\x20-\x21\x23-\x5B\x5D-\x7E]*")


@pytest.mark.parametrize(
    "claims",
    [
        [],
        {"userinfo": []},
        {"userinfo": {'é"\\': "x"}},
        {"id_token": {'"name"': {"essential": "x"}}},
        {"id_token": {"n\u00e9": {"values": "x"}}},
        {"userinfo": {"name": {"value": float("nan")}}},
        {"userinfo": {"name": {"value": json.loads("[" * 17 + "1" + "]" * 17)}}},
        {"userinfo": {"\ud800": None}},
    ],
)
def test_error_descriptions_use_allowed_characters(claims):
    with pytest.raises(InvalidRequestError) as raised:
        normalize_claims_request(claims)

    assert ERROR_DESCRIPTION.fullmatch(raised.value.description)


@pytest.mark.django_db(databases="__all__")
def test_access_token_claims_field_empty_and_invalid(test_user, application):
    token = AccessToken.objects.create(
        user=test_user,
        application=application,
        token="t1",
        expires=timezone.now() + timedelta(hours=1),
        claims=None,
    )
    token.refresh_from_db()
    assert token.claims == {}

    token.claims = [1]
    with pytest.raises(ValidationError):
        token.full_clean()
    with pytest.raises(ValidationError):
        token.save()


@pytest.mark.django_db(databases="__all__")
def test_admin_can_clear_access_token_claims(admin_client, test_user, application):
    token = AccessToken.objects.create(
        user=test_user,
        application=application,
        token="t2",
        expires=timezone.now() + timedelta(hours=1),
        claims={"userinfo": {"name": None}},
    )
    url = reverse("admin:oauth2_provider_accesstoken_change", args=[token.pk])
    form = admin_client.get(url).context["adminform"].form
    data = {name: form[name].value() for name in form.fields}
    data = {name: "" if value is None else value for name, value in data.items()}
    data["claims"] = ""
    data["expires_0"], data["expires_1"] = (
        token.expires.strftime("%Y-%m-%d"),
        token.expires.strftime("%H:%M:%S"),
    )
    rsp = admin_client.post(url, data=data)

    assert rsp.status_code == 302, rsp.content
    token.refresh_from_db()
    assert token.claims == {}


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(COUNTING_SETTINGS)
def test_additional_claims_computed_once_per_response(
    oauth2_settings, test_user, application, client, oidc_key
):
    requested = {"id_token": {"name": None, "sub": {"value": str(test_user.pk)}}, "userinfo": {"email": None}}
    code = _authorize(client, test_user, application, "code", requested)["code"][0]
    client.logout()
    CountingClaimsValidator.calls = 0
    token_data = _token(
        client,
        application,
        {"grant_type": "authorization_code", "code": code, "redirect_uri": "http://example.org"},
    )
    assert CountingClaimsValidator.calls == 1

    CountingClaimsValidator.calls = 0
    _userinfo(client, token_data["access_token"])
    assert CountingClaimsValidator.calls == 1


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_consent_page_omits_protocol_claims(oauth2_settings, test_user, application, client):
    requested = {"id_token": {"acr": {"values": ["x"]}, "auth_time": {"essential": True}, "name": None}}
    client.force_login(test_user)
    rsp = client.get(reverse("oauth2_provider:authorize"), data=_params(application, "code", requested))

    assert rsp.context["requested_claims"] == ["name"]


class RequestedOnlyValidator(OAuth2Validator):
    """Computes a claim only when the claims parameter asked for it."""

    def get_additional_claims(self, request):
        wanted = set(self.get_requested_claims(request, "userinfo"))
        return {"name": "Expensive Name"} if "name" in wanted else {}


REQUESTED_ONLY_SETTINGS = deepcopy(SETTINGS)
REQUESTED_ONLY_SETTINGS["OAUTH2_VALIDATOR_CLASS"] = RequestedOnlyValidator


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(REQUESTED_ONLY_SETTINGS)
def test_userinfo_claims_request_visible_to_additional_claims(
    oauth2_settings, test_user, application, client, oidc_key
):
    token_data = _code_flow(client, test_user, application, {"userinfo": {"name": None}})

    assert _userinfo(client, token_data["access_token"])["name"] == "Expensive Name"


def _push(client, application, claims):
    data = {
        "client_id": application.client_id,
        "scope": "openid",
        "redirect_uri": "http://example.org",
        "response_type": "code",
    }
    if claims is not None:
        data["claims"] = json.dumps(claims)
    pushed = post_form(
        client,
        reverse("oauth2_provider:pushed-authorization-request"),
        data=data,
        **get_basic_auth_header(application.client_id, CLEARTEXT_SECRET),
    )
    assert pushed.status_code == 201, pushed.content
    query = urlencode({"client_id": application.client_id, "request_uri": pushed.json()["request_uri"]})
    url = f"{reverse('oauth2_provider:authorize')}?{query}"
    rsp = client.get(url)
    assert rsp.status_code == 200, rsp.content
    return url, {name: value for name, value in rsp.context["form"].initial.items() if value is not None}


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
@pytest.mark.parametrize("claims", [None, {"userinfo": {"name": None}}])
def test_pushed_request_consent_posted_to_bare_url(oauth2_settings, test_user, application, client, claims):
    # A custom consent form may post to the authorize URL without the request_uri query.
    oauth2_settings.PKCE_REQUIRED = False
    client.force_login(test_user)
    _, fields = _push(client, application, claims)
    rsp = client.post(reverse("oauth2_provider:authorize"), data={**fields, "allow": True})

    assert "code" in _redirect_params(rsp)


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
@pytest.mark.parametrize("state", ["abc ", " abc"])
def test_state_with_surrounding_whitespace(oauth2_settings, test_user, application, client, state):
    client.force_login(test_user)
    query = urlencode({**_params(application, "code", None), "state": state})
    url = f"{reverse('oauth2_provider:authorize')}?{query}"
    fields = {
        name: value for name, value in client.get(url).context["form"].initial.items() if value is not None
    }
    rsp = client.post(url, data={**fields, "allow": True})

    assert "code" in _redirect_params(rsp)


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_denial_needs_no_claims_request(oauth2_settings, test_user, application, client):
    url, fields = _consent_form(client, test_user, application, "code", {"userinfo": {"name": None}})
    fields.pop("claims_request")
    # A real consent form carries its CSRF token; the test client doesn't check it.
    rsp = client.post(url, data={**fields, "csrfmiddlewaretoken": "token"})

    assert _redirect_params(rsp)["error"] == ["access_denied"]


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_missing_claims_request_logged(oauth2_settings, test_user, application, client, caplog):
    url, fields = _consent_form(client, test_user, application, "code", None)
    fields.pop("claims_request")
    with caplog.at_level("WARNING", logger="oauth2_provider"):
        rsp = client.post(url, data={**fields, "allow": True})

    assert rsp.status_code == 400
    assert "claims_request" in caplog.text


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_pushed_request_with_repeated_claims_refused(oauth2_settings, application, client):
    url = f"{reverse('oauth2_provider:pushed-authorization-request')}?claims=%7B%7D"
    rsp = post_form(
        client,
        url,
        data={
            "client_id": application.client_id,
            "scope": "openid",
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "claims": json.dumps({"userinfo": {"name": None}}),
        },
        **get_basic_auth_header(application.client_id, CLEARTEXT_SECRET),
    )

    assert rsp.status_code == 400
    assert rsp.json()["error"] == "invalid_request"


@pytest.mark.django_db(databases="__all__")
def test_access_token_claims_key_lookups(test_user, application):
    AccessToken.objects.create(
        user=test_user,
        application=application,
        token="t3",
        expires=timezone.now() + timedelta(hours=1),
        claims={"userinfo": {"name": {"essential": True}}},
    )

    assert AccessToken.objects.filter(claims__userinfo__name__essential=True).count() == 1
    assert AccessToken.objects.filter(claims__has_key="userinfo").count() == 1


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_consent_page_renders_claims_request(oauth2_settings, test_user, application, client):
    client.force_login(test_user)
    rsp = client.get(reverse("oauth2_provider:authorize"), data=_params(application, "code", None))

    assert 'name="claims_request"' in rsp.content.decode()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(ACR_SETTINGS)
@pytest.mark.parametrize(
    "requested",
    [ESSENTIAL_MFA, {"id_token": {"sub": {"value": "nobody"}}}],
    ids=["essential-acr", "sub"],
)
def test_dropping_openid_scope_with_claims_refused(
    oauth2_settings, test_user, application, client, requested
):
    # oauthlib only checks the claims request for an OpenID request.
    url, fields = _consent_form(client, test_user, application, "code", requested, scope="openid email")
    rsp = client.post(url, data={**fields, "scope": "email", "allow": True})

    assert rsp.status_code == 400
    assert not Grant.objects.exists()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(ACR_SETTINGS)
@pytest.mark.parametrize(
    "requested",
    [ESSENTIAL_MFA, {"userinfo": {"sub": {"value": "nobody"}}}],
    ids=["essential-acr", "userinfo-sub"],
)
def test_changing_response_type_with_claims_refused(
    oauth2_settings, test_user, application, client, requested
):
    # Without id_token, oauthlib routes the implicit flow to the OAuth 2.0 grant,
    # which never checks the claims request.
    application.authorization_grant_type = application.GRANT_IMPLICIT
    application.save()
    url, fields = _consent_form(client, test_user, application, "id_token token", requested)
    rsp = client.post(url, data={**fields, "response_type": "token", "allow": True})

    assert rsp.status_code == 400
    assert b"invalid_request" in rsp.content
    assert not AccessToken.objects.exists()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(ACR_SETTINGS)
def test_changing_hybrid_response_type_with_claims_refused(
    oauth2_settings, test_user, hybrid_application, client
):
    url, fields = _consent_form(client, test_user, hybrid_application, "code id_token", ESSENTIAL_MFA)
    rsp = client.post(url, data={**fields, "response_type": "code", "allow": True})

    assert rsp.status_code == 400
    assert b"invalid_request" in rsp.content
    assert not Grant.objects.exists()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_reordered_response_type_allowed(oauth2_settings, test_user, application, client):
    # The order of the values of response_type does not matter (RFC 6749 section 3.1.1).
    application.authorization_grant_type = application.GRANT_IMPLICIT
    application.save()
    requested = {"userinfo": {"name": None}}
    url, fields = _consent_form(client, test_user, application, "id_token token", requested)
    assert fields["response_type"] == "id_token token"
    rsp = client.post(url, data={**fields, "response_type": "token id_token", "allow": True})

    assert "id_token" in _redirect_params(rsp)


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_dropping_openid_scope_without_claims_allowed(oauth2_settings, test_user, application, client):
    url, fields = _consent_form(client, test_user, application, "code", None, scope="openid email")
    rsp = client.post(url, data={**fields, "scope": "email", "allow": True})

    assert "code" in _redirect_params(rsp)


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_declined_claim_covered_by_granted_scope_follows_scope(
    oauth2_settings, test_user, application, client, oidc_key
):
    # Partial consent withdraws the claims request only; the granted email scope
    # still releases email. Declining it means declining the scope.
    code = _authorize(
        client,
        test_user,
        application,
        "code",
        {"userinfo": {"email": None}},
        scope="openid email",
        consented_claims="{}",
    )["code"][0]
    client.logout()
    token_data = _token(
        client,
        application,
        {"grant_type": "authorization_code", "code": code, "redirect_uri": "http://example.org"},
    )

    assert _userinfo(client, token_data["access_token"])["email"] == test_user.email


class SerializedValuesValidator(OAuth2Validator):
    def get_claim_dict(self, request):
        claims = super().get_claim_dict(request)
        claims["sub"] = uuid.UUID("12345678-1234-5678-1234-567812345678")
        return claims

    def get_additional_claims(self, request):
        return {"groups": ("a", "b")}


SERIALIZED_SETTINGS = deepcopy(SETTINGS)
SERIALIZED_SETTINGS["OAUTH2_VALIDATOR_CLASS"] = SerializedValuesValidator


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SERIALIZED_SETTINGS)
def test_values_compared_as_sent(oauth2_settings, test_user, application, client, oidc_key):
    # A UUID sub is sent as its string, a tuple as an array: requests match those.
    requested = {
        "id_token": {
            "sub": {"value": "12345678-1234-5678-1234-567812345678"},
            "groups": {"value": ["a", "b"]},
        }
    }
    token_data = _code_flow(client, test_user, application, requested)

    id_claims = _claims(token_data["id_token"], oidc_key)
    assert id_claims["sub"] == "12345678-1234-5678-1234-567812345678"
    assert id_claims["groups"] == ["a", "b"]


class NoSubValidator(ClaimsValidator):
    def get_claim_dict(self, request):
        claims = super().get_claim_dict(request)
        claims.pop("sub")
        return claims


NO_SUB_SETTINGS = deepcopy(SETTINGS)
NO_SUB_SETTINGS["OAUTH2_VALIDATOR_CLASS"] = NoSubValidator


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(NO_SUB_SETTINGS)
def test_sub_value_without_sub_claim_fails_closed(oauth2_settings, test_user, application, client):
    params = _authorize(client, test_user, application, "code", {"id_token": {"sub": {"value": "1"}}})

    assert params["error"] == ["login_required"]


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
@pytest.mark.parametrize(
    "claims",
    [
        {"userinfo": {"name": {"value": 2**53 + 1}}},
        {"userinfo": {"name": {"values": [-(2**53) - 1]}}},
        {"userinfo": {"name": {"values": [1e16]}}},
        pytest.param({"userinfo": {f"claim{i}": None for i in range(2000)}}, id="too-large"),
    ],
)
def test_unsafe_integers_and_oversized_requests_rejected(
    oauth2_settings, test_user, application, client, claims
):
    client.force_login(test_user)
    rsp = client.get(reverse("oauth2_provider:authorize"), data=_params(application, "code", claims))

    assert _redirect_params(rsp)["error"] == ["invalid_request"]


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_consent_page_lists_only_supplied_claims(oauth2_settings, test_user, application, client):
    # Standard claims and the ones the validator supplies are listed; other names never.
    spoof = "Nothing else. This app is verified by your administrator"
    requested = {"userinfo": {"name": None, spoof: None, "phone_number": None, "x-custom": None}}
    client.force_login(test_user)
    rsp = client.get(reverse("oauth2_provider:authorize"), data=_params(application, "code", requested))

    assert rsp.context["requested_claims"] == ["name", "phone_number"]
    # Only the hidden claims field carries it, escaped, not the visible listing.
    assert f"<li>{spoof}</li>" not in rsp.content.decode()
    assert "<li>name</li>" in rsp.content.decode()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(HOOK_SETTINGS)
def test_consent_page_applies_get_requested_claims(oauth2_settings, test_user, application, client):
    client.force_login(test_user)
    requested = {"userinfo": {"name": None, "email": None}}
    rsp = client.get(reverse("oauth2_provider:authorize"), data=_params(application, "code", requested))

    assert rsp.context["requested_claims"] == ["email"]


class RequestBoundValidator(ClaimsValidator):
    def get_additional_claims(self, request):
        if request.access_token is None and request.grant_type is None and request.code is None:
            raise RuntimeError("needs a token request")
        return super().get_additional_claims(request)


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_consent_listing_falls_back_when_validator_fails(
    oauth2_settings, test_user, application, client, caplog
):
    oauth2_settings.OAUTH2_VALIDATOR_CLASS = RequestBoundValidator
    client.force_login(test_user)
    with caplog.at_level("ERROR", logger="oauth2_provider"):
        rsp = client.get(
            reverse("oauth2_provider:authorize"),
            data=_params(application, "code", {"userinfo": {"name": None, "unknown": None}}),
        )

    assert rsp.context["requested_claims"] == ["name", "unknown"]
    assert "requested claims" in caplog.text


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(SETTINGS)
def test_consent_page_with_raw_brackets_in_query(oauth2_settings, test_user, application, client):
    # Browsers send [ and ] unencoded; the consent listing must not choke on them.
    client.force_login(test_user)
    query = urlencode(_params(application, "code", None, state="[abc]"))
    claims = "%7B%22userinfo%22%3A%7B%22name%22%3A%7B%22values%22%3A[%22a%22]%7D%7D%7D"
    rsp = client.get(f"{reverse('oauth2_provider:authorize')}?{query}&claims={claims}")

    assert rsp.status_code == 200
    assert rsp.context["requested_claims"] == ["name"]


class ContextDependentValidator(OAuth2Validator):
    """Supplies name only for a token or UserInfo request, without raising otherwise."""

    def get_additional_claims(self, request):
        if request.grant_type is None and request.access_token is None:
            return {}
        return {"name": request.user.get_username()}


CONTEXT_SETTINGS = deepcopy(SETTINGS)
CONTEXT_SETTINGS["OAUTH2_VALIDATOR_CLASS"] = ContextDependentValidator


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(CONTEXT_SETTINGS)
def test_consent_page_lists_standard_claims_whatever_the_context(
    oauth2_settings, test_user, application, client
):
    client.force_login(test_user)
    rsp = client.get(
        reverse("oauth2_provider:authorize"), data=_params(application, "code", {"userinfo": {"name": None}})
    )

    assert rsp.context["requested_claims"] == ["name"]


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(COUNTING_SETTINGS)
def test_skipped_consent_does_not_compute_listing(oauth2_settings, test_user, application, client):
    application.skip_authorization = True
    application.save()
    client.force_login(test_user)
    CountingClaimsValidator.calls = 0
    rsp = client.get(
        reverse("oauth2_provider:authorize"), data=_params(application, "code", {"userinfo": {"name": None}})
    )

    assert "code" in _redirect_params(rsp)
    assert CountingClaimsValidator.calls == 0


class ClientIdHookValidator(ClaimsValidator):
    def get_requested_claims(self, request, target):
        requested = super().get_requested_claims(request, target)
        return requested if request.client_id == request.client.client_id else {}


CLIENT_ID_HOOK_SETTINGS = deepcopy(SETTINGS)
CLIENT_ID_HOOK_SETTINGS["OAUTH2_VALIDATOR_CLASS"] = ClientIdHookValidator


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(CLIENT_ID_HOOK_SETTINGS)
def test_consent_listing_hook_sees_client_id(oauth2_settings, test_user, application, client):
    client.force_login(test_user)
    rsp = client.get(
        reverse("oauth2_provider:authorize"), data=_params(application, "code", {"userinfo": {"name": None}})
    )

    assert rsp.context["requested_claims"] == ["name"]


class RedirectUriHookValidator(ClaimsValidator):
    """Releases requested claims only to one redirect URI, and records the user it saw.

    A test device for the request the consent listing passes the hooks: redirect_uri
    is not on every request claims are released from, so real hooks shouldn't key on it.
    """

    users = []

    def get_requested_claims(self, request, target):
        RedirectUriHookValidator.users.append(request.user)
        requested = super().get_requested_claims(request, target)
        return requested if request.redirect_uri == "http://example.org" else {}


REDIRECT_URI_HOOK_SETTINGS = deepcopy(SETTINGS)
REDIRECT_URI_HOOK_SETTINGS["OAUTH2_VALIDATOR_CLASS"] = RedirectUriHookValidator


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(REDIRECT_URI_HOOK_SETTINGS)
def test_consent_listing_hook_sees_authorization_request(
    oauth2_settings, test_user, application, client, oidc_key
):
    # The listing must show what issuance releases, so the hook sees the same request
    # parameters as at the authorization endpoint.
    client.force_login(test_user)
    rsp = client.get(
        reverse("oauth2_provider:authorize"), data=_params(application, "code", {"id_token": {"email": None}})
    )
    assert rsp.context["requested_claims"] == ["email"]

    token_data = _code_flow(client, test_user, application, {"id_token": {"email": None}})
    assert _claims(token_data["id_token"], oidc_key)["email"] == test_user.email


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(REDIRECT_URI_HOOK_SETTINGS)
def test_consent_listing_ignores_client_sent_user(oauth2_settings, test_user, application, client):
    client.force_login(test_user)
    RedirectUriHookValidator.users = []
    rsp = client.get(
        reverse("oauth2_provider:authorize"),
        data=_params(application, "code", {"id_token": {"email": None}}, user="mallory"),
    )

    assert rsp.context["requested_claims"] == ["email"]
    assert RedirectUriHookValidator.users
    assert all(user == test_user for user in RedirectUriHookValidator.users)


class RefreshHookValidator(ClaimsValidator):
    def get_requested_claims(self, request, target):
        if request.grant_type == "refresh_token":
            return {}
        return super().get_requested_claims(request, target)


REFRESH_HOOK_SETTINGS = deepcopy(SETTINGS)
REFRESH_HOOK_SETTINGS["OAUTH2_VALIDATOR_CLASS"] = RefreshHookValidator


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(REFRESH_HOOK_SETTINGS)
def test_consent_listing_ignores_client_sent_parameters(oauth2_settings, test_user, application, client):
    # Only the parameters oauthlib validated reach the hooks: a client can't hide a
    # claim from the consent page by sending a token-endpoint parameter.
    client.force_login(test_user)
    rsp = client.get(
        reverse("oauth2_provider:authorize"),
        data=_params(application, "code", {"id_token": {"email": None}}, grant_type="refresh_token"),
    )

    assert rsp.context["requested_claims"] == ["email"]
