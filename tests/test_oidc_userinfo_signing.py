"""Signed UserInfo responses (OpenID Connect Core 1.0 section 5.3.2)."""

import json
import logging
from datetime import timedelta

import pytest
from django.contrib.auth import get_user
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone
from jwcrypto import jwk, jwt
from oauthlib.openid import Server as OpenIDServer

from oauth2_provider.authorization_server.oidc.client_metadata import (
    UnsupportedClientMetadataError,
    userinfo_signed_response_alg,
    userinfo_signing_algorithm,
)
from oauth2_provider.authorization_server.oidc.server import Server, userinfo_signing_available
from oauth2_provider.authorization_server.oidc.views import _load_id_token
from oauth2_provider.core.checks import validate_userinfo_signing_server
from oauth2_provider.models import get_application_model
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauth2_provider.resource_server import ProtectedResourceView

from . import presets


Application = get_application_model()

ISSUER = presets.OIDC_SETTINGS_RW["OIDC_ISS_ENDPOINT"]


@pytest.fixture
def signed_userinfo_tokens(oidc_tokens):
    """Tokens for a client that registered userinfo_signed_response_alg=RS256."""
    application = oidc_tokens.application
    application.userinfo_signed_response_alg = Application.RS256_ALGORITHM
    application.save()
    return oidc_tokens


def _get_userinfo(client, access_token, method="get", **extra):
    return getattr(client, method)(
        reverse("oauth2_provider:user-info"),
        HTTP_AUTHORIZATION=f"Bearer {access_token}",
        **extra,
    )


def _verify(client, token):
    """Verify *token* against the published JWKS and return (header, claims)."""
    jwks = jwk.JWKSet.from_json(client.get(reverse("oauth2_provider:jwks-info")).content)
    verified = jwt.JWT(key=jwks, jwt=token)
    return json.loads(verified.header), json.loads(verified.claims)


@pytest.mark.django_db(databases="__all__")
def test_userinfo_is_json_without_a_registered_signing_algorithm(oidc_tokens, client):
    rsp = _get_userinfo(client, oidc_tokens.access_token)
    assert rsp.status_code == 200
    assert rsp["Content-Type"] == "application/json"
    data = rsp.json()
    assert data == {"sub": str(oidc_tokens.user.pk)}


@pytest.mark.django_db(databases="__all__")
@pytest.mark.parametrize("method", ["get", "post"])
def test_userinfo_is_a_signed_jwt_for_a_client_that_registered_rs256(
    signed_userinfo_tokens, client, oidc_key, method
):
    before = int(timezone.now().timestamp())
    rsp = _get_userinfo(client, signed_userinfo_tokens.access_token, method=method)
    assert rsp.status_code == 200
    assert rsp["Content-Type"] == "application/jwt"

    header, claims = _verify(client, rsp.content.decode())
    assert header == {"typ": "JWT", "alg": "RS256", "kid": oidc_key.thumbprint()}
    assert claims["sub"] == str(signed_userinfo_tokens.user.pk)
    # Section 5.3.2: a signed response SHOULD contain iss and aud.
    assert claims["iss"] == ISSUER
    assert claims["aud"] == signed_userinfo_tokens.application.client_id
    assert before <= claims["iat"] <= int(timezone.now().timestamp())
    assert "exp" not in claims


@pytest.mark.django_db(databases="__all__")
def test_signed_userinfo_carries_exp_when_a_lifetime_is_configured(signed_userinfo_tokens, client):
    signed_userinfo_tokens.oauth2_settings.OIDC_USERINFO_JWT_EXPIRE_SECONDS = 300
    rsp = _get_userinfo(client, signed_userinfo_tokens.access_token)
    _, claims = _verify(client, rsp.content.decode())
    assert claims["exp"] == claims["iat"] + 300


@pytest.mark.django_db(databases="__all__")
def test_signed_userinfo_exp_accepts_a_timedelta(signed_userinfo_tokens, client):
    signed_userinfo_tokens.oauth2_settings.OIDC_USERINFO_JWT_EXPIRE_SECONDS = timedelta(
        minutes=5, seconds=0.5
    )
    rsp = _get_userinfo(client, signed_userinfo_tokens.access_token)
    _, claims = _verify(client, rsp.content.decode())
    assert claims["exp"] == claims["iat"] + 300


@pytest.mark.django_db(databases="__all__")
@pytest.mark.parametrize("value", [0, -1, "300", True])
def test_signed_userinfo_rejects_an_invalid_lifetime(signed_userinfo_tokens, client, value):
    signed_userinfo_tokens.oauth2_settings.OIDC_USERINFO_JWT_EXPIRE_SECONDS = value
    with pytest.raises(ImproperlyConfigured, match="OIDC_USERINFO_JWT_EXPIRE_SECONDS"):
        _get_userinfo(client, signed_userinfo_tokens.access_token)


@pytest.mark.django_db(databases="__all__")
def test_signed_userinfo_is_signed_with_the_server_key_for_an_hs256_id_token_client(
    signed_userinfo_tokens, client, oidc_key
):
    # The client's ID Token algorithm does not choose the UserInfo signing key.
    application = signed_userinfo_tokens.application
    application.algorithm = Application.HS256_ALGORITHM
    application.save()
    rsp = _get_userinfo(client, signed_userinfo_tokens.access_token)
    header, _ = _verify(client, rsp.content.decode())
    assert header["alg"] == "RS256"
    assert header["kid"] == oidc_key.thumbprint()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.parametrize("cause", ["key-removed", "no-oidc-support", "unsupported-stored-value"])
def test_userinfo_that_cannot_be_signed_is_json(signed_userinfo_tokens, client, caplog, cause):
    # clean() refuses all three, so the key was removed after the client opted in, or the
    # row was saved without validation. Registration responses then report JSON too.
    if cause == "key-removed":
        signed_userinfo_tokens.oauth2_settings.OIDC_RSA_PRIVATE_KEY = ""
    elif cause == "no-oidc-support":
        Application.objects.filter(pk=signed_userinfo_tokens.application.pk).update(
            algorithm=Application.NO_ALGORITHM
        )
    else:
        Application.objects.filter(pk=signed_userinfo_tokens.application.pk).update(
            userinfo_signed_response_alg="HS256"
        )
    with caplog.at_level(logging.WARNING, logger="oauth2_provider"):
        rsp = _get_userinfo(client, signed_userinfo_tokens.access_token)
    assert "is returned unsigned" in caplog.text
    assert rsp.status_code == 200
    assert rsp["Content-Type"] == "application/json"
    assert rsp.json()["sub"] == str(signed_userinfo_tokens.user.pk)
    application = Application.objects.get(pk=signed_userinfo_tokens.application.pk)
    assert userinfo_signed_response_alg(application) is None


@pytest.mark.django_db(databases="__all__")
def test_signed_userinfo_includes_claims_added_by_a_get_userinfo_claims_override(
    signed_userinfo_tokens, client
):
    # The override style documented in docs/oidc.rst keeps working: the claims
    # are still a dict when get_userinfo_claims returns, and are signed afterwards.
    class CustomValidator(OAuth2Validator):
        def get_userinfo_claims(self, request):
            claims = super().get_userinfo_claims(request)
            claims["color_scheme"] = "dark"
            return claims

    signed_userinfo_tokens.oauth2_settings.OAUTH2_VALIDATOR_CLASS = CustomValidator
    rsp = _get_userinfo(client, signed_userinfo_tokens.access_token)
    assert rsp["Content-Type"] == "application/jwt"
    _, claims = _verify(client, rsp.content.decode())
    assert claims["color_scheme"] == "dark"


@pytest.mark.django_db(databases="__all__")
def test_signed_userinfo_iss_and_aud_cannot_be_overridden_by_user_claims(signed_userinfo_tokens, client):
    class CustomValidator(OAuth2Validator):
        oidc_claim_scope = None

        def get_additional_claims(self, request):
            return {"iss": "https://attacker.example", "aud": "someone-else"}

    signed_userinfo_tokens.oauth2_settings.OAUTH2_VALIDATOR_CLASS = CustomValidator
    rsp = _get_userinfo(client, signed_userinfo_tokens.access_token)
    _, claims = _verify(client, rsp.content.decode())
    assert claims["iss"] == ISSUER
    assert claims["aud"] == signed_userinfo_tokens.application.client_id


@pytest.mark.django_db(databases="__all__")
def test_signed_userinfo_keeps_the_cors_header(signed_userinfo_tokens, client):
    rsp = _get_userinfo(client, signed_userinfo_tokens.access_token, HTTP_ORIGIN="http://example.org")
    assert rsp["Content-Type"] == "application/jwt"
    assert rsp["Access-Control-Allow-Origin"] == "*"


@pytest.mark.django_db(databases="__all__")
def test_signed_userinfo_still_rejects_a_bad_token(signed_userinfo_tokens, client):
    rsp = _get_userinfo(client, "not-a-real-token")
    assert rsp.status_code == 401


@pytest.mark.django_db(databases="__all__")
def test_finalize_userinfo_response_override_shapes_the_response(signed_userinfo_tokens, client):
    class CustomValidator(OAuth2Validator):
        def finalize_userinfo_response(self, claims, request):
            return super().finalize_userinfo_response({**claims, "signed_only": True}, request)

    signed_userinfo_tokens.oauth2_settings.OAUTH2_VALIDATOR_CLASS = CustomValidator
    rsp = _get_userinfo(client, signed_userinfo_tokens.access_token)
    _, claims = _verify(client, rsp.content.decode())
    assert claims["signed_only"] is True


@pytest.mark.django_db(databases="__all__")
def test_userinfo_without_sub_is_a_server_error(signed_userinfo_tokens, client):
    class CustomValidator(OAuth2Validator):
        def get_userinfo_claims(self, request):
            return {"name": "no subject"}

    signed_userinfo_tokens.oauth2_settings.OAUTH2_VALIDATOR_CLASS = CustomValidator
    rsp = _get_userinfo(client, signed_userinfo_tokens.access_token)
    assert rsp.status_code == 500


@pytest.mark.django_db(databases="__all__")
def test_userinfo_claims_already_a_jwt_are_returned_unchanged(signed_userinfo_tokens, client):
    # oauthlib lets get_userinfo_claims return a JWT itself; it is not signed again.
    class CustomValidator(OAuth2Validator):
        def get_userinfo_claims(self, request):
            return "already.a.jwt"

    signed_userinfo_tokens.oauth2_settings.OAUTH2_VALIDATOR_CLASS = CustomValidator
    rsp = _get_userinfo(client, signed_userinfo_tokens.access_token)
    assert rsp["Content-Type"] == "application/jwt"
    assert rsp.content == b"already.a.jwt"


@pytest.mark.django_db(databases="__all__")
def test_a_plain_oauthlib_server_returns_json_even_to_a_signing_client(signed_userinfo_tokens, client):
    # The documented consequence of an OIDC_SERVER_CLASS that does not derive from ours.
    signed_userinfo_tokens.oauth2_settings.OAUTH2_SERVER_CLASS = OpenIDServer
    rsp = _get_userinfo(client, signed_userinfo_tokens.access_token)
    assert rsp["Content-Type"] == "application/json"
    assert rsp.json()["sub"] == str(signed_userinfo_tokens.user.pk)


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_default_oidc_server_class_signs_userinfo(oauth2_settings):
    assert oauth2_settings.OAUTH2_SERVER_CLASS is Server


# A signed UserInfo response is a JWT signed with the OP key whose aud is the
# client, like an ID Token, but it is not one: it has no jti and no stored
# IDToken. It must be refused wherever an ID Token is accepted, not crash.


class _ResourceView(ProtectedResourceView):
    def get(self, request, *args, **kwargs):
        return HttpResponse("protected")


@pytest.mark.django_db(databases="__all__")
def test_signed_userinfo_is_not_accepted_as_an_id_token_hint(signed_userinfo_tokens, logged_in_client):
    signed = _get_userinfo(logged_in_client, signed_userinfo_tokens.access_token).content.decode()
    signed_userinfo_tokens.oauth2_settings.update(presets.OIDC_SETTINGS_RP_LOGOUT)

    assert _load_id_token(signed) == (None, None)
    rsp = logged_in_client.get(reverse("oauth2_provider:rp-initiated-logout"), data={"id_token_hint": signed})
    assert rsp.status_code == 400
    assert get_user(logged_in_client).is_authenticated


@pytest.mark.django_db(databases="__all__")
def test_signed_userinfo_is_not_accepted_as_a_bearer_id_token(signed_userinfo_tokens, client):
    signed = _get_userinfo(client, signed_userinfo_tokens.access_token).content.decode()

    assert OAuth2Validator()._load_id_token(signed) is None
    request = RequestFactory().get("/fake-resource", HTTP_AUTHORIZATION=f"Bearer {signed}")
    rsp = _ResourceView.as_view()(request)
    assert rsp.status_code == 403


@pytest.mark.django_db(databases="__all__")
def test_a_jti_user_claim_is_left_out_of_signed_userinfo(signed_userinfo_tokens, logged_in_client):
    # jti is what tells an ID Token apart: a signed UserInfo response never carries one,
    # even when the claims do, so it can still not pass for an ID Token.
    class CustomValidator(OAuth2Validator):
        oidc_claim_scope = None

        def get_additional_claims(self, request):
            return {"jti": "chosen-by-the-claims"}

    signed_userinfo_tokens.oauth2_settings.OAUTH2_VALIDATOR_CLASS = CustomValidator
    signed = _get_userinfo(logged_in_client, signed_userinfo_tokens.access_token).content.decode()
    _, claims = _verify(logged_in_client, signed)
    assert "jti" not in claims

    signed_userinfo_tokens.oauth2_settings.update(presets.OIDC_SETTINGS_RP_LOGOUT)
    assert _load_id_token(signed) == (None, None)


@pytest.mark.django_db(databases="__all__")
def test_exp_and_nbf_user_claims_are_left_out_of_signed_userinfo(signed_userinfo_tokens, client):
    # None for OIDC_USERINFO_JWT_EXPIRE_SECONDS means no exp: the claims cannot set one.
    class CustomValidator(OAuth2Validator):
        oidc_claim_scope = None

        def get_additional_claims(self, request):
            return {"exp": 1, "nbf": 4102444800, "account_expiry": 1}

    signed_userinfo_tokens.oauth2_settings.OAUTH2_VALIDATOR_CLASS = CustomValidator
    rsp = _get_userinfo(client, signed_userinfo_tokens.access_token)
    _, claims = _verify(client, rsp.content.decode())
    assert "exp" not in claims
    assert "nbf" not in claims
    assert claims["account_expiry"] == 1


@pytest.mark.django_db(databases="__all__")
@pytest.mark.parametrize("claims", [None, ["sub"]], ids=["no-claims", "unknown-type"])
def test_userinfo_claims_that_are_neither_a_dict_nor_a_jwt_are_a_server_error(oidc_tokens, client, claims):
    class CustomValidator(OAuth2Validator):
        def get_userinfo_claims(self, request):
            return claims

    oidc_tokens.oauth2_settings.OAUTH2_VALIDATOR_CLASS = CustomValidator
    rsp = _get_userinfo(client, oidc_tokens.access_token)
    assert rsp.status_code == 500


@pytest.mark.django_db(databases="__all__")
def test_a_validator_without_the_hook_returns_json(signed_userinfo_tokens, client):
    # The server keeps oauthlib's behaviour for a validator without a callable
    # finalize_userinfo_response, so signing must be neither advertised nor accepted.
    class CustomValidator(OAuth2Validator):
        finalize_userinfo_response = None

    signed_userinfo_tokens.oauth2_settings.OAUTH2_VALIDATOR_CLASS = CustomValidator
    rsp = _get_userinfo(client, signed_userinfo_tokens.access_token)
    assert rsp["Content-Type"] == "application/json"
    assert rsp.json()["sub"] == str(signed_userinfo_tokens.user.pk)

    assert userinfo_signing_available() is False
    discovery = client.get(reverse("oauth2_provider:oidc-connect-discovery-info")).json()
    assert "userinfo_signing_alg_values_supported" not in discovery
    with pytest.raises(UnsupportedClientMetadataError, match="does not sign UserInfo responses"):
        userinfo_signing_algorithm({"userinfo_signed_response_alg": "RS256"})
    assert userinfo_signed_response_alg(signed_userinfo_tokens.application) is None
    assert [m.id for m in validate_userinfo_signing_server(None)] == ["oauth2_provider.I001"]


@pytest.mark.django_db(databases="__all__")
def test_a_finalize_override_that_drops_sub_is_a_server_error(oidc_tokens, client):
    class CustomValidator(OAuth2Validator):
        def finalize_userinfo_response(self, claims, request):
            return {k: v for k, v in claims.items() if k != "sub"}

    oidc_tokens.oauth2_settings.OAUTH2_VALIDATOR_CLASS = CustomValidator
    rsp = _get_userinfo(client, oidc_tokens.access_token)
    assert rsp.status_code == 500


@pytest.mark.django_db(databases="__all__")
@pytest.mark.parametrize(
    "overrides, expected",
    [
        pytest.param({}, True, id="default"),
        pytest.param({"OIDC_SERVER_CLASS": "oauthlib.openid.Server"}, False, id="plain-oauthlib-server"),
        pytest.param(
            {"OAUTH2_VALIDATOR_CLASS": "oauthlib.openid.RequestValidator"}, False, id="validator-without-hook"
        ),
        pytest.param({"OIDC_RSA_PRIVATE_KEY": ""}, False, id="no-rsa-key"),
        pytest.param({"OIDC_ENABLED": False}, False, id="oidc-disabled"),
        pytest.param(
            {"OIDC_SERVER_CLASS": "tests.does_not_exist.Server"}, False, id="unimportable-server-class"
        ),
    ],
)
def test_userinfo_signing_available(oauth2_settings, overrides, expected):
    oauth2_settings.update({**presets.OIDC_SETTINGS_RW, **overrides})
    assert userinfo_signing_available() is expected


@pytest.mark.django_db(databases="__all__")
def test_signing_is_neither_advertised_nor_registrable_when_the_server_cannot_sign(oauth2_settings, client):
    # A client is never promised a signed response the endpoint would send as JSON.
    oauth2_settings.update({**presets.OIDC_SETTINGS_RW, "OIDC_SERVER_CLASS": "oauthlib.openid.Server"})
    discovery = client.get(reverse("oauth2_provider:oidc-connect-discovery-info")).json()
    assert "userinfo_signing_alg_values_supported" not in discovery
    with pytest.raises(UnsupportedClientMetadataError, match="does not sign UserInfo responses"):
        userinfo_signing_algorithm({"userinfo_signed_response_alg": "RS256"})
