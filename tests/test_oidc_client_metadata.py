"""Unit tests for the OpenID Connect client metadata helpers shared by DCR and CIMD."""

import pytest

from oauth2_provider.authorization_server.oidc.client_metadata import (
    UnsupportedClientMetadataError,
    id_token_signing_algorithm,
)
from oauth2_provider.models import get_application_model

from . import presets


Application = get_application_model()

HS256_REQUEST = {"id_token_signed_response_alg": "HS256"}

# A client an administrator-set HS256 is kept for, as the DCR view derives it.
ELIGIBLE_CLIENT = {
    "client_type": Application.CLIENT_CONFIDENTIAL,
    "token_endpoint_auth_method": Application.TOKEN_AUTH_METHOD_CLIENT_SECRET_JWT,
    "authorization_grant_type": Application.GRANT_AUTHORIZATION_CODE,
    "client_secret": "s" * 32,
}


@pytest.mark.parametrize(
    "server",
    [
        pytest.param("oidc-rs256-key", marks=pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)),
        pytest.param("oidc-no-rsa-key", marks=pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_HS256_ONLY)),
        pytest.param(
            "oidc-disabled",
            marks=pytest.mark.oauth2_settings({**presets.OIDC_SETTINGS_RW, "OIDC_ENABLED": False}),
        ),
    ],
)
@pytest.mark.parametrize(
    "client",
    [
        pytest.param(ELIGIBLE_CLIENT, id="client_secret_jwt"),
        pytest.param({}, id="public-or-cimd"),
    ],
)
@pytest.mark.parametrize("current", [Application.NO_ALGORITHM, Application.RS256_ALGORITHM])
def test_new_hs256_is_refused(oauth2_settings, server, client, current):
    # HS256 is not offered to self-registered clients, even an otherwise
    # eligible client_secret_jwt one, on registration or on an update, whatever
    # the server can sign with. The advice follows what the server can do:
    # RS256 when it can sign with it, otherwise omitting the parameter.
    with pytest.raises(UnsupportedClientMetadataError) as excinfo:
        id_token_signing_algorithm(HS256_REQUEST, current=current, **client)
    message = str(excinfo.value)
    assert message.startswith("Unsupported id_token_signed_response_alg: 'HS256'.")
    assert "not offered to self-registered clients" in message
    if server == "oidc-rs256-key":
        assert "use RS256" in message
    else:
        assert "use RS256" not in message
        assert "omit id_token_signed_response_alg" in message


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
@pytest.mark.parametrize(
    "client",
    [
        pytest.param(ELIGIBLE_CLIENT, id="client_secret_jwt"),
        pytest.param({}, id="public"),
    ],
)
def test_unsupported_value_lists_rs256(oauth2_settings, client):
    with pytest.raises(UnsupportedClientMetadataError) as excinfo:
        id_token_signing_algorithm({"id_token_signed_response_alg": "ES256"}, **client)
    assert str(excinfo.value).endswith("Supported values: RS256")


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_HS256_ONLY)
@pytest.mark.parametrize(
    "client_secret",
    [
        pytest.param("s" * 32, id="32-ascii"),
        # 16 characters, but 32 octets in UTF-8: the minimum counts octets.
        pytest.param("é" * 16, id="32-octets-16-characters"),
    ],
)
def test_echoed_hs256_accepts_client_secret_of_32_octets(oauth2_settings, client_secret):
    client = {**ELIGIBLE_CLIENT, "client_secret": client_secret}
    assert (
        id_token_signing_algorithm(HS256_REQUEST, current=Application.HS256_ALGORITHM, **client)
        == Application.HS256_ALGORITHM
    )


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_HS256_ONLY)
@pytest.mark.parametrize(
    "client_secret",
    [
        pytest.param("", id="empty"),
        pytest.param("s" * 31, id="31-ascii"),
        pytest.param("é" * 15 + "s", id="31-octets"),
    ],
)
def test_echoed_hs256_refuses_client_secret_under_32_octets(oauth2_settings, client_secret):
    client = {**ELIGIBLE_CLIENT, "client_secret": client_secret}
    with pytest.raises(UnsupportedClientMetadataError, match="at least 32 octets"):
        id_token_signing_algorithm(HS256_REQUEST, current=Application.HS256_ALGORITHM, **client)


@pytest.mark.oauth2_settings({**presets.OIDC_SETTINGS_RW, "OIDC_ENABLED": False})
def test_echoed_hs256_is_kept_without_oidc_for_an_eligible_client(oauth2_settings):
    # RFC 7592 section 2.2: a PUT sends back the value a previous response
    # reported, so an administrator's HS256 survives an update with OIDC off.
    assert (
        id_token_signing_algorithm(HS256_REQUEST, current=Application.HS256_ALGORITHM, **ELIGIBLE_CLIENT)
        == Application.HS256_ALGORITHM
    )


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
@pytest.mark.parametrize(
    "client, reason",
    [
        pytest.param({}, "public client", id="public"),
        pytest.param(
            {
                **ELIGIBLE_CLIENT,
                "token_endpoint_auth_method": Application.TOKEN_AUTH_METHOD_CLIENT_SECRET_BASIC,
            },
            "client_secret_jwt",
            id="client_secret_basic",
        ),
        pytest.param(
            {**ELIGIBLE_CLIENT, "authorization_grant_type": Application.GRANT_IMPLICIT},
            "implicit",
            id="implicit",
        ),
        pytest.param(
            {**ELIGIBLE_CLIENT, "authorization_grant_type": Application.GRANT_OPENID_HYBRID},
            "hybrid",
            id="hybrid",
        ),
    ],
)
def test_echoed_hs256_is_refused_for_an_ineligible_client(oauth2_settings, client, reason):
    with pytest.raises(UnsupportedClientMetadataError) as excinfo:
        id_token_signing_algorithm(HS256_REQUEST, current=Application.HS256_ALGORITHM, **client)
    message = str(excinfo.value)
    assert message.startswith("id_token_signed_response_alg 'HS256' is not available for this client: ")
    assert reason in message


# A value a swapped application model may let an administrator set, outside
# SUPPORTED_ID_TOKEN_ALGS and other than HS256.
OTHER_ADMIN_ALG = "ES256"


@pytest.mark.oauth2_settings({**presets.OIDC_SETTINGS_RW, "OIDC_ENABLED": False})
def test_echoed_administrator_set_algorithm_is_kept_for_an_eligible_client(oauth2_settings):
    # As on master, any echoed value registration would not grant is kept, not
    # only HS256; the 32-octet secret rule is HS256's own, so it does not apply.
    client = {**ELIGIBLE_CLIENT, "client_secret": ""}
    assert (
        id_token_signing_algorithm(
            {"id_token_signed_response_alg": OTHER_ADMIN_ALG}, current=OTHER_ADMIN_ALG, **client
        )
        == OTHER_ADMIN_ALG
    )


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
@pytest.mark.parametrize(
    "client",
    [
        pytest.param({}, id="public"),
        pytest.param(
            {
                **ELIGIBLE_CLIENT,
                "token_endpoint_auth_method": Application.TOKEN_AUTH_METHOD_CLIENT_SECRET_BASIC,
            },
            id="client_secret_basic",
        ),
        pytest.param(
            {**ELIGIBLE_CLIENT, "authorization_grant_type": Application.GRANT_IMPLICIT}, id="implicit"
        ),
        pytest.param(
            {**ELIGIBLE_CLIENT, "authorization_grant_type": Application.GRANT_OPENID_HYBRID}, id="hybrid"
        ),
    ],
)
def test_echoed_administrator_set_algorithm_is_refused_for_an_ineligible_client(oauth2_settings, client):
    with pytest.raises(UnsupportedClientMetadataError) as excinfo:
        id_token_signing_algorithm(
            {"id_token_signed_response_alg": OTHER_ADMIN_ALG}, current=OTHER_ADMIN_ALG, **client
        )
    message = str(excinfo.value)
    assert message.startswith("id_token_signed_response_alg 'ES256' is not available for this client: ")
    assert "client_secret_jwt" in message
    assert "implicit or hybrid" in message


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_unechoed_administrator_set_algorithm_is_refused(oauth2_settings):
    # Only an echo keeps it: asking for a value the application does not have
    # is refused like any other unsupported value.
    with pytest.raises(UnsupportedClientMetadataError, match="Supported values: RS256"):
        id_token_signing_algorithm(
            {"id_token_signed_response_alg": OTHER_ADMIN_ALG},
            current=Application.HS256_ALGORITHM,
            **ELIGIBLE_CLIENT,
        )
