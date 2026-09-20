"""
Tests for OAuth Client ID Metadata Document (CIMD) support.

draft-ietf-oauth-client-id-metadata-document
"""

import json
import logging
import socket
import time
from datetime import timedelta
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import pytest
import urllib3
from django.core.cache import cache
from django.db import IntegrityError
from django.urls import reverse
from django.utils import timezone
from jwcrypto import jwk, jwt
from oauthlib.common import Request as OAuthlibRequest

from oauth2_provider.authorization_server import cimd
from oauth2_provider.authorization_server.cimd import (
    CIMDError,
    HostAllowlistCIMDPermission,
    SafeMetadataFetcher,
    _build_application_kwargs,
    _effective_max_age,
    _ip_is_public,
    _resolve_and_validate,
    _resolve_auth_method,
    _resolve_grant_type,
    _validate_client_id_url,
    is_cimd_client_id,
    refresh_if_stale,
    resolve_cimd_application,
)
from oauth2_provider.models import get_application_model

from . import presets
from .utils import post_form


Application = get_application_model()

CLIENT_URL = "https://client.example.com/oauth/metadata.json"
PUBLIC_JWKS = {
    "keys": [
        {
            "crv": "P-256",
            "kid": "cimd-ec-1",
            "kty": "EC",
            "x": "tS3tFvO_rzqp4FW4XU0M8agahChhDCxvfwkAOUf0r1w",
            "y": "RXB1hhJu-vYd1Go5VyQ5gcQcxnNmCaCmE05mBrJ1qM4",
        }
    ]
}
# Signing keys for the private_key_jwt flows below; a document publishes the public half.
SIGNING_KEY = jwk.JWK.generate(kty="EC", crv="P-256", kid="cimd-signer-1")
ROTATED_KEY = jwk.JWK.generate(kty="EC", crv="P-256", kid="cimd-signer-2")
TOKEN_ENDPOINT = "http://testserver/o/token/"


def _oauthlib_request():
    request = OAuthlibRequest("https://example.com/authorize")
    request.client = None
    return request


def _document(**overrides):
    doc = {
        "client_id": CLIENT_URL,
        "client_name": "Example CIMD Client",
        "redirect_uris": ["https://client.example.com/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": "none",
    }
    doc.update(overrides)
    return doc


# Fetchers injected via CIMD_METADATA_FETCHER. The settings wrapper stores the
# value as-is, so tests assign the class object directly (in production the
# setting is a dotted path resolved by perform_import). They take no arguments.
class _GoodFetcher:
    def fetch(self, client_id):
        return _document(), 3600


class _MismatchFetcher:
    def fetch(self, client_id):
        return _document(client_id="https://someone-else.example/meta.json"), 3600


class _ConfidentialFetcher:
    def fetch(self, client_id):
        return _document(token_endpoint_auth_method="client_secret_basic"), 3600


class _PrivateKeyJWTFetcher:
    def fetch(self, client_id):
        return _document(
            token_endpoint_auth_method="private_key_jwt",
            jwks_uri="https://client.example.com/oauth/jwks.json",
        ), 3600


class _SharedSecretWithPluralFetcher:
    def fetch(self, client_id):
        # The declared method is in the list, so only the shared-secret rule rejects this.
        document = _document(
            token_endpoint_auth_method="client_secret_basic",
            token_endpoint_auth_methods_supported=["client_secret_basic", "none"],
        )
        return document, 3600


class _FailingFetcher:
    def fetch(self, client_id):
        raise CIMDError("could not fetch")


class _UpdatedFetcher:
    def fetch(self, client_id):
        return _document(redirect_uris=["https://client.example.com/new-callback"]), 3600


class _OverlongNameFetcher:
    def fetch(self, client_id):
        # Passes the metadata checks but fails Application.full_clean
        # (name is a max_length=255 CharField).
        return _document(client_name="x" * 300), 3600


class _ExplodingFetcher:
    def fetch(self, client_id):
        raise RuntimeError("boom")


def _fetcher(cls):
    return cls


@pytest.fixture(autouse=True)
def _clear_cimd_cache():
    # The failure backoff lives in Django's cache; isolate it per test.
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def cimd_enabled(oauth2_settings):
    oauth2_settings.CIMD_ENABLED = True
    oauth2_settings.CIMD_METADATA_FETCHER = _fetcher(_GoodFetcher)
    return oauth2_settings


@pytest.fixture
def private_key_jwt_advertised(oauth2_settings):
    """A server that advertises private_key_jwt, so CIMD registers it (see _supported_auth_methods)."""
    oauth2_settings.OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED = [
        *oauth2_settings.OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
        "private_key_jwt",
    ]
    return oauth2_settings


# ---------------------------------------------------------------------------
# client_id URL shape
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "client_id, expected",
    [
        ("https://client.example.com/meta.json", True),
        ("https://client.example.com/", True),
        # RFC 3986 section 3.1: the scheme is case-insensitive.
        ("HTTPS://client.example.com/meta.json", True),
        ("http://client.example.com/meta.json", False),
        ("HTTP://client.example.com/meta.json", False),
        ("client-abc123", False),
        ("", False),
        (None, False),
    ],
)
def test_is_cimd_client_id(client_id, expected):
    assert is_cimd_client_id(client_id) is expected


@pytest.mark.parametrize(
    "url",
    [
        "http://client.example.com/meta.json",  # not https
        "https:///meta.json",  # no host
        "https://user:pass@client.example.com/meta.json",  # userinfo
        "https://client.example.com/meta.json#frag",  # fragment
        "https://client.example.com",  # no path
        "https://client.example.com/a/../meta.json",  # double-dot path segment
        "https://client.example.com/./meta.json",  # single-dot path segment
        "https://client.example.com:99999/meta.json",  # out-of-range port
    ],
)
def test_validate_client_id_url_rejected(url):
    with pytest.raises(CIMDError):
        _validate_client_id_url(url)


def test_validate_client_id_url_accepts_explicit_port():
    parsed = _validate_client_id_url("https://client.example.com:8443/meta.json")
    assert parsed.port == 8443


def test_validate_client_id_url_accepted():
    parsed = _validate_client_id_url(CLIENT_URL)
    assert parsed.hostname == "client.example.com"


# ---------------------------------------------------------------------------
# SSRF: IP validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip, public",
    [
        ("93.184.216.34", True),  # public
        ("2606:2800:220:1:248:1893:25c8:1946", True),  # public v6
        ("127.0.0.1", False),  # loopback
        ("10.0.0.1", False),  # private
        ("192.168.1.1", False),  # private
        ("169.254.169.254", False),  # link-local cloud metadata
        ("100.64.0.1", False),  # CGNAT
        ("::1", False),  # loopback v6
        ("fd00::1", False),  # unique-local v6
        ("not-an-ip", False),
        # IPv6 forms embedding an internal IPv4 must be rejected via the
        # embedded address, not trusted because the v6 wrapper looks global.
        ("64:ff9b::a9fe:a9fe", False),  # NAT64 wrapping 169.254.169.254
        ("64:ff9b::7f00:1", False),  # NAT64 wrapping 127.0.0.1
        ("::ffff:169.254.169.254", False),  # IPv4-mapped cloud metadata
        ("::ffff:10.0.0.1", False),  # IPv4-mapped private
        ("64:ff9b::5db8:d822", True),  # NAT64 wrapping a public 93.184.216.34
        # Teredo (2001::/32) embeds a server IPv4 and a bit-inverted client
        # IPv4; both must be public. 3f57:fefe de-obfuscates to 192.168.1.1,
        # a247:27dd to 93.184.216.34.
        ("2001:0:4136:e378::3f57:fefe", False),  # private client behind public server
        ("2001:0:a00:1::a247:27dd", False),  # private server 10.0.0.1
        ("2001:0:4136:e378::a247:27dd", True),  # public server and client
    ],
)
def test_ip_is_public(ip, public):
    assert _ip_is_public(ip) is public


def test_resolve_and_validate_rejects_internal(mocker):
    mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("10.0.0.5", 443))],
    )
    with pytest.raises(CIMDError):
        _resolve_and_validate("internal.example.com", 443)


def test_resolve_and_validate_rejects_mixed(mocker):
    # A host resolving to both a public and an internal address is refused
    # wholesale, so a split result cannot smuggle an internal connection.
    mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.getaddrinfo",
        return_value=[
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ],
    )
    with pytest.raises(CIMDError):
        _resolve_and_validate("client.example.com", 443)


def test_resolve_and_validate_returns_public_ips(mocker):
    mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    assert _resolve_and_validate("client.example.com", 443) == ["93.184.216.34"]


def test_resolve_and_validate_dns_failure(mocker):
    mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.getaddrinfo", side_effect=socket.gaierror("no such host")
    )
    with pytest.raises(CIMDError):
        _resolve_and_validate("bad.example.com", 443)


def test_resolve_and_validate_no_addresses(mocker):
    mocker.patch("oauth2_provider.core.safe_fetch.socket.getaddrinfo", return_value=[])
    with pytest.raises(CIMDError):
        _resolve_and_validate("empty.example.com", 443)


# ---------------------------------------------------------------------------
# Document validation
# ---------------------------------------------------------------------------


def test_build_application_kwargs_public():
    kwargs = _build_application_kwargs(_document())
    assert kwargs == {
        "name": "Example CIMD Client",
        "redirect_uris": "https://client.example.com/callback",
        "authorization_grant_type": "authorization-code",
        "algorithm": Application.NO_ALGORITHM,
        "token_endpoint_auth_method": "none",
        "client_type": Application.CLIENT_PUBLIC,
        "client_jwks": "",
        "client_jwks_uri": "",
    }


@pytest.mark.parametrize(
    "key_metadata, expected_key_field",
    [
        ({"jwks": PUBLIC_JWKS}, "client_jwks"),
        ({"jwks_uri": "https://client.example.com/jwks.json"}, "client_jwks_uri"),
        # An empty or whitespace-only jwks_uri counts as absent, as for DCR.
        ({"jwks": PUBLIC_JWKS, "jwks_uri": ""}, "client_jwks"),
        ({"jwks": PUBLIC_JWKS, "jwks_uri": "  "}, "client_jwks"),
    ],
)
def test_build_application_kwargs_private_key_jwt(
    private_key_jwt_advertised, key_metadata, expected_key_field
):
    kwargs = _build_application_kwargs(
        _document(token_endpoint_auth_method="private_key_jwt", **key_metadata)
    )

    assert kwargs["client_type"] == Application.CLIENT_CONFIDENTIAL
    assert kwargs["token_endpoint_auth_method"] == Application.TOKEN_AUTH_METHOD_PRIVATE_KEY_JWT
    assert kwargs[expected_key_field]
    other_key_field = "client_jwks_uri" if expected_key_field == "client_jwks" else "client_jwks"
    assert kwargs[other_key_field] == ""


@pytest.mark.parametrize(
    "document",
    [
        _document(token_endpoint_auth_method="client_secret_basic"),
        # Not advertised by this server (see _supported_auth_methods), so refused.
        _document(token_endpoint_auth_method="private_key_jwt"),
        _document(token_endpoint_auth_method=["none"]),  # not a string
        # RFC 7591 section 2: never both, whatever the method.
        _document(jwks=PUBLIC_JWKS, jwks_uri="https://client.example.com/jwks.json"),
        _document(client_secret="shhh"),
        _document(client_secret=None),  # forbidden by presence, not value
        _document(client_secret_expires_at=0),  # spec: MUST NOT be present
        _document(redirect_uris="not-a-list"),
        _document(redirect_uris=[123]),
        _document(redirect_uris=[]),  # redirect-based grants need at least one
        {k: v for k, v in _document().items() if k != "redirect_uris"},
        _document(grant_types="authorization_code"),  # not a list
        _document(grant_types=[123]),
        _document(grant_types=["client_credentials"]),  # not a public/known grant
        _document(grant_types=[]),  # nothing left to register
        _document(grant_types=["refresh_token"]),  # refresh alone registers no flow
        _document(client_name=123),
        # A method this server cannot register, with no usable alternative offered.
        _document(
            token_endpoint_auth_method="private_key_jwt",
            token_endpoint_auth_methods_supported=["private_key_jwt"],
        ),
        # The declared method is absent from the plural list, and the list offers
        # nothing this server registers either.
        _document(
            token_endpoint_auth_method="private_key_jwt",
            token_endpoint_auth_methods_supported=["client_secret_basic"],
        ),
        _document(token_endpoint_auth_method="private_key_jwt"),  # no plural field
        _document(  # plural field present but not a list
            token_endpoint_auth_method="private_key_jwt",
            token_endpoint_auth_methods_supported="none",
        ),
        _document(  # plural field entries must be strings
            token_endpoint_auth_method="private_key_jwt",
            token_endpoint_auth_methods_supported=[123, "none"],
        ),
        _document(token_endpoint_auth_methods_supported=None),  # plural field present but null
        _document(token_endpoint_auth_methods_supported=[]),  # plural field offers nothing
        # Section 4.1: a declared shared-secret method is forbidden outright; offering
        # "none" alongside it does not rescue the document.
        _document(
            token_endpoint_auth_method="client_secret_basic",
            token_endpoint_auth_methods_supported=["client_secret_basic", "none"],
        ),
        _document(token_endpoint_auth_method="client_secret_post"),
        _document(token_endpoint_auth_method="client_secret_jwt"),
        # The declared method must be a string, whatever the plural field offers.
        _document(token_endpoint_auth_method=None, token_endpoint_auth_methods_supported=["none"]),
        _document(token_endpoint_auth_method=True, token_endpoint_auth_methods_supported=["none"]),
        _document(token_endpoint_auth_method=["none"], token_endpoint_auth_methods_supported=["none"]),
        _document(token_endpoint_auth_method={"a": 1}, token_endpoint_auth_methods_supported=["none"]),
        # RP Metadata Choices section 2: a declared method MUST be in the plural list.
        _document(
            token_endpoint_auth_method="private_key_jwt",
            token_endpoint_auth_methods_supported=["none"],
        ),
        _document(
            token_endpoint_auth_method="none",
            token_endpoint_auth_methods_supported=["private_key_jwt"],
        ),
        # No declared method, and the plural field offers nothing this server registers.
        {
            **{k: v for k, v in _document().items() if k != "token_endpoint_auth_method"},
            "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        },
    ],
)
def test_build_application_kwargs_rejects(document):
    with pytest.raises(CIMDError):
        _build_application_kwargs(document)


def test_build_application_kwargs_refuses_private_key_jwt_for_the_implicit_grant(private_key_jwt_advertised):
    """Implicit issues tokens with no client authentication, contradicting draft section 6.2."""
    document = _document(
        token_endpoint_auth_method="private_key_jwt", jwks=PUBLIC_JWKS, grant_types=["implicit"]
    )

    with pytest.raises(CIMDError, match="authorization_code grant"):
        _build_application_kwargs(document)
    # A public implicit client is unaffected.
    public = _build_application_kwargs(_document(grant_types=["implicit"]))
    assert public["authorization_grant_type"] == Application.GRANT_IMPLICIT


@pytest.mark.parametrize("jwks_uri", ["https://client.example.com/jwks.json", " https://x.example/k "])
def test_build_application_kwargs_rejects_jwks_with_jwks_uri_for_a_public_client(jwks_uri):
    """RFC 7591 section 2: jwks and jwks_uri MUST NOT both be present, whatever the method."""
    with pytest.raises(CIMDError, match="mutually exclusive"):
        _build_application_kwargs(_document(jwks=PUBLIC_JWKS, jwks_uri=jwks_uri))


@pytest.mark.parametrize("jwks_uri", ["", "   "])
def test_build_application_kwargs_public_client_with_blank_jwks_uri(jwks_uri):
    """A blank jwks_uri counts as absent, so it does not conflict with jwks."""
    kwargs = _build_application_kwargs(_document(jwks=PUBLIC_JWKS, jwks_uri=jwks_uri))

    assert kwargs["client_type"] == Application.CLIENT_PUBLIC
    assert kwargs["client_jwks"] == ""
    assert kwargs["client_jwks_uri"] == ""


@pytest.mark.parametrize(
    "oauth2_advertises, oidc_enabled, oidc_advertises, registered",
    [
        # Without OpenID Connect only the RFC 8414 document is served, so its list decides.
        (True, False, True, True),
        (True, False, False, True),
        # With OpenID Connect both documents are served, and a client may read either.
        (True, True, True, True),
        (True, True, False, False),
        # MCP clients read the RFC 8414 document first: advertising only in the OIDC
        # one would store a confidential client that authenticates as public.
        (False, True, True, False),
    ],
)
def test_build_application_kwargs_requires_private_key_jwt_in_every_served_discovery_document(
    oauth2_settings, oauth2_advertises, oidc_enabled, oidc_advertises, registered
):
    secret_methods = ["client_secret_basic", "client_secret_post"]
    pkj = ["private_key_jwt"]
    oauth2_settings.OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED = secret_methods + (
        pkj if oauth2_advertises else []
    )
    oauth2_settings.OIDC_ENABLED = oidc_enabled
    oauth2_settings.OIDC_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED = secret_methods + (
        pkj if oidc_advertises else []
    )
    document = _document(
        token_endpoint_auth_method="private_key_jwt",
        jwks_uri="https://client.example.com/jwks.json",
    )

    if registered:
        assert _build_application_kwargs(document)["client_type"] == Application.CLIENT_CONFIDENTIAL
    else:
        with pytest.raises(CIMDError, match="private_key_jwt"):
            _build_application_kwargs(document)


def _stored_inline_jwks(jwks):
    document = _document(token_endpoint_auth_method="private_key_jwt", jwks=jwks)
    return _build_application_kwargs(document)["client_jwks"]


def test_build_application_kwargs_stores_inline_jwks_in_canonical_member_and_array_order(
    private_key_jwt_advertised,
):
    """A document that only reorders the members of its keys must not read as publishing new keys."""
    key = PUBLIC_JWKS["keys"][0]
    reordered = {"keys": [dict(reversed(list(key.items())))]}
    assert json.dumps(reordered) != json.dumps(PUBLIC_JWKS)

    assert _stored_inline_jwks(reordered) == _stored_inline_jwks(PUBLIC_JWKS)
    assert json.loads(_stored_inline_jwks(reordered)) == PUBLIC_JWKS


def test_build_application_kwargs_stores_inline_jwks_in_canonical_array_order(private_key_jwt_advertised):
    """A document that only reorders its keys array must not read as publishing new keys."""
    first, second = (json.loads(key.export_public()) for key in (SIGNING_KEY, ROTATED_KEY))

    stored = _stored_inline_jwks({"keys": [first, second]})

    assert stored == _stored_inline_jwks({"keys": [second, first]})
    # Still a valid JWK Set holding both keys.
    assert sorted(key["kid"] for key in json.loads(stored)["keys"]) == sorted(
        [SIGNING_KEY.kid, ROTATED_KEY.kid]
    )


@pytest.mark.parametrize(
    "key_metadata",
    [
        {},
        {"jwks_uri": ""},  # blank counts as absent, so no key source is published
        {"jwks_uri": "   "},
        {"jwks": PUBLIC_JWKS, "jwks_uri": "https://client.example.com/jwks.json"},
        {"jwks_uri": "http://client.example.com/jwks.json"},
        {"jwks_uri": ["https://client.example.com/jwks.json"]},
        {"jwks": ["not", "an", "object"]},
        {"jwks": {"keys": "not-a-list"}},
        {"jwks": {"keys": []}},
        {"jwks": {"keys": [["not", "an", "object"]]}},
        # The implicit grant never authenticates the client (draft section 6.2).
        {"jwks": PUBLIC_JWKS, "grant_types": ["implicit"]},
    ],
)
def test_build_application_kwargs_rejects_invalid_private_key_jwt(private_key_jwt_advertised, key_metadata):
    document = _document(token_endpoint_auth_method="private_key_jwt", **key_metadata)

    with pytest.raises(CIMDError):
        _build_application_kwargs(document)


@pytest.mark.parametrize(
    "key",
    [
        {**PUBLIC_JWKS["keys"][0], "d": "AQ"},  # private key material
        {**PUBLIC_JWKS["keys"][0], "use": "enc"},  # not usable for signature verification
        {"kty": "oct", "k": "c2VjcmV0", "kid": "shared"},  # a symmetric key is a shared secret
    ],
    ids=["private-key", "encryption-only", "symmetric"],
)
@pytest.mark.django_db(databases="__all__")
def test_resolve_rejects_unusable_inline_jwks(cimd_enabled, private_key_jwt_advertised, key):
    """Key material is validated by Application.clean(), so an unusable set never persists a row."""

    class Fetcher:
        def fetch(self, client_id):
            return _document(token_endpoint_auth_method="private_key_jwt", jwks={"keys": [key]}), 3600

    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(Fetcher)

    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is None
    assert not Application.objects.filter(client_id=CLIENT_URL).exists()


def test_resolve_auth_method_defaults_to_none():
    assert _resolve_auth_method({}) == "none"


def test_resolve_auth_method_keeps_a_supported_declared_method():
    """A method this server supports wins over anything the plural field offers."""
    document = _document(
        token_endpoint_auth_method="none",
        token_endpoint_auth_methods_supported=["private_key_jwt", "none"],
    )

    assert _resolve_auth_method(document) == "none"


def test_resolve_auth_method_negotiates_from_the_plural_field(caplog):
    """The shape is the one ChatGPT publishes at https://chatgpt.com/oauth/client.json."""
    document = _document(
        token_endpoint_auth_method="private_key_jwt",
        token_endpoint_auth_methods_supported=["none", "private_key_jwt"],
    )

    with caplog.at_level(logging.INFO, logger="oauth2_provider.authorization_server.cimd"):
        assert _build_application_kwargs(document)["token_endpoint_auth_method"] == "none"
    assert "chose token_endpoint_auth_method 'private_key_jwt'" in caplog.text


def test_build_application_kwargs_does_not_log_negotiation_for_a_refused_document(caplog):
    """A document refused on a later field never leaves a notice saying it was registered."""
    document = _document(
        token_endpoint_auth_method="private_key_jwt",
        token_endpoint_auth_methods_supported=["none", "private_key_jwt"],
        redirect_uris=[],
    )

    with caplog.at_level(logging.INFO, logger="oauth2_provider.authorization_server.cimd"):
        with pytest.raises(CIMDError, match="redirect_uris"):
            _build_application_kwargs(document)
    assert "does not register" not in caplog.text


def test_resolve_auth_method_rejects_non_string_entries():
    document = _document(
        token_endpoint_auth_method="private_key_jwt",
        token_endpoint_auth_methods_supported=[123, None, "none"],
    )

    with pytest.raises(CIMDError, match="array of strings"):
        _resolve_auth_method(document)


def test_resolve_auth_method_negotiates_from_a_plural_field_alone(caplog):
    """With no declared method the plural list is the client's whole statement.

    Nothing was overridden, so the negotiation notice stays silent.
    """
    document = {k: v for k, v in _document().items() if k != "token_endpoint_auth_method"}
    document["token_endpoint_auth_methods_supported"] = ["private_key_jwt", "none"]

    with caplog.at_level(logging.INFO, logger="oauth2_provider.authorization_server.cimd"):
        assert _build_application_kwargs(document)["token_endpoint_auth_method"] == "none"
    assert "does not register" not in caplog.text


def test_resolve_auth_method_rejects_declared_shared_secret_method():
    """Section 4.1 forbids the declaration itself; the plural field cannot rescue it."""
    document = _document(
        token_endpoint_auth_method="client_secret_basic",
        token_endpoint_auth_methods_supported=["client_secret_basic", "none"],
    )

    with pytest.raises(CIMDError, match="shared-secret"):
        _resolve_auth_method(document)


def test_resolve_auth_method_rejects_a_declared_method_missing_from_the_plural_field():
    document = _document(
        token_endpoint_auth_method="private_key_jwt",
        token_endpoint_auth_methods_supported=["none"],
    )

    with pytest.raises(CIMDError, match="is not in token_endpoint_auth_methods_supported"):
        _resolve_auth_method(document)


def test_resolve_auth_method_error_names_the_declared_method():
    document = _document(
        token_endpoint_auth_method="private_key_jwt",
        token_endpoint_auth_methods_supported=["private_key_jwt"],
    )

    with pytest.raises(CIMDError, match="private_key_jwt"):
        _resolve_auth_method(document)


def test_build_application_kwargs_registers_the_chatgpt_transition_document():
    document = {
        "client_id": CLIENT_URL,
        "client_uri": "https://chatgpt.com/",
        "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "client_name": "ChatGPT",
        "token_endpoint_auth_signing_alg": "RS256",
        "jwks_uri": "https://chatgpt.com/oauth/jwks.json",
    }

    assert _build_application_kwargs(document) == {
        "name": "ChatGPT",
        "redirect_uris": "https://chatgpt.com/connector_platform_oauth_redirect",
        "authorization_grant_type": "authorization-code",
        "algorithm": Application.NO_ALGORITHM,
        "token_endpoint_auth_method": "none",
        "client_type": Application.CLIENT_PUBLIC,
        "client_jwks": "",
        "client_jwks_uri": "",
    }


def test_resolve_grant_type_ignores_refresh_token():
    assert _resolve_grant_type(["authorization_code", "refresh_token"]) == "authorization-code"


def test_resolve_grant_type_ignores_an_unsupported_grant():
    """RFC 7591 section 2.1: drop what this server does not support, keep what it does.

    The list is the one Claude publishes at
    https://claude.ai/oauth/mcp-oauth-client-metadata.
    """
    grant_types = ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"]

    assert _resolve_grant_type(grant_types) == "authorization-code"


def test_resolve_grant_type_prefers_authorization_code():
    assert _resolve_grant_type(["implicit", "authorization_code"]) == "authorization-code"


def test_resolve_grant_type_keeps_a_lone_supported_grant():
    assert _resolve_grant_type(["implicit", "client_credentials"]) == "implicit"


def test_build_application_kwargs_registers_a_document_with_an_extra_grant():
    document = _document(
        grant_types=["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"]
    )

    assert _build_application_kwargs(document)["authorization_grant_type"] == "authorization-code"


# ---------------------------------------------------------------------------
# ID Token signing algorithm
# (OpenID Connect Dynamic Client Registration 1.0 section 2)
# ---------------------------------------------------------------------------


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_build_application_kwargs_defaults_to_rs256_when_server_can_sign(oauth2_settings):
    # id_token_signed_response_alg is OPTIONAL and defaults to RS256, so a
    # document that says nothing is provisioned to receive RS256 ID Tokens as
    # soon as the server holds an RSA signing key.
    assert _build_application_kwargs(_document())["algorithm"] == Application.RS256_ALGORITHM
    explicit = _document(id_token_signed_response_alg="RS256")
    assert _build_application_kwargs(explicit)["algorithm"] == Application.RS256_ALGORITHM


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_build_application_kwargs_null_id_token_alg_means_default(oauth2_settings):
    # JSON null is not a value the spec defines; treat it like an absent parameter.
    assert _build_application_kwargs(_document(id_token_signed_response_alg=None))["algorithm"] == (
        Application.RS256_ALGORITHM
    )


def test_build_application_kwargs_no_algorithm_without_server_key(oauth2_settings):
    # No key, nothing requested: register the client anyway, it simply cannot
    # be issued ID Tokens until the server is configured to sign them.
    assert not oauth2_settings.OIDC_RSA_PRIVATE_KEY
    assert _build_application_kwargs(_document())["algorithm"] == Application.NO_ALGORITHM


@pytest.mark.oauth2_settings({**presets.OIDC_SETTINGS_RW, "OIDC_ENABLED": False})
def test_build_application_kwargs_no_algorithm_when_oidc_disabled(oauth2_settings):
    # A key alone does not make the server an OpenID Provider (the RFC 8414
    # metadata view gates its jwks_uri on both settings too): with OIDC off no
    # ID Token is ever issued, so provisioning RS256 would only mislead.
    assert oauth2_settings.OIDC_RSA_PRIVATE_KEY
    assert _build_application_kwargs(_document())["algorithm"] == Application.NO_ALGORITHM
    with pytest.raises(CIMDError, match="id_token_signed_response_alg"):
        _build_application_kwargs(_document(id_token_signed_response_alg="RS256"))


def test_build_application_kwargs_rejects_rs256_without_server_key(oauth2_settings):
    assert not oauth2_settings.OIDC_RSA_PRIVATE_KEY
    with pytest.raises(CIMDError, match="id_token_signed_response_alg"):
        _build_application_kwargs(_document(id_token_signed_response_alg="RS256"))


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
@pytest.mark.parametrize("alg", ["HS256", "ES256", "none", "", 256])
def test_build_application_kwargs_rejects_unsupported_id_token_alg(oauth2_settings, alg):
    # HS256 would sign with the client secret, which a CIMD client must not
    # have; nothing else is implemented. A CIMD client gets no registration
    # response, so an unsupported request is refused rather than silently
    # replaced with an algorithm the client did not ask for.
    with pytest.raises(CIMDError, match="id_token_signed_response_alg"):
        _build_application_kwargs(_document(id_token_signed_response_alg=alg))


# ---------------------------------------------------------------------------
# Cache lifetime
# ---------------------------------------------------------------------------


def test_effective_max_age(oauth2_settings):
    oauth2_settings.CIMD_METADATA_MIN_AGE_SECONDS = 300
    oauth2_settings.CIMD_METADATA_MAX_AGE_SECONDS = 3600
    assert _effective_max_age(None) == 3600  # default to ceiling
    assert _effective_max_age("max-age=1000") == 1000
    assert _effective_max_age("max-age=99999") == 3600  # clamped to ceiling
    assert _effective_max_age("max-age=10") == 300  # clamped to floor
    assert _effective_max_age("no-store") == 300  # floor
    assert _effective_max_age("no-cache") == 300  # floor


# ---------------------------------------------------------------------------
# resolve_cimd_application
# ---------------------------------------------------------------------------


@pytest.mark.django_db(databases="__all__")
def test_resolve_disabled_returns_none(oauth2_settings):
    oauth2_settings.CIMD_METADATA_FETCHER = _fetcher(_GoodFetcher)
    # CIMD_ENABLED defaults to False
    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is None
    assert not Application.objects.filter(client_id=CLIENT_URL).exists()


@pytest.mark.django_db(databases="__all__")
def test_resolve_non_url_returns_none(cimd_enabled):
    assert resolve_cimd_application("plain-client-id", _oauthlib_request()) is None


@pytest.mark.django_db(databases="__all__")
def test_resolve_creates_public_application(cimd_enabled):
    app = resolve_cimd_application(CLIENT_URL, _oauthlib_request())
    assert app is not None
    assert app.client_id == CLIENT_URL
    assert app.registration_source == Application.RegistrationSource.CIMD
    assert app.client_type == Application.CLIENT_PUBLIC
    assert app.token_endpoint_auth_method == Application.TOKEN_AUTH_METHOD_NONE
    assert app.authorization_grant_type == Application.GRANT_AUTHORIZATION_CODE
    assert app.redirect_uris == "https://client.example.com/callback"
    assert app.user is None
    assert app.cimd_expires_at is not None
    assert app.cimd_expires_at > timezone.now()
    # #1451: a CIMD client keeps the can_introspect default (an opt-out capability).
    app.refresh_from_db()
    assert app.can_introspect is True


@pytest.mark.django_db(databases="__all__")
def test_resolve_creates_private_key_jwt_application(cimd_enabled, private_key_jwt_advertised):
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_PrivateKeyJWTFetcher)

    app = resolve_cimd_application(CLIENT_URL, _oauthlib_request())

    assert app is not None
    assert app.registration_source == Application.RegistrationSource.CIMD
    assert app.client_type == Application.CLIENT_CONFIDENTIAL
    assert app.token_endpoint_auth_method == Application.TOKEN_AUTH_METHOD_PRIVATE_KEY_JWT
    assert app.client_jwks_uri == "https://client.example.com/oauth/jwks.json"


@pytest.mark.django_db(databases="__all__")
def test_resolve_refresh_can_change_private_key_jwt_to_public(
    cimd_enabled, private_key_jwt_advertised, caplog
):
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_PrivateKeyJWTFetcher)
    first = resolve_cimd_application(CLIENT_URL, _oauthlib_request())

    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_GoodFetcher)
    with caplog.at_level(logging.INFO, logger="oauth2_provider.authorization_server.cimd"):
        second = resolve_cimd_application(CLIENT_URL, _oauthlib_request())

    assert "token_endpoint_auth_method changed from 'private_key_jwt' to 'none'" in caplog.text

    assert second.pk == first.pk
    assert second.client_type == Application.CLIENT_PUBLIC
    assert second.token_endpoint_auth_method == Application.TOKEN_AUTH_METHOD_NONE
    assert second.client_jwks == ""
    assert second.client_jwks_uri == ""


def _key_source_fetcher(key_metadata):
    class Fetcher:
        def fetch(self, client_id):
            return _document(token_endpoint_auth_method="private_key_jwt", **key_metadata), 3600

    return Fetcher


@pytest.mark.parametrize(
    "before, after",
    [
        (
            {"jwks_uri": "https://client.example.com/jwks-a.json"},
            {"jwks_uri": "https://client.example.com/jwks-b.json"},
        ),
        ({"jwks": PUBLIC_JWKS}, {"jwks_uri": "https://client.example.com/jwks.json"}),
        ({"jwks_uri": "https://client.example.com/jwks.json"}, {"jwks": PUBLIC_JWKS}),
    ],
    ids=["jwks_uri-changed", "inline-to-jwks_uri", "jwks_uri-to-inline"],
)
@pytest.mark.django_db(databases="__all__")
def test_resolve_refresh_logs_a_changed_key_source(
    cimd_enabled, private_key_jwt_advertised, caplog, before, after
):
    """Draft section 6.3.1: a new key source is logged, like a rotated inline set."""
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_key_source_fetcher(before))
    first = resolve_cimd_application(CLIENT_URL, _oauthlib_request())

    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_key_source_fetcher(after))
    with caplog.at_level(logging.INFO, logger="oauth2_provider.authorization_server.cimd"):
        second = resolve_cimd_application(CLIENT_URL, _oauthlib_request())

    assert second.pk == first.pk
    assert "published new client keys on re-fetch" in caplog.text
    assert "changed from" not in caplog.text
    assert second.client_jwks_uri == after.get("jwks_uri", "")
    assert bool(second.client_jwks) == ("jwks" in after)


@pytest.mark.django_db(databases="__all__")
def test_resolve_client_id_mismatch_rejected_and_backed_off(cimd_enabled, mocker):
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_MismatchFetcher)
    fetch = mocker.spy(_MismatchFetcher, "fetch")
    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is None
    assert not Application.objects.filter(client_id=CLIENT_URL).exists()
    # Backed off: a second attempt must not fetch again.
    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is None
    assert fetch.call_count == 1


@pytest.mark.django_db(databases="__all__")
def test_resolve_confidential_document_rejected(cimd_enabled):
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_ConfidentialFetcher)
    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is None


@pytest.mark.django_db(databases="__all__")
def test_resolve_unadvertised_private_key_jwt_backs_off_per_policy(cimd_enabled, mocker, caplog):
    """The method gate arms a backoff scoped to this node's policy, never the shared one."""
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_PrivateKeyJWTFetcher)
    cimd_enabled.CIMD_FAILURE_BACKOFF_SECONDS = 17
    fetch = mocker.spy(_PrivateKeyJWTFetcher, "fetch")
    cache_set = mocker.spy(cimd.cache, "set")

    with caplog.at_level(logging.INFO, logger="oauth2_provider.authorization_server.cimd"):
        assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is None
    assert "refused by server policy" in caplog.text
    assert not Application.objects.filter(client_id=CLIENT_URL).exists()
    # The shared failure backoff would block nodes whose policy accepts the document.
    assert cache.get(cimd._backoff_cache_key(CLIENT_URL)) is None
    assert cache.get(cimd._policy_backoff_cache_key(CLIENT_URL))
    # The policy backoff lapses after CIMD_FAILURE_BACKOFF_SECONDS, like the shared one.
    cache_set.assert_called_once_with(cimd._policy_backoff_cache_key(CLIENT_URL), True, 17)

    # Within the window, the same policy does not fetch the document again.
    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is None
    assert fetch.call_count == 1

    # A policy that advertises the method is keyed apart, so it fetches and
    # registers the client on the very next request.
    cimd_enabled.OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED = [
        *cimd_enabled.OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
        "private_key_jwt",
    ]
    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is not None
    assert fetch.call_count == 2


def test_policy_backoff_cache_key_is_bounded_and_policy_scoped(oauth2_settings):
    """The key fits memcached's 250-byte limit and differs per client_id and per policy."""
    long_url = "https://client.example.com/" + "a" * 228
    key = cimd._policy_backoff_cache_key(long_url)
    assert len(key) <= 250
    assert key != cimd._backoff_cache_key(long_url)
    assert key != cimd._policy_backoff_cache_key(CLIENT_URL)

    oauth2_settings.OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED = [
        *oauth2_settings.OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
        "private_key_jwt",
    ]
    assert cimd._policy_backoff_cache_key(long_url) != key


@pytest.mark.django_db(databases="__all__")
def test_resolve_shared_secret_method_backs_off(cimd_enabled):
    """A method the spec forbids is invalid metadata, not policy, so it is backed off."""
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_ConfidentialFetcher)
    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is None
    assert cache.get(cimd._backoff_cache_key(CLIENT_URL))


@pytest.mark.django_db(databases="__all__")
def test_resolve_shared_secret_document_rejected_despite_plural_field(cimd_enabled):
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_SharedSecretWithPluralFetcher)
    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is None
    assert not Application.objects.filter(client_id=CLIENT_URL).exists()


@pytest.mark.django_db(databases="__all__")
def test_resolve_fetch_failure_backs_off(cimd_enabled, mocker):
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_FailingFetcher)
    fetch = mocker.spy(_FailingFetcher, "fetch")
    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is None
    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is None
    assert fetch.call_count == 1  # second call short-circuited by backoff


@pytest.mark.django_db(databases="__all__")
def test_resolve_refuses_to_hijack_non_cimd_application(cimd_enabled):
    Application.objects.create(
        client_id=CLIENT_URL,
        name="Manually provisioned",
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="https://manual.example.com/callback",
    )
    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is None
    app = Application.objects.get(client_id=CLIENT_URL)
    assert app.registration_source == Application.RegistrationSource.MANUAL
    assert app.client_type == Application.CLIENT_CONFIDENTIAL


@pytest.mark.django_db(databases="__all__")
def test_resolve_updates_existing_cimd_application(cimd_enabled):
    first = resolve_cimd_application(CLIENT_URL, _oauthlib_request())
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_UpdatedFetcher)
    second = resolve_cimd_application(CLIENT_URL, _oauthlib_request())
    assert second.pk == first.pk
    assert Application.objects.filter(client_id=CLIENT_URL).count() == 1
    assert second.redirect_uris == "https://client.example.com/new-callback"


@pytest.mark.django_db(databases="__all__")
def test_resolve_concurrency_cap_fails_fast(cimd_enabled):
    cimd_enabled.CIMD_MAX_CONCURRENT_FETCHES = 1
    semaphore = cimd._get_fetch_semaphore()
    assert semaphore.acquire(blocking=False)
    try:
        assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is None
        assert not Application.objects.filter(client_id=CLIENT_URL).exists()
    finally:
        semaphore.release()


def test_get_fetch_semaphore_disabled(oauth2_settings):
    oauth2_settings.CIMD_MAX_CONCURRENT_FETCHES = 0
    assert cimd._get_fetch_semaphore() is None


# ---------------------------------------------------------------------------
# Registration permission gate
# ---------------------------------------------------------------------------


class _DenyAllPermission:
    def has_permission(self, request, client_id):
        return False


@pytest.mark.django_db(databases="__all__")
def test_resolve_denied_by_permission_skips_fetch_without_backoff(cimd_enabled, mocker):
    fetch = mocker.spy(_GoodFetcher, "fetch")
    cimd_enabled.CIMD_REGISTRATION_PERMISSION_CLASSES = (_DenyAllPermission,)
    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is None
    assert fetch.call_count == 0
    assert not Application.objects.filter(client_id=CLIENT_URL).exists()
    # A policy denial must not back the URL off: allowing the host takes
    # effect on the very next request.
    cimd_enabled.CIMD_REGISTRATION_PERMISSION_CLASSES = (cimd.AllowAllCIMDPermission,)
    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is not None


@pytest.mark.django_db(databases="__all__")
def test_resolve_empty_permission_classes_fail_closed(cimd_enabled):
    cimd_enabled.CIMD_REGISTRATION_PERMISSION_CLASSES = ()
    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is None


@pytest.mark.parametrize(
    "allowed_hosts, permitted",
    [
        (["client.example.com"], True),
        (["other.example.com"], False),
        ([".example.com"], True),  # domain-and-subdomains wildcard
        (["*"], True),
        ([], False),
    ],
)
def test_host_allowlist_permission(oauth2_settings, allowed_hosts, permitted):
    oauth2_settings.CIMD_ALLOWED_HOSTS = allowed_hosts
    assert HostAllowlistCIMDPermission().has_permission(None, CLIENT_URL) is permitted


def test_host_allowlist_permission_rejects_hostless_url(oauth2_settings):
    oauth2_settings.CIMD_ALLOWED_HOSTS = ["*"]
    assert HostAllowlistCIMDPermission().has_permission(None, "https:///path-only") is False


@pytest.mark.django_db(databases="__all__")
def test_resolve_with_host_allowlist(cimd_enabled):
    cimd_enabled.CIMD_REGISTRATION_PERMISSION_CLASSES = (HostAllowlistCIMDPermission,)
    cimd_enabled.CIMD_ALLOWED_HOSTS = ["client.example.com"]
    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is not None


@pytest.mark.django_db(databases="__all__")
def test_permission_classes_receive_the_oauthlib_request(cimd_enabled):
    from oauthlib.common import Request

    from oauth2_provider.oauth2_validators import OAuth2Validator

    seen = []

    class _RecordingPermission:
        def has_permission(self, request, client_id):
            seen.append((request, client_id))
            return True

    cimd_enabled.CIMD_REGISTRATION_PERMISSION_CLASSES = (_RecordingPermission,)
    request = Request("https://example.com/authorize")
    request.client = None
    assert OAuth2Validator().validate_client_id(CLIENT_URL, request) is True
    assert seen == [(request, CLIENT_URL)]


@pytest.mark.django_db(databases="__all__")
def test_resolve_recovers_from_concurrent_insert_race(cimd_enabled, mocker):
    # Reproduce the interleaving the IntegrityError handler exists for: our
    # first-sight get() misses, a concurrent writer commits the row, our save()
    # then hits the unique constraint, and we recover by re-loading the winner.
    winner = Application.objects.create(
        client_id=CLIENT_URL,
        registration_source=Application.RegistrationSource.CIMD,
        client_type=Application.CLIENT_PUBLIC,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="https://client.example.com/callback",
    )
    mocker.patch.object(Application.objects, "get", side_effect=[Application.DoesNotExist, winner])
    mocker.patch.object(Application, "save", side_effect=IntegrityError("duplicate client_id"))

    resolved = resolve_cimd_application(CLIENT_URL, _oauthlib_request())
    assert resolved.pk == winner.pk


@pytest.mark.django_db(databases="__all__")
def test_resolve_race_with_vanished_row_fails_closed(cimd_enabled, mocker):
    # save() hits the unique constraint but the winning row is gone by the time
    # we re-load it (e.g. rolled back): treat the client as unknown.
    mocker.patch.object(Application.objects, "get", side_effect=Application.DoesNotExist)
    mocker.patch.object(Application, "save", side_effect=IntegrityError("duplicate client_id"))
    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is None


@pytest.mark.django_db(databases="__all__")
def test_resolve_race_with_non_cimd_winner_is_refused(cimd_enabled, mocker):
    # The concurrent writer that won the unique-constraint race was a manual
    # registration: the hijack guard must hold on the re-load path too.
    winner = Application.objects.create(
        client_id=CLIENT_URL,
        registration_source=Application.RegistrationSource.MANUAL,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
    )
    mocker.patch.object(Application.objects, "get", side_effect=[Application.DoesNotExist, winner])
    mocker.patch.object(Application, "save", side_effect=IntegrityError("duplicate client_id"))
    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is None


@pytest.mark.django_db(databases="__all__")
def test_resolve_rejects_metadata_failing_model_validation(cimd_enabled):
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_OverlongNameFetcher)
    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is None
    assert not Application.objects.filter(client_id=CLIENT_URL).exists()


@pytest.mark.django_db(databases="__all__")
def test_resolve_degrades_unexpected_errors_and_backs_off(cimd_enabled, mocker):
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_ExplodingFetcher)
    fetch = mocker.spy(_ExplodingFetcher, "fetch")
    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is None
    assert resolve_cimd_application(CLIENT_URL, _oauthlib_request()) is None
    assert fetch.call_count == 1  # second call short-circuited by backoff


# ---------------------------------------------------------------------------
# refresh_if_stale
# ---------------------------------------------------------------------------


@pytest.mark.django_db(databases="__all__")
def test_refresh_if_stale_noop_for_fresh(cimd_enabled):
    app = resolve_cimd_application(CLIENT_URL, _oauthlib_request())
    returned = refresh_if_stale(app, _oauthlib_request())
    assert returned.redirect_uris == "https://client.example.com/callback"


@pytest.mark.django_db(databases="__all__")
def test_refresh_if_stale_refetches_when_expired(cimd_enabled):
    app = resolve_cimd_application(CLIENT_URL, _oauthlib_request())
    Application.objects.filter(pk=app.pk).update(cimd_expires_at=timezone.now() - timedelta(seconds=1))
    app.refresh_from_db()

    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_UpdatedFetcher)
    refreshed = refresh_if_stale(app, _oauthlib_request())
    assert refreshed.redirect_uris == "https://client.example.com/new-callback"


@pytest.mark.django_db(databases="__all__")
def test_refresh_if_stale_keeps_an_admin_introspection_opt_out(cimd_enabled):
    # #1451: can_introspect is not client metadata; a refresh keeps what an
    # administrator set.
    app = resolve_cimd_application(CLIENT_URL, _oauthlib_request())
    assert app.can_introspect is True
    Application.objects.filter(pk=app.pk).update(
        can_introspect=False, cimd_expires_at=timezone.now() - timedelta(seconds=1)
    )
    app.refresh_from_db()

    refreshed = refresh_if_stale(app, _oauthlib_request())
    assert refreshed.cimd_expires_at > timezone.now()
    assert refreshed.can_introspect is False
    assert Application.objects.get(pk=app.pk).can_introspect is False


def _preassign_pk_on_first_sight(mocker):
    """Give the unsaved CIMD instance a pk, as a primary key with a default would.

    A swapped model whose primary key has a default (e.g. a UUIDField with
    default=uuid4) has a pk before its first save. Returns the pk assigned.
    """
    original_init = Application.__init__
    preassigned_pk = 987654321

    def init_with_preassigned_pk(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        if self._state.adding and self.pk is None and kwargs.get("client_id") == CLIENT_URL:
            self.pk = preassigned_pk

    mocker.patch.object(Application, "__init__", init_with_preassigned_pk)
    return preassigned_pk


@pytest.mark.django_db(databases="__all__")
def test_first_sight_is_detected_when_the_pk_has_a_default(cimd_enabled, mocker, caplog):
    # First sight must still be recognised when the unsaved instance has a pk.
    preassigned_pk = _preassign_pk_on_first_sight(mocker)
    # Derive a signing algorithm so a first sight mistaken for a re-fetch would
    # also log an algorithm "change".
    cimd_enabled.OIDC_ENABLED = True
    cimd_enabled.OIDC_RSA_PRIVATE_KEY = presets.OIDC_SETTINGS_RW["OIDC_RSA_PRIVATE_KEY"]

    with caplog.at_level(logging.INFO, logger="oauth2_provider.authorization_server.cimd"):
        app = resolve_cimd_application(CLIENT_URL, _oauthlib_request())

    assert app.pk == preassigned_pk
    assert "signing algorithm changed" not in caplog.text


@pytest.mark.django_db(databases="__all__")
def test_private_key_jwt_first_sight_is_detected_when_the_pk_has_a_default(
    cimd_enabled, private_key_jwt_advertised, mocker, caplog
):
    """A first sight with keys logs no credential change, even when the unsaved instance has a pk."""
    preassigned_pk = _preassign_pk_on_first_sight(mocker)
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_private_key_jwt_fetcher(SIGNING_KEY))

    with caplog.at_level(logging.INFO, logger="oauth2_provider.authorization_server.cimd"):
        app = resolve_cimd_application(CLIENT_URL, _oauthlib_request())

    assert app.pk == preassigned_pk
    assert app.token_endpoint_auth_method == Application.TOKEN_AUTH_METHOD_PRIVATE_KEY_JWT
    assert app.client_jwks
    # Mistaken for a re-fetch, the blank method would read as a change from
    # "none", and the empty key fields as a change of keys.
    assert "token_endpoint_auth_method changed" not in caplog.text
    assert "published new client keys" not in caplog.text


@pytest.mark.django_db(databases="__all__")
def test_refresh_if_stale_logs_no_method_change_for_a_legacy_public_row(cimd_enabled, caplog):
    """Every legacy row was public, so its blank method reads as ``none``, not as a change."""

    app = resolve_cimd_application(CLIENT_URL, _oauthlib_request())
    Application.objects.filter(pk=app.pk).update(
        token_endpoint_auth_method=Application.TOKEN_AUTH_METHOD_DEFAULT,
        cimd_expires_at=timezone.now() - timedelta(seconds=1),
    )
    app.refresh_from_db()

    with caplog.at_level(logging.INFO, logger="oauth2_provider.authorization_server.cimd"):
        refreshed = refresh_if_stale(app, _oauthlib_request())

    assert refreshed.token_endpoint_auth_method == Application.TOKEN_AUTH_METHOD_NONE
    assert "changed from" not in caplog.text
    assert "published new client keys" not in caplog.text


@pytest.mark.django_db(databases="__all__")
def test_refresh_if_stale_keeps_last_good_on_failure(cimd_enabled):
    app = resolve_cimd_application(CLIENT_URL, _oauthlib_request())
    Application.objects.filter(pk=app.pk).update(cimd_expires_at=timezone.now() - timedelta(seconds=1))
    app.refresh_from_db()

    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_FailingFetcher)
    refreshed = refresh_if_stale(app, _oauthlib_request())
    assert refreshed.redirect_uris == "https://client.example.com/callback"


@pytest.mark.django_db(databases="__all__")
def test_refresh_if_stale_ignores_non_cimd(application):
    assert refresh_if_stale(application, _oauthlib_request()) is application


# ---------------------------------------------------------------------------
# ID Token signing algorithm provisioning (#1853)
# ---------------------------------------------------------------------------


def _expire(app):
    Application.objects.filter(pk=app.pk).update(cimd_expires_at=timezone.now() - timedelta(seconds=1))
    app.refresh_from_db()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_resolve_provisions_rs256_when_server_can_sign(cimd_enabled):
    app = resolve_cimd_application(CLIENT_URL, _oauthlib_request())
    assert app is not None
    assert app.algorithm == Application.RS256_ALGORITHM
    assert Application.objects.get(pk=app.pk).algorithm == Application.RS256_ALGORITHM


@pytest.mark.django_db(databases="__all__")
def test_resolve_leaves_algorithm_unset_without_server_key(cimd_enabled):
    assert not cimd_enabled.OIDC_RSA_PRIVATE_KEY
    app = resolve_cimd_application(CLIENT_URL, _oauthlib_request())
    assert app is not None
    assert app.algorithm == Application.NO_ALGORITHM


@pytest.mark.django_db(databases="__all__")
def test_refresh_gains_rs256_once_server_key_is_configured(cimd_enabled):
    # A client first seen before the server could sign picks RS256 up on its
    # next re-fetch: configuring the key later heals existing rows.
    app = resolve_cimd_application(CLIENT_URL, _oauthlib_request())
    assert app.algorithm == Application.NO_ALGORITHM
    _expire(app)

    cimd_enabled.OIDC_ENABLED = True
    cimd_enabled.OIDC_RSA_PRIVATE_KEY = presets.OIDC_SETTINGS_RW["OIDC_RSA_PRIVATE_KEY"]
    refreshed = refresh_if_stale(app, _oauthlib_request())
    assert refreshed.algorithm == Application.RS256_ALGORITHM
    assert Application.objects.get(pk=app.pk).algorithm == Application.RS256_ALGORITHM


@pytest.mark.django_db(databases="__all__")
def test_refresh_logs_signing_algorithm_change(cimd_enabled, caplog):
    # The value is derived from this process's settings and written to the
    # shared row, so an operator can see a node changing it.
    app = resolve_cimd_application(CLIENT_URL, _oauthlib_request())
    _expire(app)
    cimd_enabled.OIDC_ENABLED = True
    cimd_enabled.OIDC_RSA_PRIVATE_KEY = presets.OIDC_SETTINGS_RW["OIDC_RSA_PRIVATE_KEY"]
    with caplog.at_level(logging.INFO, logger="oauth2_provider.authorization_server.cimd"):
        refresh_if_stale(app, _oauthlib_request())
    assert "signing algorithm changed from '' to 'RS256'" in caplog.text


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_refresh_drops_rs256_once_server_key_is_removed(cimd_enabled):
    # The algorithm is re-derived on every fetch. Were the stale RS256 kept,
    # full_clean() would reject the row on every refresh ("You must set
    # OIDC_RSA_PRIVATE_KEY ...") and the new redirect URI would never land.
    app = resolve_cimd_application(CLIENT_URL, _oauthlib_request())
    assert app.algorithm == Application.RS256_ALGORITHM
    _expire(app)

    cimd_enabled.OIDC_RSA_PRIVATE_KEY = ""
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_UpdatedFetcher)
    refreshed = refresh_if_stale(app, _oauthlib_request())
    assert refreshed.algorithm == Application.NO_ALGORITHM
    assert refreshed.redirect_uris == "https://client.example.com/new-callback"
    assert refreshed.cimd_expires_at > timezone.now()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_openid_code_flow_issues_id_token_to_cimd_client(cimd_enabled, client, django_user_model, oidc_key):
    """Regression test for #1853.

    A client the server has only ever seen as a CIMD URL completes an
    ``openid`` authorization-code flow and receives an ID Token signed with the
    server's RSA key. Before the fix the stored application had no signing
    algorithm and the token endpoint raised ``ImproperlyConfigured`` ("This
    application does not support signed tokens").
    """
    user = django_user_model.objects.create_user("cimd_oidc_user", password="123456")
    client.force_login(user)
    redirect_uri = "https://client.example.com/callback"
    authorize_data = {
        "client_id": CLIENT_URL,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "state": "random_state_string",
        "nonce": "random_nonce",
    }

    # The browser's GET of the consent page is where an unseen CIMD URL is
    # resolved and persisted; the consent POST then loads the stored row.
    response = client.get(reverse("oauth2_provider:authorize"), data=authorize_data)
    assert response.status_code == 200, response.content
    response = client.post(reverse("oauth2_provider:authorize"), data={**authorize_data, "allow": True})
    assert response.status_code == 302, response.content
    code = parse_qs(urlparse(response["Location"]).query)["code"][0]

    response = post_form(
        client,
        reverse("oauth2_provider:token"),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": CLIENT_URL,
        },
    )
    assert response.status_code == 200, response.content
    content = response.json()
    assert "id_token" in content

    # Verifying with the server's RSA key proves the token was signed with it.
    verified = jwt.JWT(key=oidc_key, jwt=content["id_token"])
    assert verified.token.jose_header["alg"] == "RS256"
    claims = json.loads(verified.claims)
    assert claims["aud"] == CLIENT_URL
    assert claims["nonce"] == "random_nonce"


# ---------------------------------------------------------------------------
# SafeMetadataFetcher (SSRF pinning + response handling)
# ---------------------------------------------------------------------------


class _FakeHTTPResponse:
    def __init__(self, status=200, headers=None, body=b'{"client_id": "x"}'):
        self.status = status
        self.headers = headers or {"Content-Type": "application/json"}
        self._body = body

    def read(self, amt):
        return self._body[:amt]

    def release_conn(self):
        pass


def test_fetcher_pins_validated_ip(oauth2_settings, mocker):
    mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    captured = {}

    class _FakePool:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def urlopen(self, method, path, **kwargs):
            captured["method"] = method
            captured["path"] = path
            captured["urlopen_kwargs"] = kwargs
            return _FakeHTTPResponse(body=f'{{"client_id": "{CLIENT_URL}"}}'.encode())

        def close(self):
            pass

    mocker.patch("oauth2_provider.core.safe_fetch.urllib3.HTTPSConnectionPool", _FakePool)

    metadata, max_age = SafeMetadataFetcher().fetch(CLIENT_URL)

    assert metadata["client_id"] == CLIENT_URL
    # Connects to the validated IP, but SNI/verification use the real hostname.
    assert captured["host"] == "93.184.216.34"
    assert captured["server_hostname"] == "client.example.com"
    assert captured["urlopen_kwargs"]["redirect"] is False
    assert captured["urlopen_kwargs"]["headers"]["Host"] == "client.example.com"
    assert captured["urlopen_kwargs"]["headers"]["Accept"] == "application/json, application/*+json"


def test_fetcher_rejects_non_200():
    with pytest.raises(CIMDError):
        SafeMetadataFetcher()._read_document(_FakeHTTPResponse(status=404))


def test_fetcher_rejects_non_json():
    resp = _FakeHTTPResponse(headers={"Content-Type": "text/html"})
    with pytest.raises(CIMDError):
        SafeMetadataFetcher()._read_document(resp)


def test_fetcher_rejects_oversized(oauth2_settings):
    oauth2_settings.CIMD_MAX_DOCUMENT_SIZE = 8
    resp = _FakeHTTPResponse(body=b'{"client_id": "aaaaaaaaaaaaaaaa"}')
    with pytest.raises(CIMDError):
        SafeMetadataFetcher()._read_document(resp)


def test_fetcher_rejects_bad_json():
    resp = _FakeHTTPResponse(body=b"not json")
    with pytest.raises(CIMDError):
        SafeMetadataFetcher()._read_document(resp)


def test_fetcher_rejects_non_object_json():
    resp = _FakeHTTPResponse(body=b'["valid json", "but not an object"]')
    with pytest.raises(CIMDError):
        SafeMetadataFetcher()._read_document(resp)


def test_fetcher_accepts_structured_json_suffix():
    resp = _FakeHTTPResponse(
        headers={"Content-Type": "application/client-metadata+json"},
        body=b'{"client_id": "x"}',
    )
    metadata, _ = SafeMetadataFetcher()._read_document(resp)
    assert metadata["client_id"] == "x"


def test_fetcher_fails_over_to_next_validated_ip(oauth2_settings, mocker):
    mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 443)), (2, 1, 6, "", ("93.184.216.35", 443))],
    )
    hosts = []

    class _FailFirstPool:
        def __init__(self, **kwargs):
            self._host = kwargs["host"]
            hosts.append(kwargs["host"])

        def urlopen(self, method, path, **kwargs):
            if self._host == "93.184.216.34":
                raise urllib3.exceptions.HTTPError("connect failed")
            return _FakeHTTPResponse(body=f'{{"client_id": "{CLIENT_URL}"}}'.encode())

        def close(self):
            pass

    mocker.patch("oauth2_provider.core.safe_fetch.urllib3.HTTPSConnectionPool", _FailFirstPool)
    metadata, _ = SafeMetadataFetcher().fetch(CLIENT_URL)
    assert metadata["client_id"] == CLIENT_URL
    # Each attempt is pinned to the next validated IP, never the hostname.
    assert hosts == ["93.184.216.34", "93.184.216.35"]


def test_fetcher_raises_when_all_ips_fail(oauth2_settings, mocker):
    mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
    )

    class _AlwaysFailPool:
        def __init__(self, **kwargs):
            pass

        def urlopen(self, method, path, **kwargs):
            raise urllib3.exceptions.HTTPError("unreachable")

        def close(self):
            pass

    mocker.patch("oauth2_provider.core.safe_fetch.urllib3.HTTPSConnectionPool", _AlwaysFailPool)
    with pytest.raises(CIMDError):
        SafeMetadataFetcher().fetch(CLIENT_URL)


def test_fetcher_shares_one_deadline_across_ips(oauth2_settings, mocker):
    # A hostname resolving to many IPs must not multiply the time budget: the
    # deadline is shared, so each attempt gets only the remaining time and the
    # loop stops once the budget is spent instead of trying every address for a
    # fresh timeout each.
    oauth2_settings.CIMD_FETCH_TIMEOUT_SECONDS = 5
    mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.getaddrinfo",
        return_value=[
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("93.184.216.35", 443)),
            (2, 1, 6, "", ("93.184.216.36", 443)),
        ],
    )
    # deadline = 0 + 5; iter1 remaining=5 (now=0), iter2 remaining=2 (now=3),
    # iter3 remaining=-1 (now=6) -> break before the third IP is attempted.
    mocker.patch("oauth2_provider.core.safe_fetch.time.monotonic", side_effect=[0, 0, 3, 6])

    attempts = []

    class _SlowPool:
        def __init__(self, **kwargs):
            attempts.append((kwargs["host"], kwargs["timeout"].total))

        def urlopen(self, method, path, **kwargs):
            raise urllib3.exceptions.HTTPError("timed out")

        def close(self):
            pass

    mocker.patch("oauth2_provider.core.safe_fetch.urllib3.HTTPSConnectionPool", _SlowPool)

    with pytest.raises(CIMDError):
        SafeMetadataFetcher().fetch(CLIENT_URL)

    # The third IP is never tried once the shared deadline passes, and each
    # attempt's total budget is the remaining time (5, then 2), not a fresh 5s.
    assert attempts == [("93.184.216.34", 5), ("93.184.216.35", 2)]


def test_fetcher_includes_port_and_query(oauth2_settings, mocker):
    mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 8443))],
    )
    captured = {}

    class _Pool:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def urlopen(self, method, path, **kwargs):
            captured["path"] = path
            captured["urlopen_kwargs"] = kwargs
            return _FakeHTTPResponse(body=b'{"client_id": "x"}')

        def close(self):
            pass

    mocker.patch("oauth2_provider.core.safe_fetch.urllib3.HTTPSConnectionPool", _Pool)
    SafeMetadataFetcher().fetch("https://client.example.com:8443/meta.json?v=1")
    assert captured["port"] == 8443
    assert captured["path"] == "/meta.json?v=1"
    # Non-default port must appear in the Host header (from the URL authority).
    assert captured["urlopen_kwargs"]["headers"]["Host"] == "client.example.com:8443"


# ---------------------------------------------------------------------------
# Validator integration + metadata advertisement
# ---------------------------------------------------------------------------


def _public_jwks(key):
    return {"keys": [json.loads(key.export_public())]}


def _private_key_jwt_fetcher(key):
    class Fetcher:
        def fetch(self, client_id):
            return _document(token_endpoint_auth_method="private_key_jwt", jwks=_public_jwks(key)), 3600

    return Fetcher


def _client_assertion(key, audience=TOKEN_ENDPOINT):
    now = int(time.time())
    claims = {
        "iss": CLIENT_URL,
        "sub": CLIENT_URL,
        "aud": audience,
        "exp": now + 60,
        "iat": now,
        "jti": uuid4().hex,
    }
    token = jwt.JWT(header={"alg": "ES256", "kid": key.kid}, claims=claims)
    token.make_signed_token(key)
    return token.serialize()


def _token_request(**params):
    """An oauthlib token request from the host the assertion audience names."""
    request = OAuthlibRequest(TOKEN_ENDPOINT, http_method="POST", headers={"HTTP_HOST": "testserver"})
    request.client = None
    request.grant_type = "authorization_code"
    for name, value in params.items():
        setattr(request, name, value)
    return request


def _authenticate_with(key):
    from oauth2_provider.core.rfc7523 import JWT_BEARER_CLIENT_ASSERTION_TYPE
    from oauth2_provider.oauth2_validators import OAuth2Validator

    request = _token_request(
        client_assertion=_client_assertion(key),
        client_assertion_type=JWT_BEARER_CLIENT_ASSERTION_TYPE,
    )
    return OAuth2Validator().authenticate_client(request), request


def _expire_stored_document():
    Application.objects.filter(client_id=CLIENT_URL).update(
        cimd_expires_at=timezone.now() - timedelta(seconds=1)
    )


@pytest.mark.django_db(databases="__all__")
def test_token_endpoint_resolves_private_key_jwt_client_from_its_assertion(
    cimd_enabled, private_key_jwt_advertised, caplog
):
    """First sight at the token endpoint: the client_id is the assertion's ``sub``."""
    from oauth2_provider.oauth2_validators import OAuth2Validator

    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_private_key_jwt_fetcher(SIGNING_KEY))

    with caplog.at_level(logging.INFO, logger="oauth2_provider.authorization_server.cimd"):
        ok, request = _authenticate_with(SIGNING_KEY)

    assert ok is True
    # A first sight registers the client; there is no earlier credential to have changed.
    assert "changed from" not in caplog.text
    assert "published new client keys" not in caplog.text
    assert request.client.client_id == CLIENT_URL
    assert request.client.client_type == Application.CLIENT_CONFIDENTIAL
    assert request.client.registration_source == Application.RegistrationSource.CIMD

    # A key the document did not publish is refused.
    assert _authenticate_with(ROTATED_KEY)[0] is False
    # RFC 9700 section 2.5: a client registered for private_key_jwt cannot fall
    # back to a secret or to the public-client path.
    secret_request = _token_request(client_id=CLIENT_URL, client_secret="guess")
    assert OAuth2Validator().authenticate_client(secret_request) is False
    assert OAuth2Validator().authenticate_client_id(CLIENT_URL, _token_request()) is False


@pytest.mark.django_db(databases="__all__")
def test_token_endpoint_verifies_a_private_key_jwt_client_against_its_jwks_uri(
    cimd_enabled, private_key_jwt_advertised, mocker
):
    """A document publishing a jwks_uri is verified against the key set fetched from it."""
    from oauth2_provider.authorization_server import client_assertions

    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_PrivateKeyJWTFetcher)
    fetch = mocker.patch.object(
        client_assertions.safe_fetch,
        "fetch_https_json",
        return_value=(_public_jwks(SIGNING_KEY), {}),
    )

    ok, request = _authenticate_with(SIGNING_KEY)

    assert ok is True
    assert request.client.client_jwks_uri == "https://client.example.com/oauth/jwks.json"
    assert fetch.call_count == 1
    assert fetch.call_args.args[0] == "https://client.example.com/oauth/jwks.json"

    # A key the URL does not publish is refused, after the one unknown-kid refetch.
    assert _authenticate_with(ROTATED_KEY)[0] is False
    assert fetch.call_count == 2


@pytest.mark.django_db(databases="__all__")
def test_refresh_rotates_private_key_jwt_keys(cimd_enabled, private_key_jwt_advertised, caplog):
    """Draft section 6.3.1: a refetched document's keys replace the stored set."""
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_private_key_jwt_fetcher(SIGNING_KEY))
    assert _authenticate_with(SIGNING_KEY)[0] is True

    _expire_stored_document()
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_private_key_jwt_fetcher(ROTATED_KEY))

    with caplog.at_level(logging.INFO, logger="oauth2_provider.authorization_server.cimd"):
        assert _authenticate_with(ROTATED_KEY)[0] is True
    assert "published new client keys on re-fetch" in caplog.text
    assert _authenticate_with(SIGNING_KEY)[0] is False
    stored = json.loads(Application.objects.get(client_id=CLIENT_URL).client_jwks)
    assert [key["kid"] for key in stored["keys"]] == [ROTATED_KEY.kid]


@pytest.mark.django_db(databases="__all__")
def test_refresh_with_reordered_keys_logs_no_key_change(cimd_enabled, private_key_jwt_advertised, caplog):
    """A refetched document that only reorders its keys array stores the same set, silently."""
    keys = [json.loads(key.export_public()) for key in (SIGNING_KEY, ROTATED_KEY)]

    def fetcher(order):
        class Fetcher:
            def fetch(self, client_id):
                return _document(token_endpoint_auth_method="private_key_jwt", jwks={"keys": order}), 3600

        return Fetcher

    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(fetcher(keys))
    assert _authenticate_with(SIGNING_KEY)[0] is True
    stored = Application.objects.get(client_id=CLIENT_URL).client_jwks

    _expire_stored_document()
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(fetcher(list(reversed(keys))))
    with caplog.at_level(logging.INFO, logger="oauth2_provider.authorization_server.cimd"):
        assert _authenticate_with(ROTATED_KEY)[0] is True

    assert Application.objects.get(client_id=CLIENT_URL).client_jwks == stored
    assert "published new client keys" not in caplog.text


@pytest.mark.django_db(databases="__all__")
def test_refresh_moves_public_client_to_private_key_jwt(cimd_enabled, private_key_jwt_advertised, caplog):
    """The reverse of test_resolve_refresh_can_change_private_key_jwt_to_public."""
    from oauth2_provider.oauth2_validators import OAuth2Validator

    assert OAuth2Validator().authenticate_client_id(CLIENT_URL, _token_request()) is True

    _expire_stored_document()
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_private_key_jwt_fetcher(SIGNING_KEY))

    with caplog.at_level(logging.INFO, logger="oauth2_provider.authorization_server.cimd"):
        assert _authenticate_with(SIGNING_KEY)[0] is True
    assert "token_endpoint_auth_method changed from 'none' to 'private_key_jwt'" in caplog.text
    app = Application.objects.get(client_id=CLIENT_URL)
    assert app.client_type == Application.CLIENT_CONFIDENTIAL
    assert app.token_endpoint_auth_method == Application.TOKEN_AUTH_METHOD_PRIVATE_KEY_JWT
    assert OAuth2Validator().authenticate_client_id(CLIENT_URL, _token_request()) is False


@pytest.mark.django_db(databases="__all__")
def test_private_key_jwt_client_refreshes_its_tokens(
    cimd_enabled, private_key_jwt_advertised, django_user_model
):
    """The refresh-token grant authenticates the CIMD client with its assertion, then binds the token."""
    from oauth2_provider.core.rfc7523 import JWT_BEARER_CLIENT_ASSERTION_TYPE
    from oauth2_provider.models import get_access_token_model, get_refresh_token_model
    from oauth2_provider.oauth2_validators import OAuth2Validator

    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_private_key_jwt_fetcher(SIGNING_KEY))
    assert _authenticate_with(SIGNING_KEY)[0] is True
    application = Application.objects.get(client_id=CLIENT_URL)
    user = django_user_model.objects.create_user("cimd_refresh_user")
    access_token = get_access_token_model().objects.create(
        user=user,
        token="cimd-access-token",
        application=application,
        expires=timezone.now() + timedelta(hours=1),
        scope="read",
    )
    get_refresh_token_model().objects.create(
        user=user, token="cimd-refresh-token", application=application, access_token=access_token
    )

    validator = OAuth2Validator()
    request = _token_request(
        grant_type="refresh_token",
        client_assertion=_client_assertion(SIGNING_KEY),
        client_assertion_type=JWT_BEARER_CLIENT_ASSERTION_TYPE,
    )
    assert validator.client_authentication_required(request) is True
    assert validator.authenticate_client(request) is True
    assert validator.validate_refresh_token("cimd-refresh-token", request.client, request) is True
    assert request.user == user

    # Without an assertion the confidential client cannot refresh as a public one.
    assert validator.authenticate_client_id(CLIENT_URL, _token_request(grant_type="refresh_token")) is False


def _introspectable_token(django_user_model):
    from oauth2_provider.models import get_access_token_model

    return get_access_token_model().objects.create(
        user=django_user_model.objects.create_user("cimd_introspect_user"),
        token="cimd-introspectable-token",
        application=Application.objects.get(client_id=CLIENT_URL),
        expires=timezone.now() + timedelta(days=1),
        scope="read",
    )


def _introspect_with_assertion(client, key, token):
    """POST to the introspection endpoint, authenticating with a client assertion signed by *key*."""
    from oauth2_provider.core.rfc7523 import JWT_BEARER_CLIENT_ASSERTION_TYPE

    introspect = reverse("oauth2_provider:introspect")
    return post_form(
        client,
        introspect,
        data={
            "client_assertion_type": JWT_BEARER_CLIENT_ASSERTION_TYPE,
            "client_assertion": _client_assertion(key, audience="http://testserver" + introspect),
            "token": token.token,
        },
    )


@pytest.mark.django_db(databases="__all__")
def test_private_key_jwt_client_can_introspect(
    client, cimd_enabled, private_key_jwt_advertised, django_user_model
):
    """A confidential CIMD client authenticates to the introspection endpoint with an assertion."""
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_private_key_jwt_fetcher(SIGNING_KEY))
    assert _authenticate_with(SIGNING_KEY)[0] is True
    token = _introspectable_token(django_user_model)

    response = _introspect_with_assertion(client, SIGNING_KEY, token)

    assert response.status_code == 200, response.content
    assert json.loads(response.content)["active"] is True


@pytest.mark.django_db(databases="__all__")
def test_private_key_jwt_client_introspection_opt_out_survives_a_refetch(
    client, cimd_enabled, private_key_jwt_advertised, django_user_model
):
    """#1451: an operator's ``can_introspect=False`` refuses the assertion, before and after a re-fetch."""
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_private_key_jwt_fetcher(SIGNING_KEY))
    assert _authenticate_with(SIGNING_KEY)[0] is True
    token = _introspectable_token(django_user_model)
    Application.objects.filter(client_id=CLIENT_URL).update(can_introspect=False)

    assert _introspect_with_assertion(client, SIGNING_KEY, token).status_code == 403

    # The stale document is re-fetched while the introspection request
    # authenticates the client; the re-fetch must not restore the flag.
    _expire_stored_document()
    assert _introspect_with_assertion(client, SIGNING_KEY, token).status_code == 403
    stored = Application.objects.get(client_id=CLIENT_URL)
    assert stored.cimd_expires_at > timezone.now()
    assert stored.can_introspect is False


@pytest.mark.parametrize(
    "key_metadata",
    [{"jwks": PUBLIC_JWKS}, {"jwks_uri": "https://client.example.com/oauth/jwks.json"}],
    ids=["jwks", "jwks_uri"],
)
@pytest.mark.django_db(databases="__all__")
def test_introspection_opt_out_survives_method_changes(
    cimd_enabled, private_key_jwt_advertised, key_metadata
):
    """``none`` → ``private_key_jwt`` → ``none`` re-fetches never change ``can_introspect``."""
    app = resolve_cimd_application(CLIENT_URL, _oauthlib_request())
    Application.objects.filter(pk=app.pk).update(can_introspect=False)

    _expire_stored_document()
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_key_source_fetcher(key_metadata))
    refresh_if_stale(Application.objects.get(pk=app.pk), _oauthlib_request())
    stored = Application.objects.get(pk=app.pk)
    assert stored.token_endpoint_auth_method == Application.TOKEN_AUTH_METHOD_PRIVATE_KEY_JWT
    assert stored.client_type == Application.CLIENT_CONFIDENTIAL
    assert (stored.client_jwks or stored.client_jwks_uri) != ""
    assert stored.can_introspect is False

    _expire_stored_document()
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_GoodFetcher)
    refresh_if_stale(Application.objects.get(pk=app.pk), _oauthlib_request())
    stored = Application.objects.get(pk=app.pk)
    assert stored.token_endpoint_auth_method == Application.TOKEN_AUTH_METHOD_NONE
    assert stored.client_type == Application.CLIENT_PUBLIC
    assert stored.client_jwks == ""
    assert stored.client_jwks_uri == ""
    assert stored.can_introspect is False


@pytest.mark.parametrize("operator_value", [True, False])
@pytest.mark.django_db(databases="__all__")
def test_documented_pre_save_receiver_covers_private_key_jwt_clients(
    cimd_enabled, private_key_jwt_advertised, operator_value
):
    """The receiver in docs/resource_server.rst ("Introspection when registration is open")."""
    from django.db.models.signals import pre_save

    # Verbatim from the docs.
    def no_introspection_for_registered_clients(sender, instance, raw, **kwargs):
        """Turn can_introspect off for clients that registered through DCR or CIMD."""
        if raw or not instance._state.adding:
            return
        if instance.registration_source in (
            sender.RegistrationSource.DCR,
            sender.RegistrationSource.CIMD,
        ):
            instance.can_introspect = False

    pre_save.connect(
        no_introspection_for_registered_clients,
        sender=Application,
        dispatch_uid="test_no_introspection_for_registered_clients",
    )
    try:
        cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_private_key_jwt_fetcher(SIGNING_KEY))
        assert _authenticate_with(SIGNING_KEY)[0] is True
        stored = Application.objects.get(client_id=CLIENT_URL)
        assert stored.client_type == Application.CLIENT_CONFIDENTIAL
        assert stored.can_introspect is False

        # An operator then sets the flag (as the admin does, with save()).
        stored.can_introspect = operator_value
        stored.save()

        # A re-fetch that rotates the keys keeps the operator's value.
        _expire_stored_document()
        cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_private_key_jwt_fetcher(ROTATED_KEY))
        assert _authenticate_with(ROTATED_KEY)[0] is True
        stored = Application.objects.get(client_id=CLIENT_URL)
        assert [key["kid"] for key in json.loads(stored.client_jwks)["keys"]] == [ROTATED_KEY.kid]
        assert stored.can_introspect is operator_value
    finally:
        pre_save.disconnect(sender=Application, dispatch_uid="test_no_introspection_for_registered_clients")


def _deadvertise_private_key_jwt(oauth2_settings):
    oauth2_settings.OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED = [
        method
        for method in oauth2_settings.OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED
        if method != "private_key_jwt"
    ]


def _stored_row():
    return Application.objects.filter(client_id=CLIENT_URL).values().get()


@pytest.mark.django_db(databases="__all__")
def test_first_sight_refuses_a_resolved_row_with_an_unadvertised_method(cimd_enabled, mocker, caplog):
    """The method gate also applies to a row the resolver hands back on first sight.

    This node does not advertise private_key_jwt, yet the resolver can return a
    row registered with it: after losing a concurrent first-sight race it
    reloads the winner's row, which a node that advertises the method may have
    stored, and a lookup against a lagging replica can miss a row that exists.
    """
    from oauth2_provider.oauth2_validators import OAuth2Validator

    def resolve_to_a_row_stored_elsewhere(client_id, request):
        # Stored after this node's lookup missed it, by a node whose policy
        # registers private_key_jwt.
        return Application.objects.create(
            client_id=client_id,
            name="Example CIMD Client",
            user=None,
            redirect_uris="https://client.example.com/callback",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            token_endpoint_auth_method=Application.TOKEN_AUTH_METHOD_PRIVATE_KEY_JWT,
            client_jwks=json.dumps(_public_jwks(SIGNING_KEY)),
            registration_source=Application.RegistrationSource.CIMD,
            cimd_expires_at=timezone.now() + timedelta(hours=1),
        )

    resolve = mocker.patch.object(
        cimd, "resolve_cimd_application", side_effect=resolve_to_a_row_stored_elsewhere
    )
    request = _token_request()

    with caplog.at_level(logging.INFO, logger="oauth2_provider.authorization_server.cimd"):
        assert OAuth2Validator()._load_application(CLIENT_URL, request) is None

    resolve.assert_called_once()
    assert request.client is None
    assert "which this server does not register" in caplog.text
    # Refused, not removed: the row another node stored is left as it is.
    assert _stored_row()["token_endpoint_auth_method"] == Application.TOKEN_AUTH_METHOD_PRIVATE_KEY_JWT


@pytest.mark.django_db(databases="__all__")
def test_deadvertising_private_key_jwt_refuses_the_stored_client(
    cimd_enabled, private_key_jwt_advertised, mocker, caplog
):
    """The method gate also applies to a stored row, which is left untouched."""
    from oauth2_provider.oauth2_validators import OAuth2Validator

    fetcher = _private_key_jwt_fetcher(SIGNING_KEY)
    fetch = mocker.spy(fetcher, "fetch")
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(fetcher)
    assert _authenticate_with(SIGNING_KEY)[0] is True
    stored = _stored_row()

    _deadvertise_private_key_jwt(private_key_jwt_advertised)
    with caplog.at_level(logging.INFO, logger="oauth2_provider.authorization_server.cimd"):
        assert _authenticate_with(SIGNING_KEY)[0] is False
    assert "which this server does not register" in caplog.text
    # Confidential, so the public path refuses it too; nor is it a known client.
    assert OAuth2Validator().authenticate_client_id(CLIENT_URL, _token_request()) is False
    assert OAuth2Validator().validate_client_id(CLIENT_URL, _token_request()) is False
    assert _stored_row() == stored

    # Advertising the method again restores the client from the stored row.
    private_key_jwt_advertised.OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED = [
        *private_key_jwt_advertised.OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
        "private_key_jwt",
    ]
    assert _authenticate_with(SIGNING_KEY)[0] is True
    assert fetch.call_count == 1
    assert _stored_row() == stored


@pytest.mark.django_db(databases="__all__")
def test_deadvertised_stale_private_key_jwt_row_refetch_is_backed_off_per_policy(
    cimd_enabled, private_key_jwt_advertised, mocker
):
    """A refetch refused by the method policy keeps the row, refuses it, and is not repeated."""
    from oauth2_provider.oauth2_validators import OAuth2Validator

    fetcher = _private_key_jwt_fetcher(SIGNING_KEY)
    fetch = mocker.spy(fetcher, "fetch")
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(fetcher)
    assert _authenticate_with(SIGNING_KEY)[0] is True
    _expire_stored_document()
    stored = _stored_row()

    _deadvertise_private_key_jwt(private_key_jwt_advertised)
    for _ in range(3):
        assert _authenticate_with(SIGNING_KEY)[0] is False
        assert OAuth2Validator()._load_application(CLIENT_URL, _token_request()) is None
    # One refetch for the window: the stored row is returned while backed off
    # and still refused by is_usable_registration.
    assert fetch.call_count == 2
    assert _stored_row() == stored
    assert cache.get(cimd._backoff_cache_key(CLIENT_URL)) is None

    # Once the window lapses, a document that has since moved to "none" is
    # picked up on the next use.
    cache.delete(cimd._policy_backoff_cache_key(CLIENT_URL))
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_GoodFetcher)
    assert OAuth2Validator().authenticate_client_id(CLIENT_URL, _token_request()) is True
    assert _stored_row()["token_endpoint_auth_method"] == Application.TOKEN_AUTH_METHOD_NONE


@pytest.mark.django_db(databases="__all__")
def test_validate_client_id_resolves_cimd_url(cimd_enabled):
    from oauthlib.common import Request

    from oauth2_provider.oauth2_validators import OAuth2Validator

    validator = OAuth2Validator()
    request = Request("https://example.com/authorize")
    request.client = None

    # Authorize leg: oauthlib calls validate_client_id during
    # validate_authorization_request.
    assert validator.validate_client_id(CLIENT_URL, request) is True
    assert request.client.client_id == CLIENT_URL
    assert request.client.registration_source == Application.RegistrationSource.CIMD


@pytest.mark.django_db(databases="__all__")
def test_authenticate_client_id_resolves_cimd_url(cimd_enabled):
    from oauthlib.common import Request

    from oauth2_provider.oauth2_validators import OAuth2Validator

    validator = OAuth2Validator()
    request = Request("https://example.com/token")
    request.client = None

    # Token leg: a public client authenticates via authenticate_client_id, which
    # shares the same _load_application seam, so CIMD must resolve there too.
    assert validator.authenticate_client_id(CLIENT_URL, request) is True
    assert request.client.client_id == CLIENT_URL
    assert request.client.registration_source == Application.RegistrationSource.CIMD


def test_metadata_advertised_when_enabled(oauth2_settings, client):
    oauth2_settings.CIMD_ENABLED = True
    response = client.get(reverse("oauth2_provider:oauth-server-metadata"))
    assert response.json()["client_id_metadata_document_supported"] is True


def test_metadata_not_advertised_when_disabled(client):
    response = client.get(reverse("oauth2_provider:oauth-server-metadata"))
    assert response.json()["client_id_metadata_document_supported"] is False


# ---------------------------------------------------------------------------
# clearcimdapplications management command
# ---------------------------------------------------------------------------


def _stored_app(host, *, source=None, expires_delta=timedelta(hours=-1)):
    return Application.objects.create(
        client_id=f"https://{host}/meta.json",
        name=host,
        client_type=Application.CLIENT_PUBLIC,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="https://client.example.com/callback",
        registration_source=source or Application.RegistrationSource.CIMD,
        cimd_expires_at=timezone.now() + expires_delta,
    )


# batch_size=1 exercises the batched-transaction loop across prune and survive
# outcomes; None exercises the default.
@pytest.mark.parametrize("batch_size", [None, 1])
@pytest.mark.django_db(databases="__all__")
def test_clearcimdapplications_prunes_only_dead_expired_cimd_rows(django_user_model, capsys, batch_size):
    from django.core.management import call_command

    from oauth2_provider.models import (
        get_access_token_model,
        get_grant_model,
        get_id_token_model,
        get_refresh_token_model,
    )

    user = django_user_model.objects.create_user("cimd-prune-user")
    now = timezone.now()

    _stored_app("dead.example.com")
    dead_tokens = _stored_app("dead-tokens.example.com")
    get_access_token_model().objects.create(
        token="expired-at", expires=now - timedelta(hours=1), application=dead_tokens
    )
    get_refresh_token_model().objects.create(
        token="revoked-rt", user=user, application=dead_tokens, revoked=now - timedelta(hours=1)
    )

    fresh = _stored_app("fresh.example.com", expires_delta=timedelta(hours=1))
    manual = _stored_app("manual.example.com", source=Application.RegistrationSource.MANUAL)
    live_access = _stored_app("live-access.example.com")
    get_access_token_model().objects.create(
        token="live-at", expires=now + timedelta(hours=1), application=live_access
    )
    live_refresh = _stored_app("live-refresh.example.com")
    get_refresh_token_model().objects.create(token="live-rt", user=user, application=live_refresh)
    live_grant = _stored_app("live-grant.example.com")
    get_grant_model().objects.create(
        user=user,
        code="live-code",
        application=live_grant,
        expires=now + timedelta(minutes=5),
        redirect_uri="https://client.example.com/callback",
    )
    live_idtoken = _stored_app("live-idtoken.example.com")
    get_id_token_model().objects.create(expires=now + timedelta(hours=1), application=live_idtoken)

    call_command("clearcimdapplications", **({} if batch_size is None else {"batch_size": batch_size}))

    survivors = set(Application.objects.values_list("pk", flat=True))
    assert survivors == {fresh.pk, manual.pk, live_access.pk, live_refresh.pk, live_grant.pk, live_idtoken.pk}
    assert "Deleted 2 expired CIMD application(s)" in capsys.readouterr().out


@pytest.mark.parametrize("batch_size", [0, -1])
def test_clearcimdapplications_rejects_non_positive_batch_size(batch_size):
    from django.core.management import CommandError, call_command

    with pytest.raises(CommandError, match="--batch-size"):
        call_command("clearcimdapplications", batch_size=batch_size)


@pytest.mark.django_db(databases="__all__")
def test_clearcimdapplications_skips_row_whose_source_changed_mid_run(mocker):
    """A row that stops being CIMD between the candidate scan and the locked
    re-check must not be deleted: the locked query re-applies the
    registration_source filter, not just cimd_expires_at.
    """
    from django.core.management import call_command
    from django.db import transaction as real_transaction

    app = _stored_app("mutated.example.com")  # CIMD + expired, no live tokens

    real_atomic = real_transaction.atomic

    def flip_then_atomic(*args, **kwargs):
        # Simulate registration_source changing (data correction / custom code)
        # after the candidate query selected this row but before the lock.
        Application.objects.filter(pk=app.pk).update(
            registration_source=Application.RegistrationSource.MANUAL
        )
        return real_atomic(*args, **kwargs)

    mocker.patch(
        "oauth2_provider.management.commands.clearcimdapplications.transaction.atomic",
        side_effect=flip_then_atomic,
    )

    call_command("clearcimdapplications")

    # The row is no longer CIMD by lock time, so it is left untouched.
    assert Application.objects.filter(pk=app.pk).exists()
