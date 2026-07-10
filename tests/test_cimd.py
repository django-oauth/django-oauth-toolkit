"""
Tests for OAuth Client ID Metadata Document (CIMD) support.

draft-ietf-oauth-client-id-metadata-document
"""

import socket
from datetime import timedelta

import pytest
import urllib3
from django.core.cache import cache
from django.db import IntegrityError
from django.urls import reverse
from django.utils import timezone

from oauth2_provider import cimd
from oauth2_provider.cimd import (
    CIMDError,
    HostAllowlistCIMDPermission,
    SafeMetadataFetcher,
    _build_application_kwargs,
    _effective_max_age,
    _ip_is_public,
    _resolve_and_validate,
    _resolve_grant_type,
    _validate_client_id_url,
    is_cimd_client_id,
    refresh_if_stale,
    resolve_cimd_application,
)
from oauth2_provider.models import get_application_model


Application = get_application_model()

CLIENT_URL = "https://client.example.com/oauth/metadata.json"


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
        "oauth2_provider.cimd.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("10.0.0.5", 443))],
    )
    with pytest.raises(CIMDError):
        _resolve_and_validate("internal.example.com", 443)


def test_resolve_and_validate_rejects_mixed(mocker):
    # A host resolving to both a public and an internal address is refused
    # wholesale, so a split result cannot smuggle an internal connection.
    mocker.patch(
        "oauth2_provider.cimd.socket.getaddrinfo",
        return_value=[
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ],
    )
    with pytest.raises(CIMDError):
        _resolve_and_validate("client.example.com", 443)


def test_resolve_and_validate_returns_public_ips(mocker):
    mocker.patch(
        "oauth2_provider.cimd.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    assert _resolve_and_validate("client.example.com", 443) == ["93.184.216.34"]


def test_resolve_and_validate_dns_failure(mocker):
    mocker.patch("oauth2_provider.cimd.socket.getaddrinfo", side_effect=socket.gaierror("no such host"))
    with pytest.raises(CIMDError):
        _resolve_and_validate("bad.example.com", 443)


def test_resolve_and_validate_no_addresses(mocker):
    mocker.patch("oauth2_provider.cimd.socket.getaddrinfo", return_value=[])
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
    }


@pytest.mark.parametrize(
    "document",
    [
        _document(token_endpoint_auth_method="client_secret_basic"),
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
        _document(grant_types=["authorization_code", "implicit"]),  # more than one
        _document(client_name=123),
    ],
)
def test_build_application_kwargs_rejects(document):
    with pytest.raises(CIMDError):
        _build_application_kwargs(document)


def test_resolve_grant_type_ignores_refresh_token():
    assert _resolve_grant_type(["authorization_code", "refresh_token"]) == "authorization-code"


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
    assert resolve_cimd_application(CLIENT_URL) is None
    assert not Application.objects.filter(client_id=CLIENT_URL).exists()


@pytest.mark.django_db(databases="__all__")
def test_resolve_non_url_returns_none(cimd_enabled):
    assert resolve_cimd_application("plain-client-id") is None


@pytest.mark.django_db(databases="__all__")
def test_resolve_creates_public_application(cimd_enabled):
    app = resolve_cimd_application(CLIENT_URL)
    assert app is not None
    assert app.client_id == CLIENT_URL
    assert app.registration_source == Application.RegistrationSource.CIMD
    assert app.client_type == Application.CLIENT_PUBLIC
    assert app.authorization_grant_type == Application.GRANT_AUTHORIZATION_CODE
    assert app.redirect_uris == "https://client.example.com/callback"
    assert app.user is None
    assert app.cimd_expires_at is not None
    assert app.cimd_expires_at > timezone.now()


@pytest.mark.django_db(databases="__all__")
def test_resolve_client_id_mismatch_rejected_and_backed_off(cimd_enabled, mocker):
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_MismatchFetcher)
    fetch = mocker.spy(_MismatchFetcher, "fetch")
    assert resolve_cimd_application(CLIENT_URL) is None
    assert not Application.objects.filter(client_id=CLIENT_URL).exists()
    # Backed off: a second attempt must not fetch again.
    assert resolve_cimd_application(CLIENT_URL) is None
    assert fetch.call_count == 1


@pytest.mark.django_db(databases="__all__")
def test_resolve_confidential_document_rejected(cimd_enabled):
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_ConfidentialFetcher)
    assert resolve_cimd_application(CLIENT_URL) is None


@pytest.mark.django_db(databases="__all__")
def test_resolve_fetch_failure_backs_off(cimd_enabled, mocker):
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_FailingFetcher)
    fetch = mocker.spy(_FailingFetcher, "fetch")
    assert resolve_cimd_application(CLIENT_URL) is None
    assert resolve_cimd_application(CLIENT_URL) is None
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
    assert resolve_cimd_application(CLIENT_URL) is None
    app = Application.objects.get(client_id=CLIENT_URL)
    assert app.registration_source == Application.RegistrationSource.MANUAL
    assert app.client_type == Application.CLIENT_CONFIDENTIAL


@pytest.mark.django_db(databases="__all__")
def test_resolve_updates_existing_cimd_application(cimd_enabled):
    first = resolve_cimd_application(CLIENT_URL)
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_UpdatedFetcher)
    second = resolve_cimd_application(CLIENT_URL)
    assert second.pk == first.pk
    assert Application.objects.filter(client_id=CLIENT_URL).count() == 1
    assert second.redirect_uris == "https://client.example.com/new-callback"


@pytest.mark.django_db(databases="__all__")
def test_resolve_concurrency_cap_fails_fast(cimd_enabled):
    cimd_enabled.CIMD_MAX_CONCURRENT_FETCHES = 1
    semaphore = cimd._get_fetch_semaphore()
    assert semaphore.acquire(blocking=False)
    try:
        assert resolve_cimd_application(CLIENT_URL) is None
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
    assert resolve_cimd_application(CLIENT_URL) is None
    assert fetch.call_count == 0
    assert not Application.objects.filter(client_id=CLIENT_URL).exists()
    # A policy denial must not back the URL off: allowing the host takes
    # effect on the very next request.
    cimd_enabled.CIMD_REGISTRATION_PERMISSION_CLASSES = (cimd.AllowAllCIMDPermission,)
    assert resolve_cimd_application(CLIENT_URL) is not None


@pytest.mark.django_db(databases="__all__")
def test_resolve_empty_permission_classes_fail_closed(cimd_enabled):
    cimd_enabled.CIMD_REGISTRATION_PERMISSION_CLASSES = ()
    assert resolve_cimd_application(CLIENT_URL) is None


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
    assert resolve_cimd_application(CLIENT_URL) is not None


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

    resolved = resolve_cimd_application(CLIENT_URL)
    assert resolved.pk == winner.pk


@pytest.mark.django_db(databases="__all__")
def test_resolve_race_with_vanished_row_fails_closed(cimd_enabled, mocker):
    # save() hits the unique constraint but the winning row is gone by the time
    # we re-load it (e.g. rolled back): treat the client as unknown.
    mocker.patch.object(Application.objects, "get", side_effect=Application.DoesNotExist)
    mocker.patch.object(Application, "save", side_effect=IntegrityError("duplicate client_id"))
    assert resolve_cimd_application(CLIENT_URL) is None


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
    assert resolve_cimd_application(CLIENT_URL) is None


@pytest.mark.django_db(databases="__all__")
def test_resolve_rejects_metadata_failing_model_validation(cimd_enabled):
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_OverlongNameFetcher)
    assert resolve_cimd_application(CLIENT_URL) is None
    assert not Application.objects.filter(client_id=CLIENT_URL).exists()


@pytest.mark.django_db(databases="__all__")
def test_resolve_degrades_unexpected_errors_and_backs_off(cimd_enabled, mocker):
    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_ExplodingFetcher)
    fetch = mocker.spy(_ExplodingFetcher, "fetch")
    assert resolve_cimd_application(CLIENT_URL) is None
    assert resolve_cimd_application(CLIENT_URL) is None
    assert fetch.call_count == 1  # second call short-circuited by backoff


# ---------------------------------------------------------------------------
# refresh_if_stale
# ---------------------------------------------------------------------------


@pytest.mark.django_db(databases="__all__")
def test_refresh_if_stale_noop_for_fresh(cimd_enabled):
    app = resolve_cimd_application(CLIENT_URL)
    returned = refresh_if_stale(app)
    assert returned.redirect_uris == "https://client.example.com/callback"


@pytest.mark.django_db(databases="__all__")
def test_refresh_if_stale_refetches_when_expired(cimd_enabled):
    app = resolve_cimd_application(CLIENT_URL)
    Application.objects.filter(pk=app.pk).update(cimd_expires_at=timezone.now() - timedelta(seconds=1))
    app.refresh_from_db()

    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_UpdatedFetcher)
    refreshed = refresh_if_stale(app)
    assert refreshed.redirect_uris == "https://client.example.com/new-callback"


@pytest.mark.django_db(databases="__all__")
def test_refresh_if_stale_keeps_last_good_on_failure(cimd_enabled):
    app = resolve_cimd_application(CLIENT_URL)
    Application.objects.filter(pk=app.pk).update(cimd_expires_at=timezone.now() - timedelta(seconds=1))
    app.refresh_from_db()

    cimd_enabled.CIMD_METADATA_FETCHER = _fetcher(_FailingFetcher)
    refreshed = refresh_if_stale(app)
    assert refreshed.redirect_uris == "https://client.example.com/callback"


@pytest.mark.django_db(databases="__all__")
def test_refresh_if_stale_ignores_non_cimd(application):
    assert refresh_if_stale(application) is application


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
        "oauth2_provider.cimd.socket.getaddrinfo",
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

    mocker.patch("oauth2_provider.cimd.urllib3.HTTPSConnectionPool", _FakePool)

    metadata, max_age = SafeMetadataFetcher().fetch(CLIENT_URL)

    assert metadata["client_id"] == CLIENT_URL
    # Connects to the validated IP, but SNI/verification use the real hostname.
    assert captured["host"] == "93.184.216.34"
    assert captured["server_hostname"] == "client.example.com"
    assert captured["urlopen_kwargs"]["redirect"] is False
    assert captured["urlopen_kwargs"]["headers"]["Host"] == "client.example.com"


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
        "oauth2_provider.cimd.socket.getaddrinfo",
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

    mocker.patch("oauth2_provider.cimd.urllib3.HTTPSConnectionPool", _FailFirstPool)
    metadata, _ = SafeMetadataFetcher().fetch(CLIENT_URL)
    assert metadata["client_id"] == CLIENT_URL
    # Each attempt is pinned to the next validated IP, never the hostname.
    assert hosts == ["93.184.216.34", "93.184.216.35"]


def test_fetcher_raises_when_all_ips_fail(oauth2_settings, mocker):
    mocker.patch(
        "oauth2_provider.cimd.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
    )

    class _AlwaysFailPool:
        def __init__(self, **kwargs):
            pass

        def urlopen(self, method, path, **kwargs):
            raise urllib3.exceptions.HTTPError("unreachable")

        def close(self):
            pass

    mocker.patch("oauth2_provider.cimd.urllib3.HTTPSConnectionPool", _AlwaysFailPool)
    with pytest.raises(CIMDError):
        SafeMetadataFetcher().fetch(CLIENT_URL)


def test_fetcher_includes_port_and_query(oauth2_settings, mocker):
    mocker.patch(
        "oauth2_provider.cimd.socket.getaddrinfo",
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

    mocker.patch("oauth2_provider.cimd.urllib3.HTTPSConnectionPool", _Pool)
    SafeMetadataFetcher().fetch("https://client.example.com:8443/meta.json?v=1")
    assert captured["port"] == 8443
    assert captured["path"] == "/meta.json?v=1"
    # Non-default port must appear in the Host header (from the URL authority).
    assert captured["urlopen_kwargs"]["headers"]["Host"] == "client.example.com:8443"


# ---------------------------------------------------------------------------
# Validator integration + metadata advertisement
# ---------------------------------------------------------------------------


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
