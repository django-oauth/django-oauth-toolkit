"""
Tests for oauth2_provider.safe_fetch (SSRF-hardened HTTPS fetching).

The SSRF pinning behavior (IP validation, deadline sharing, redirect refusal)
is additionally exercised through the CIMD suite; these tests cover the
generic entry points directly, with DNS and the connection pool faked.
"""

import pytest

from oauth2_provider import safe_fetch
from oauth2_provider.safe_fetch import SafeFetchError, fetch_https_json


class _FakeHTTPResponse:
    def __init__(self, status=200, headers=None, body=b'{"keys": []}'):
        self.status = status
        self.headers = headers if headers is not None else {"Content-Type": "application/json"}
        self._body = body

    def read(self, amt):
        return self._body[:amt]

    def release_conn(self):
        pass


def _fake_pool_returning(response):
    class _FakePool:
        def __init__(self, **kwargs):
            pass

        def urlopen(self, method, path, **kwargs):
            return response

        def close(self):
            pass

    return _FakePool


def _patch_network(mocker, response):
    mocker.patch(
        "oauth2_provider.safe_fetch.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    mocker.patch("oauth2_provider.safe_fetch.urllib3.HTTPSConnectionPool", _fake_pool_returning(response))


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/jwks.json",  # not https
        "https:///jwks.json",  # no host
        "https://example.com:99999/jwks.json",  # invalid port
        "https://user:pass@example.com/jwks.json",  # userinfo
        "https://@example.com/jwks.json",  # empty but present userinfo
        "https://:@example.com/jwks.json",  # empty username and password
    ],
)
def test_fetch_rejects_invalid_urls(url):
    with pytest.raises(SafeFetchError):
        fetch_https_json(url, timeout=5, max_size=1024)


def test_fetch_https_json_success(mocker):
    _patch_network(mocker, _FakeHTTPResponse(body=b'{"keys": [1]}'))
    data, headers = fetch_https_json("https://example.com/jwks.json", timeout=5, max_size=1024)
    assert data == {"keys": [1]}
    assert headers["Content-Type"] == "application/json"


def test_fetch_https_json_rejects_non_200(mocker):
    _patch_network(mocker, _FakeHTTPResponse(status=404))
    with pytest.raises(SafeFetchError):
        fetch_https_json("https://example.com/jwks.json", timeout=5, max_size=1024)


def test_fetch_https_json_rejects_non_json_content_type(mocker):
    _patch_network(mocker, _FakeHTTPResponse(headers={"Content-Type": "text/html"}))
    with pytest.raises(SafeFetchError):
        fetch_https_json("https://example.com/jwks.json", timeout=5, max_size=1024)


def test_fetch_https_json_rejects_oversized_body(mocker):
    _patch_network(mocker, _FakeHTTPResponse(body=b'{"keys": ["' + b"a" * 64 + b'"]}'))
    with pytest.raises(SafeFetchError):
        fetch_https_json("https://example.com/jwks.json", timeout=5, max_size=16)


def test_fetch_https_json_rejects_invalid_json(mocker):
    _patch_network(mocker, _FakeHTTPResponse(body=b"not json"))
    with pytest.raises(SafeFetchError):
        fetch_https_json("https://example.com/jwks.json", timeout=5, max_size=1024)


def test_fetch_https_json_rejects_non_object_json(mocker):
    _patch_network(mocker, _FakeHTTPResponse(body=b'["a", "list"]'))
    with pytest.raises(SafeFetchError):
        fetch_https_json("https://example.com/jwks.json", timeout=5, max_size=1024)


def test_fetch_https_json_accepts_structured_json_suffix(mocker):
    _patch_network(
        mocker,
        _FakeHTTPResponse(headers={"Content-Type": "application/jwk-set+json"}, body=b'{"keys": []}'),
    )
    data, _ = fetch_https_json("https://example.com/jwks.json", timeout=5, max_size=1024)
    assert data == {"keys": []}


def test_media_type_is_json():
    assert safe_fetch.media_type_is_json("application/json") is True
    assert safe_fetch.media_type_is_json("application/jwk-set+json; charset=utf-8") is True
    assert safe_fetch.media_type_is_json("text/html") is False
    assert safe_fetch.media_type_is_json(None) is False


def test_exhausted_timeout_reports_explicit_message(mocker):
    mocker.patch(
        "oauth2_provider.safe_fetch.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    with pytest.raises(SafeFetchError, match="timeout budget exhausted"):
        fetch_https_json("https://example.com/jwks.json", timeout=0, max_size=1024)


def test_uppercase_scheme_is_accepted(mocker):
    # RFC 3986 schemes are case-insensitive; urlparse() lowercases the scheme,
    # so HTTPS:// URLs pass the https-only check.
    _patch_network(mocker, _FakeHTTPResponse(body=b'{"keys": []}'))
    data, _ = fetch_https_json("HTTPS://example.com/jwks.json", timeout=5, max_size=1024)
    assert data == {"keys": []}
