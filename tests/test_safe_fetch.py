"""
Tests for oauth2_provider.core.safe_fetch (SSRF-hardened HTTPS fetching).

The SSRF pinning behavior (IP validation, deadline sharing, redirect refusal)
is additionally exercised through the CIMD suite; these tests cover the
generic entry points directly, with DNS and the connection pool faked.
"""

import pytest

from oauth2_provider.core import safe_fetch
from oauth2_provider.core.safe_fetch import SafeFetchError, fetch_https_json


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
        "oauth2_provider.core.safe_fetch.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    mocker.patch(
        "oauth2_provider.core.safe_fetch.urllib3.HTTPSConnectionPool", _fake_pool_returning(response)
    )


@pytest.mark.parametrize(
    "ip, public",
    [
        ("93.184.216.34", True),
        ("2606:2800:220:1:248:1893:25c8:1946", True),
        # IPv4 multicast: is_global returns True for these on every supported CPython.
        ("224.0.0.1", False),
        ("239.255.255.250", False),
        ("233.252.0.1", False),
        ("ff0e::1", False),  # IPv6 global-scope multicast
        ("::ffff:224.0.0.1", False),  # IPv4-mapped multicast
        ("64:ff9b::e000:1", False),  # NAT64 wrapping multicast
        # Deprecated IPv4-compatible ::/96, refused whatever the embedded IPv4.
        ("::7f00:1", False),  # 127.0.0.1
        ("::a9fe:a9fe", False),  # 169.254.169.254
        ("::a00:1", False),  # 10.0.0.1
        ("::808:808", False),  # 8.8.8.8
        ("::", False),
        ("::1", False),
        # SIIT ::ffff:0:0:0/96, refused whatever the embedded IPv4.
        ("::ffff:0:7f00:1", False),
        ("::ffff:0:a00:1", False),
        ("::ffff:0:808:808", False),
        # 6to4 2002::/16, refused whatever the embedded IPv4.
        ("2002:7f00:1::1", False),
        ("2002:a9fe:a9fe::1", False),
        ("2002:5db8:d822::1", False),  # 93.184.216.34
        # Teredo 2001::/32, refused whatever the server and client IPv4.
        ("2001:0:4136:e378::3f57:fefe", False),
        ("2001:0:4136:e378::a247:27dd", False),  # both 93.184.216.34
        # Local-use NAT64 64:ff9b:1::/48 is translated by the site's own NAT64.
        ("64:ff9b:1::a00:1", False),
        ("64:ff9b:1::5db8:d822", False),
        # IPv4-mapped and well-known NAT64 are judged by the embedded IPv4.
        ("::ffff:127.0.0.1", False),
        ("::ffff:169.254.169.254", False),
        ("::ffff:93.184.216.34", True),
        ("64:ff9b::a9fe:a9fe", False),
        ("64:ff9b::5db8:d822", True),
    ],
)
def test_ip_is_public(ip, public):
    assert safe_fetch.ip_is_public(ip) is public


@pytest.mark.parametrize("ip", ["::7f00:1", "::ffff:0:a9fe:a9fe", "2002:7f00:1::1", "224.0.0.1"])
def test_fetch_refuses_host_resolving_to_refused_address(mocker, ip):
    family = 10 if ":" in ip else 2
    mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.getaddrinfo",
        return_value=[(family, 1, 6, "", (ip, 443))],
    )
    pool = mocker.patch("oauth2_provider.core.safe_fetch.urllib3.HTTPSConnectionPool")
    with pytest.raises(SafeFetchError, match="non-public address"):
        fetch_https_json("https://example.com/jwks.json", timeout=5, max_size=1024)
    pool.assert_not_called()


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


def test_fetch_https_json_rejects_deeply_nested_json(mocker):
    # A deeply nested document within the size cap makes json.loads raise
    # RecursionError; it must surface as the caller's error. Raised directly so
    # the test does not depend on the interpreter's recursion limit.
    _patch_network(mocker, _FakeHTTPResponse(body=b"[[[]]]"))
    mocker.patch("oauth2_provider.core.safe_fetch.json.loads", side_effect=RecursionError)
    with pytest.raises(SafeFetchError, match="not valid JSON") as excinfo:
        fetch_https_json("https://example.com/jwks.json", timeout=5, max_size=1024)
    assert isinstance(excinfo.value.__cause__, RecursionError)


def test_fetch_https_json_accepts_structured_json_suffix(mocker):
    _patch_network(
        mocker,
        _FakeHTTPResponse(headers={"Content-Type": "application/jwk-set+json"}, body=b'{"keys": []}'),
    )
    data, _ = fetch_https_json("https://example.com/jwks.json", timeout=5, max_size=1024)
    assert data == {"keys": []}


def test_read_json_document_returns_object_and_headers():
    response = _FakeHTTPResponse(body=b'{"keys": []}')
    data, headers = safe_fetch.read_json_document(response, max_size=1024)
    assert data == {"keys": []}
    assert headers is response.headers


class _CallerError(Exception):
    pass


@pytest.mark.parametrize(
    "response",
    [
        _FakeHTTPResponse(status=404),
        _FakeHTTPResponse(headers={"Content-Type": "text/html"}),
        _FakeHTTPResponse(body=b'{"keys": [' + b"0, " * 64 + b"0]}"),
        _FakeHTTPResponse(body=b"not json"),
        _FakeHTTPResponse(body=b"[]"),
    ],
    ids=["non-200", "non-json-media-type", "oversized", "invalid-json", "non-object"],
)
def test_read_json_document_raises_callers_exception(response):
    with pytest.raises(_CallerError):
        safe_fetch.read_json_document(response, max_size=64, exc_class=_CallerError)


def test_media_type_is_json():
    assert safe_fetch.media_type_is_json("application/json") is True
    assert safe_fetch.media_type_is_json("application/jwk-set+json; charset=utf-8") is True
    assert safe_fetch.media_type_is_json("text/html") is False
    assert safe_fetch.media_type_is_json(None) is False


def test_exhausted_timeout_reports_explicit_message(mocker):
    mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.getaddrinfo",
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


def test_path_params_component_is_preserved(mocker):
    # urlparse would split ";v=2.json" off the path as legacy params; the
    # request target must keep the path verbatim.
    mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    captured = {}

    class _Pool:
        def __init__(self, **kwargs):
            pass

        def urlopen(self, method, path, **kwargs):
            captured["path"] = path
            return _FakeHTTPResponse(body=b'{"keys": []}')

        def close(self):
            pass

    mocker.patch("oauth2_provider.core.safe_fetch.urllib3.HTTPSConnectionPool", _Pool)
    fetch_https_json("https://example.com/jwks;v=2.json?x=1", timeout=5, max_size=1024)
    assert captured["path"] == "/jwks;v=2.json?x=1"
