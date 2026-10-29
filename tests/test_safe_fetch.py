"""
Tests for oauth2_provider.core.safe_fetch (SSRF-hardened HTTPS fetching).

The SSRF pinning behavior (IP validation, deadline sharing, redirect refusal)
is additionally exercised through the CIMD suite; these tests cover the
generic entry points directly, with DNS and the connection pool faked, and the
wall-clock deadline against a local TLS server that drips its response.
"""

import datetime
import socket
import ssl
import threading
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

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


def test_dns_resolution_counts_against_the_deadline(mocker):
    def slow_resolve(*args, **kwargs):
        time.sleep(0.3)
        return ["93.184.216.34"]

    mocker.patch.object(safe_fetch, "resolve_and_validate", side_effect=slow_resolve)
    with pytest.raises(SafeFetchError, match="timeout budget exhausted"):
        fetch_https_json("https://example.com/jwks.json", timeout=0.2, max_size=1024)


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


def _make_certificates(directory, hostname):
    """Write a CA and a leaf certificate for *hostname*; return (ca_pem, cert_path, key_path).

    A real CA rather than a self-signed leaf, because the default client
    context sets VERIFY_X509_STRICT on newer Pythons, which rejects a leaf
    acting as its own trust anchor.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "safe_fetch test CA")])
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ca_ski, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return ca.public_bytes(serialization.Encoding.PEM).decode(), cert_path, key_path


class _DripServer:
    """A one-thread TLS server that sends *head*, then *drip* one byte at a time.

    It keeps dripping (cycling through *drip*) until stopped, so a fetch that
    is not cut off by its deadline never finishes on its own.
    """

    DRIP_INTERVAL = 0.05

    def __init__(self, ssl_context, head, drip):
        self._ssl_context = ssl_context
        self._head = head
        self._drip = drip
        self._stopped = threading.Event()
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._listener.settimeout(0.1)
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stopped.is_set():
            try:
                conn, _addr = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with conn:
                try:
                    self._handle(conn)
                except OSError:
                    # The client gave up (or rejected the certificate).
                    pass

    def _handle(self, conn):
        conn.settimeout(5)
        with self._ssl_context.wrap_socket(conn, server_side=True) as tls:
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = tls.recv(4096)
                if not chunk:
                    return
                request += chunk
            tls.sendall(self._head)
            position = 0
            while not self._stopped.wait(self.DRIP_INTERVAL):
                if not self._drip:
                    continue
                tls.sendall(self._drip[position : position + 1])
                position = (position + 1) % len(self._drip)

    def stop(self):
        self._stopped.set()
        self._listener.close()
        self._thread.join(5)


@pytest.fixture
def drip_server(mocker, tmp_path):
    """Start a TLS server for ``drip.test`` and return the document URL.

    DNS resolution is faked to the loopback address (which the real
    validation refuses) and the client trusts the test CA; everything else,
    SNI and certificate verification included, runs as in production.
    """
    ca_pem, cert_path, key_path = _make_certificates(tmp_path, "drip.test")
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    client_context = ssl.create_default_context(cadata=ca_pem)
    mocker.patch.object(safe_fetch, "resolve_and_validate", return_value=["127.0.0.1"])
    mocker.patch.object(safe_fetch.ssl, "create_default_context", return_value=client_context)
    servers = []

    def start(head, drip=b""):
        server = _DripServer(server_context, head, drip)
        servers.append(server)
        return f"https://drip.test:{server.port}/doc"

    yield start
    for server in servers:
        server.stop()


def _fetch_json_or_fail_fast(url, *, timeout, limit=10):
    """Run fetch_https_json in a thread; fail if it is still running after *limit* seconds.

    A regression of the deadline would otherwise hang the test for as long as
    the server drips. Returns ``(result, exception, elapsed_seconds)``.
    """
    outcome = {"result": None, "exc": None}

    def run():
        started = time.monotonic()
        try:
            outcome["result"] = fetch_https_json(url, timeout=timeout, max_size=16384)
        except Exception as exc:
            outcome["exc"] = exc
        outcome["elapsed"] = time.monotonic() - started

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(limit)
    assert not thread.is_alive(), f"fetch still running after {limit}s: the deadline did not bound it"
    return outcome["result"], outcome["exc"], outcome["elapsed"]


def test_fetch_over_tls_returns_document(drip_server):
    body = b'{"keys": []}'
    url = drip_server(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode()
        + body
    )
    result, exc, _elapsed = _fetch_json_or_fail_fast(url, timeout=5)
    assert exc is None
    assert result[0] == {"keys": []}


def test_fetch_over_tls_verifies_certificate_hostname(drip_server):
    url = drip_server(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    _result, exc, _elapsed = _fetch_json_or_fail_fast(url.replace("drip.test", "other.test"), timeout=5)
    assert isinstance(exc, SafeFetchError)
    assert "certificate" in str(exc).lower()


@pytest.mark.parametrize(
    "head,drip",
    [
        pytest.param(b"HTTP/1.1 200 OK\r\nX-Pad: ", b"a", id="headers"),
        pytest.param(
            b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16384\r\n\r\n{"keys": [',
            b" ",
            id="body",
        ),
        pytest.param(
            # Without a Content-Length the body ends at EOF, so the cut-off
            # alone leaves a complete-looking document: "{}" plus padding.
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
            b" ",
            id="body-until-eof",
        ),
    ],
)
def test_dripped_response_is_cut_off_at_the_deadline(drip_server, head, drip):
    # Each byte arrives well within the per-read socket timeout, so only a
    # wall-clock deadline stops this fetch.
    url = drip_server(head, drip)
    result, exc, elapsed = _fetch_json_or_fail_fast(url, timeout=0.5)
    assert result is None
    assert isinstance(exc, SafeFetchError)
    assert "timed out" in str(exc)
    assert elapsed < 3


def test_deadline_watchdog_wakes_a_blocked_read():
    left, right = socket.socketpair()
    with left, right:
        watchdog = safe_fetch._DeadlineWatchdog(0.2)
        watchdog.watch(left)
        # A regressed watchdog then fails with a timeout instead of hanging.
        left.settimeout(5)
        started = time.monotonic()
        assert left.recv(1) == b""
        assert time.monotonic() - started < 3
        assert watchdog.cancel() is True
        assert watchdog.cancel() is True


def test_deadline_watchdog_cancelled_before_the_deadline_leaves_the_socket_open():
    left, right = socket.socketpair()
    with left, right:
        watchdog = safe_fetch._DeadlineWatchdog(60)
        watchdog.watch(left)
        assert watchdog.cancel() is False
        right.sendall(b"x")
        assert left.recv(1) == b"x"
