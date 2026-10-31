"""
Tests for oauth2_provider.core.safe_fetch (SSRF-hardened HTTPS fetching).

The SSRF pinning behavior (IP validation, deadline sharing, redirect refusal)
is additionally exercised through the CIMD suite; these tests cover the
generic entry points directly, with DNS and the connection pool faked.
"""

import datetime
import http.server
import itertools
import socket
import ssl
import threading
import time

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


# post_form runs against real sockets on the loopback interface: what it adds over the
# fetch helpers -- a wall-clock deadline and TLS through a pinned address -- is exactly
# what a faked transport would hide.


class _FormServer:
    """Answer each POST with *status* and record what arrived."""

    def __init__(self, status=204, headers=None):
        received = self.received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                received.append(
                    {
                        "path": self.path,
                        "host": self.headers.get("Host"),
                        "content_type": self.headers.get("Content-Type"),
                        "body": self.rfile.read(length),
                    }
                )
                self.send_response(status)
                for name, value in (headers or {}).items():
                    self.send_header(name, value)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def form_server():
    servers = []

    def make(**kwargs):
        server = _FormServer(**kwargs)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


# A byte every 50 ms, so that no single read ever waits long enough for a socket
# timeout. "http" never finishes its response headers. "https-handshake" announces a
# 16 KiB TLS handshake record and never finishes sending it. "https-response" completes
# the handshake and then drips the response like "http" does, over TLS: each TLS read
# is its own operation with its own timeout, so only the deadline can end it.
HTTP_DRIP = b"HTTP/1.1 200 OK\r\nX-Pad: a"


@pytest.fixture
def dripping_port(tmp_path, trust):
    """Start a listener that answers a byte at a time, forever; return its port."""
    listeners = []
    stop = threading.Event()

    def start(kind):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        listeners.append(listener)
        server_context = None
        if kind == "https-response":
            cert_path, key_path = _self_signed_certificate(tmp_path, "localhost")
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(cert_path, key_path)
            trust(cert_path)

        def drip(conn):
            try:
                if server_context is not None:
                    conn = server_context.wrap_socket(conn, server_side=True)
                if kind == "https-handshake":
                    stream = itertools.chain(b"\x16\x03\x03\x40\x00", itertools.repeat(0))
                else:
                    stream = itertools.cycle(HTTP_DRIP)
                with conn:
                    for byte in stream:
                        if stop.is_set():
                            return
                        conn.send(bytes([byte]))
                        time.sleep(0.05)
            except OSError:
                return

        def accept():
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                threading.Thread(target=drip, args=(conn,), daemon=True).start()

        threading.Thread(target=accept, daemon=True).start()
        return listener.getsockname()[1]

    yield start
    stop.set()
    for listener in listeners:
        listener.close()


def _post_form_or_fail_fast(*args, **kwargs):
    """Run post_form, failing the test rather than hanging the run if it never returns."""
    outcome = {}

    def run():
        try:
            outcome["result"] = safe_fetch.post_form(*args, **kwargs)
        except Exception as exc:
            outcome["error"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(10)
    assert not worker.is_alive(), "post_form ignored its deadline"
    if "error" in outcome:
        raise outcome["error"]
    return outcome["result"]


def test_post_form_sends_the_fields_form_encoded(form_server):
    server = form_server()
    status, _ = safe_fetch.post_form(
        f"http://localhost:{server.port}/logout?rp=1",
        {"logout_token": "a.b.c"},
        timeout=5,
        require_public_address=False,
    )
    assert status == 204
    (request,) = server.received
    assert request["path"] == "/logout?rp=1"
    assert request["host"] == f"localhost:{server.port}"
    assert request["content_type"] == "application/x-www-form-urlencoded"
    assert request["body"] == b"logout_token=a.b.c"


def test_post_form_returns_a_redirect_without_following_it(form_server):
    server = form_server(status=302, headers={"Location": "https://elsewhere.example/"})
    status, headers = safe_fetch.post_form(
        f"http://127.0.0.1:{server.port}/", {"a": "b"}, timeout=5, require_public_address=False
    )
    assert status == 302
    assert headers["Location"] == "https://elsewhere.example/"
    assert len(server.received) == 1


@pytest.mark.parametrize(
    "kind, url",
    [
        ("http", "http://127.0.0.1:{port}/"),
        ("https-handshake", "https://127.0.0.1:{port}/"),
        ("https-response", "https://localhost:{port}/"),
    ],
)
def test_post_form_deadline_bounds_a_server_answering_a_byte_at_a_time(dripping_port, kind, url):
    port = dripping_port(kind)
    started = time.monotonic()
    with pytest.raises(SafeFetchError, match="timed out|deadline exceeded"):
        _post_form_or_fail_fast(url.format(port=port), {"a": "b"}, timeout=0.5, require_public_address=False)
    assert time.monotonic() - started < 2


def test_post_form_deadline_is_shared_across_addresses(mocker):
    # The first address takes 0.6 s to fail, the second never answers, and the deadline is
    # 1 s. Shared, the deadline ends the call at 1 s; were each attempt to start a budget
    # of its own, the second would run on to 1.6 s.
    closing = socket.socket()
    closing.bind(("127.0.0.1", 0))
    port = closing.getsockname()[1]
    hanging = socket.socket()
    try:
        hanging.bind(("127.0.0.2", port))
    except OSError:  # pragma: no cover - 127.0.0.2 is loopback on Linux, not everywhere
        closing.close()
        hanging.close()
        pytest.skip("needs a second loopback address")
    held = []

    def serve(listener, delay):
        listener.listen(1)
        conn, _ = listener.accept()
        held.append(conn)
        if delay is not None:
            time.sleep(delay)
            conn.close()

    threading.Thread(target=serve, args=(closing, 0.6), daemon=True).start()
    threading.Thread(target=serve, args=(hanging, None), daemon=True).start()
    mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("127.0.0.1", port)), (2, 1, 6, "", ("127.0.0.2", port))],
    )
    started = time.monotonic()
    try:
        with pytest.raises(SafeFetchError):
            _post_form_or_fail_fast(
                f"http://two.example:{port}/", {"a": "b"}, timeout=1, require_public_address=False
            )
    finally:
        for sock in [closing, hanging, *held]:
            sock.close()
    assert time.monotonic() - started < 1.3


def test_post_form_reports_a_deadline_spent_before_any_connection(mocker):
    # A budget that is gone before the first address is tried says so, rather than
    # reporting a transport error that never happened.
    mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    connect = mocker.patch("oauth2_provider.core.safe_fetch.socket.create_connection")
    with pytest.raises(SafeFetchError, match="budget exhausted before any connection attempt"):
        safe_fetch.post_form("https://late.example/", {"a": "b"}, timeout=0)
    connect.assert_not_called()


def test_post_form_bounds_connecting_by_the_deadline(mocker):
    # The watchdog only starts once connected, so the connect itself has to be held to what
    # is left of the deadline: an address that drops SYNs would otherwise hold the call for
    # the OS connect timeout, minutes on Linux.
    mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    connect = mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.create_connection", side_effect=OSError("unreachable")
    )
    with pytest.raises(SafeFetchError):
        safe_fetch.post_form("https://rp.example/logout", {"a": "b"}, timeout=1)
    assert 0 < connect.call_args.kwargs["timeout"] <= 1


@pytest.mark.parametrize("require_public_address", [True, False])
def test_post_form_falls_back_to_the_next_address(mocker, form_server, require_public_address):
    # A dual-stack relying party whose first address is unreachable still gets its request.
    server = form_server()
    refusing = socket.socket()
    refusing.bind(("127.0.0.1", 0))
    refused_port = refusing.getsockname()[1]
    refusing.close()

    def connect(address, timeout=None):
        # A plain connect, since socket.create_connection would consult the patched resolver.
        sock = socket.socket()
        sock.settimeout(timeout)
        try:
            sock.connect(("127.0.0.1", refused_port if address[0] == "198.51.100.1" else server.port))
        except OSError:
            sock.close()
            raise
        return sock

    mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("198.51.100.1", 80)), (2, 1, 6, "", ("93.184.216.34", 80))],
    )
    mocker.patch("oauth2_provider.core.safe_fetch.ip_is_public", return_value=True)
    mocker.patch("oauth2_provider.core.safe_fetch.socket.create_connection", side_effect=connect)
    status, _ = safe_fetch.post_form(
        "http://dual-stack.example/logout",
        {"a": "b"},
        timeout=5,
        require_public_address=require_public_address,
    )
    assert status == 204


def test_post_form_brackets_an_ipv6_literal_in_the_host_header(mocker, form_server):
    server = form_server()
    real_create_connection = socket.create_connection
    mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.create_connection",
        side_effect=lambda address, timeout=None: real_create_connection(
            ("127.0.0.1", server.port), timeout=timeout
        ),
    )
    status, _ = safe_fetch.post_form(
        "http://[2001:db8::1]:8080/logout", {"a": "b"}, timeout=5, require_public_address=False
    )
    assert status == 204
    assert server.received[0]["host"] == "[2001:db8::1]:8080"


def test_post_form_gives_a_pathless_uri_with_a_query_its_root_path(form_server):
    server = form_server()
    status, _ = safe_fetch.post_form(
        f"http://127.0.0.1:{server.port}?rp=1", {"a": "b"}, timeout=5, require_public_address=False
    )
    assert status == 204
    assert server.received[0]["path"] == "/?rp=1"


def test_post_form_reports_a_response_that_is_not_http():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def answer():
        conn, _ = listener.accept()
        conn.recv(65536)
        conn.sendall(b"NOT-HTTP garbage\r\n\r\n")
        conn.close()

    threading.Thread(target=answer, daemon=True).start()
    try:
        with pytest.raises(SafeFetchError):
            safe_fetch.post_form(
                f"http://127.0.0.1:{listener.getsockname()[1]}/",
                {"a": "b"},
                timeout=5,
                require_public_address=False,
            )
    finally:
        listener.close()


def test_post_form_deadline_starts_after_resolving_the_host(mocker, form_server):
    # The timeout bounds the HTTP exchange; resolving the host is bounded by the system
    # resolver instead, so a slow lookup does not eat into the exchange's budget.
    server = form_server()
    real_getaddrinfo = socket.getaddrinfo

    def slow_for_the_named_host(host, *args, **kwargs):
        if host == "slow-dns.example":
            time.sleep(0.6)
            return [(2, 1, 6, "", ("127.0.0.1", server.port))]
        return real_getaddrinfo(host, *args, **kwargs)

    mocker.patch("oauth2_provider.core.safe_fetch.socket.getaddrinfo", side_effect=slow_for_the_named_host)
    status, _ = safe_fetch.post_form(
        f"http://slow-dns.example:{server.port}/logout", {"a": "b"}, timeout=0.3, require_public_address=False
    )
    assert status == 204


def test_post_form_connects_to_the_address_it_validated(mocker):
    # The defence against DNS rebinding: a second lookup, which could answer with an
    # internal address, must never happen; the connection goes to the address checked.
    answers = iter([[(2, 1, 6, "", ("93.184.216.34", 443))], [(2, 1, 6, "", ("127.0.0.1", 443))]])
    resolver = mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.getaddrinfo", side_effect=lambda *a, **k: next(answers)
    )
    connect = mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.create_connection", side_effect=OSError("stop here")
    )
    with pytest.raises(SafeFetchError, match="stop here"):
        safe_fetch.post_form("https://rebinding.example/logout", {"a": "b"}, timeout=5)
    assert resolver.call_count == 1
    assert connect.call_args.args[0] == ("93.184.216.34", 443)


def test_post_form_sends_an_internationalised_url_encoded(mocker, form_server):
    # The host goes out as its A-label, and the path and query percent-encoded, as
    # requests and browsers send them; nothing outside ASCII reaches the request line.
    server = form_server()
    mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("127.0.0.1", server.port))],
    )
    status, _ = safe_fetch.post_form(
        f"http://bücher.example:{server.port}/logoüt path?rp=ä",
        {"a": "b"},
        timeout=5,
        require_public_address=False,
    )
    assert status == 204
    (request,) = server.received
    assert request["host"] == f"xn--bcher-kva.example:{server.port}"
    assert request["path"] == "/logo%C3%BCt%20path?rp=%C3%A4"


def test_post_form_encodes_a_stray_percent_and_keeps_valid_escapes(mocker, form_server):
    server = form_server()
    status, _ = safe_fetch.post_form(
        f"http://127.0.0.1:{server.port}/a%41%zz%?q=%7E%",
        {"a": "b"},
        timeout=5,
        require_public_address=False,
    )
    assert status == 204
    assert server.received[0]["path"] == "/a%41%25zz%25?q=%7E%25"


@pytest.mark.parametrize(
    "host",
    [
        "a" * 64 + ".example",  # a label over 63 characters
        "bad\u3002\u3002name.example",  # ideographic full stops: an empty label
    ],
)
def test_post_form_reports_an_unencodable_host_as_its_own_error(host):
    with pytest.raises(SafeFetchError):
        safe_fetch.post_form(f"https://{host}/logout", {"a": "b"}, timeout=1)


@pytest.mark.parametrize(
    "url",
    [
        "https://169.254.169.254/latest/meta-data/",
        "https://10.0.0.1/logout",
        "http://127.0.0.1:6379/",
        "https://[::1]/logout",
        "https://[::ffff:127.0.0.1]/logout",
        "https://localhost/logout",
    ],
)
def test_post_form_refuses_non_public_addresses(url):
    with pytest.raises(SafeFetchError, match="non-public address"):
        safe_fetch.post_form(url, {"a": "b"}, timeout=1)


@pytest.mark.parametrize(
    "url, message",
    [
        ("ftp://example.com/", "http or https"),
        ("https:///logout", "must contain a host"),
        ("https://user@example.com/", "userinfo"),
        ("https://example.com:99999/", "invalid port"),
        ("https://[::1/logout", "URL is invalid"),
    ],
)
def test_post_form_rejects_invalid_urls(url, message):
    with pytest.raises(SafeFetchError, match=message):
        safe_fetch.post_form(url, {"a": "b"}, timeout=1)


def _self_signed_certificate(tmp_path, certificate_name):
    """Write a self-signed certificate for *certificate_name*; return (cert, key) paths."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, certificate_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(certificate_name)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return cert_path, key_path


def _tls_server(tmp_path, certificate_name):
    """An https form server presenting a self-signed certificate for *certificate_name*."""
    cert_path, key_path = _self_signed_certificate(tmp_path, certificate_name)
    server = _FormServer()
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    server._server.socket = server_context.wrap_socket(server._server.socket, server_side=True)
    return server, cert_path


@pytest.fixture
def trust(mocker):
    """Make post_form's default TLS context trust one extra certificate."""
    create_default_context = ssl.create_default_context

    def install(cert_path):
        def context():
            ctx = create_default_context()
            ctx.load_verify_locations(cert_path)
            return ctx

        mocker.patch("oauth2_provider.core.safe_fetch.ssl.create_default_context", context)

    return install


def test_post_form_verifies_tls_against_the_hostname_not_the_pinned_address(tmp_path, trust):
    # The connection goes to the validated address, while SNI and certificate
    # verification still use the name in the URL.
    server, cert_path = _tls_server(tmp_path, "localhost")
    trust(cert_path)
    try:
        status, _ = safe_fetch.post_form(
            f"https://localhost:{server.port}/logout", {"a": "b"}, timeout=5, require_public_address=False
        )
    finally:
        server.close()
    assert status == 204


def test_post_form_verifies_a_fully_qualified_hostname_without_its_trailing_dot(mocker, tmp_path, trust):
    # Certificates name the host without the root label's dot, as urllib3 also assumes.
    server, cert_path = _tls_server(tmp_path, "localhost")
    trust(cert_path)
    mocker.patch(
        "oauth2_provider.core.safe_fetch.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("127.0.0.1", server.port))],
    )
    try:
        status, _ = safe_fetch.post_form(
            f"https://localhost.:{server.port}/logout", {"a": "b"}, timeout=5, require_public_address=False
        )
    finally:
        server.close()
    assert status == 204
    assert server.received[0]["host"] == f"localhost:{server.port}"


def test_post_form_refuses_a_certificate_for_another_name(tmp_path, trust):
    server, cert_path = _tls_server(tmp_path, "other.example")
    trust(cert_path)
    try:
        with pytest.raises(SafeFetchError, match="certificate"):
            safe_fetch.post_form(
                f"https://localhost:{server.port}/logout", {"a": "b"}, timeout=5, require_public_address=False
            )
    finally:
        server.close()
    assert server.received == []
