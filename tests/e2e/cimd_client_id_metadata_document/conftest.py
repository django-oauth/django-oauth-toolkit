"""
Fixtures for the CIMD package: a CIMD-enabled IdP plus a loopback metadata
document server.

CIMD requires the authorization server to *fetch* the client's metadata
document, and the production ``SafeMetadataFetcher`` (rightly) refuses
loopback addresses and demands CA-verified TLS — neither of which a
self-contained test environment can satisfy. So this package launches its own
IdP with ``CIMD_ENABLED`` and the demo project's ``LoopbackMetadataFetcher``
(``tests/app/idp/idp/cimd.py``), which keeps every document-level check from
the stock fetcher and swaps only the transport: documents are served from a
local plain-HTTP server and addressed by ``https`` client_id URLs.
"""

import http.server
import json
import threading

import pytest

from tests.e2e import constants as c
from tests.e2e.helpers.idp_process import IdpServer
from tests.e2e.helpers.oauth_client import OAuthClient


class MetadataDocumentServer:
    """Serve client ID metadata documents for the live IdP to fetch.

    Documents are registered per path; ``add_client`` returns the ``https``
    client_id URL the IdP resolves (the loopback fetcher maps it back onto
    this plain-HTTP server). Fetches are counted per path so tests can assert
    caching behaviour (a stored application must not trigger a re-fetch).
    """

    def __init__(self):
        documents = self._documents = {}
        hits = self._hits = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits[self.path] = hits.get(self.path, 0) + 1
                if self.path not in documents:
                    self.send_error(404)
                    return
                body = documents[self.path]
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def client_id_for(self, path):
        return f"https://127.0.0.1:{self.port}{path}"

    def add_client(self, path, **overrides):
        """Register a valid metadata document at *path*; return its client_id URL.

        The document follows the RFC 7591 shape the draft prescribes, with the
        spec-mandated ``client_id`` echo of its own URL; ``overrides`` lets a
        test break individual fields (e.g. a mismatching ``client_id``).
        """
        client_id = self.client_id_for(path)
        document = {
            "client_id": client_id,
            "client_name": "E2E CIMD Client",
            "redirect_uris": [c.REDIRECT_URI],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "none",
        }
        document.update(overrides)
        self._documents[path] = json.dumps(document).encode()
        return client_id

    def hits(self, path):
        return self._hits.get(path, 0)

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture(scope="session")
def doc_server():
    server = MetadataDocumentServer().start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture(scope="session")
def cimd_idp():
    """A live IdP with CIMD enabled and the loopback metadata fetcher."""
    server = IdpServer(
        scopes=c.E2E_SCOPES,
        default_scopes=c.E2E_DEFAULT_SCOPES,
        pkce_required=False,
        pkce_required_client_ids=c.PKCE_REQUIRED_CLIENT_IDS,
        cimd_enabled=True,
        cimd_metadata_fetcher="idp.cimd.LoopbackMetadataFetcher",
    )
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture(scope="session")
def cimd_oauth(cimd_idp):
    return OAuthClient(cimd_idp.base_url)


@pytest.fixture
def cimd_user_session(cimd_oauth):
    return cimd_oauth.login(c.E2E_USERNAME, c.E2E_PASSWORD)
