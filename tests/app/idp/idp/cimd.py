"""
A CIMD metadata fetcher for local end-to-end testing.

The stock :class:`~oauth2_provider.cimd.SafeMetadataFetcher` deliberately
refuses loopback addresses and requires a CA-verified TLS connection, so it
can never fetch from a test server on 127.0.0.1. The e2e compliance suite
serves its client ID metadata documents from a local plain-HTTP server
instead; this fetcher maps the ``https`` client_id URL onto that server.

Only the transport differs: every document-level check from the stock fetcher
(HTTP status, media type, size cap, cache-lifetime handling) still runs via
the inherited ``_read_document``. Enabled through
``OAUTH2_PROVIDER_CIMD_METADATA_FETCHER=idp.cimd.LoopbackMetadataFetcher``;
never use it outside a local test IdP.
"""

import urllib3

from oauth2_provider.cimd import CIMDError, SafeMetadataFetcher, _validate_client_id_url
from oauth2_provider.settings import oauth2_settings


class LoopbackMetadataFetcher(SafeMetadataFetcher):
    def fetch(self, client_id):
        parsed = _validate_client_id_url(client_id)
        timeout = oauth2_settings.CIMD_FETCH_TIMEOUT_SECONDS
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        pool = urllib3.HTTPConnectionPool(
            host=parsed.hostname,
            port=parsed.port or 443,
            timeout=urllib3.Timeout(connect=timeout, read=timeout, total=timeout),
            retries=False,
            maxsize=1,
        )
        try:
            response = pool.urlopen(
                "GET",
                path,
                headers={"Host": parsed.netloc, "Accept": "application/json"},
                redirect=False,
                preload_content=False,
            )
            try:
                return self._read_document(response)
            finally:
                response.release_conn()
        except urllib3.exceptions.HTTPError as exc:
            raise CIMDError(f"could not fetch client_id document: {exc}") from exc
        finally:
            pool.close()
