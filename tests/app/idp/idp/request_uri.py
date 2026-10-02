"""
A request_uri fetcher for the OpenID Foundation conformance suite.

The suite serves the request objects of its ``oidcc-request-uri-*`` modules
from its own host, which inside the compose network resolves to a private
address and presents a self-signed certificate. The stock
:class:`~oauth2_provider.authorization_server.oidc.request_objects.SafeRequestURIFetcher`
deliberately refuses both, so this fetcher connects to the hosts listed in
``CONFORMANCE_REQUEST_URI_HOSTS`` (``host:port``) without those two checks and
hands every other ``request_uri`` to the stock fetcher. Every document-level
check (HTTP status, size cap) still runs via the inherited ``_read_document``,
and redirects are still not followed.

Enabled through
``OAUTH2_PROVIDER_OIDC_REQUEST_URI_FETCHER=idp.request_uri.ConformanceRequestURIFetcher``;
never use it outside a local test IdP.
"""

import warnings
from urllib.parse import urlsplit

import urllib3
from django.conf import settings

from oauth2_provider.authorization_server.oidc.request_objects import (
    REQUEST_OBJECT_ACCEPT,
    RequestURIFetchError,
    SafeRequestURIFetcher,
)
from oauth2_provider.settings import oauth2_settings


class ConformanceRequestURIFetcher(SafeRequestURIFetcher):
    def fetch(self, request_uri: str) -> str:
        parsed = urlsplit(request_uri)
        if parsed.scheme != "https" or parsed.netloc not in settings.CONFORMANCE_REQUEST_URI_HOSTS:
            return super().fetch(request_uri)
        timeout = oauth2_settings.OIDC_REQUEST_URI_FETCH_TIMEOUT_SECONDS
        path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
        pool = urllib3.HTTPSConnectionPool(
            host=parsed.hostname,
            port=parsed.port or 443,
            timeout=urllib3.Timeout(connect=timeout, read=timeout, total=timeout),
            retries=False,
            maxsize=1,
            cert_reqs="CERT_NONE",
            assert_hostname=False,
        )
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
                response = pool.urlopen(
                    "GET",
                    path,
                    headers={"Host": parsed.netloc, "Accept": REQUEST_OBJECT_ACCEPT},
                    redirect=False,
                    preload_content=False,
                )
            try:
                return self._read_document(response)
            finally:
                response.release_conn()
        except urllib3.exceptions.HTTPError as exc:
            raise RequestURIFetchError(f"could not fetch request_uri: {exc}") from exc
        finally:
            pool.close()
