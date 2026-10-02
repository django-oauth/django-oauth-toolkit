"""
A client ``jwks_uri`` fetcher for the OpenID conformance stack.

The stock :class:`~oauth2_provider.authorization_server.client_assertions.SafeJWKSFetcher`
refuses every host that resolves to a non-public address, so it can never fetch
the conformance suite's ``jwks_uri``, which is served on the compose network.
This fetcher lets only the hosts named in ``JWKS_URI_PRIVATE_HOSTS`` resolve to
private addresses. It still requires ``https``, verifies the certificate against
the default trust store (``SSL_CERT_FILE`` in the compose stack), refuses
redirects and applies the stock document checks and limits. Every other host
goes through the stock fetcher unchanged. Enabled through
``OAUTH2_PROVIDER_CLIENT_ASSERTION_JWKS_FETCHER=idp.client_assertions.PrivateHostJWKSFetcher``;
never use it outside a local test IdP.
"""

import ssl
from typing import Any
from urllib.parse import urlsplit

import urllib3
from django.conf import settings

from oauth2_provider.authorization_server.client_assertions import ClientAssertionError, SafeJWKSFetcher
from oauth2_provider.core import safe_fetch
from oauth2_provider.settings import oauth2_settings


class PrivateHostJWKSFetcher(SafeJWKSFetcher):
    def fetch(self, uri: str) -> dict[str, Any]:
        parsed = urlsplit(uri)
        allowed = (
            parsed.scheme.lower() == "https"
            and parsed.username is None
            and parsed.password is None
            and parsed.hostname in settings.JWKS_URI_PRIVATE_HOSTS
        )
        if not allowed:
            return super().fetch(uri)
        timeout = oauth2_settings.CLIENT_ASSERTION_JWKS_FETCH_TIMEOUT_SECONDS
        pool = urllib3.PoolManager(
            ssl_context=ssl.create_default_context(),
            retries=False,
            timeout=urllib3.Timeout(connect=timeout, read=timeout, total=timeout),
        )
        try:
            response = pool.request(
                "GET",
                uri,
                headers={"Accept": safe_fetch.JSON_ACCEPT},
                redirect=False,
                preload_content=False,
            )
            try:
                data, _headers = safe_fetch.read_json_document(
                    response,
                    max_size=oauth2_settings.CLIENT_ASSERTION_JWKS_MAX_SIZE,
                    exc_class=ClientAssertionError,
                )
                return data
            finally:
                response.release_conn()
        except urllib3.exceptions.HTTPError as exc:
            raise ClientAssertionError(f"could not fetch client jwks_uri: {exc}") from exc
        finally:
            pool.clear()
