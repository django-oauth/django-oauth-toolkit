Client ID Metadata Documents (CIMD)
===================================

`draft-ietf-oauth-client-id-metadata-document
<https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/>`_ lets a client
identify itself with an ``https`` URL as its ``client_id``, instead of pre-registering or using
Dynamic Client Registration. The authorization server fetches that URL, reads the client's metadata
(the same shape as RFC 7591) from the document it returns, and resolves it to an application. A copy
of the draft is vendored at ``rfcs/draft-ietf-oauth-client-id-metadata-document-01.txt``.

CIMD is disabled by default. Enable it with:

.. code-block:: python

    OAUTH2_PROVIDER = {
        "CIMD_ENABLED": True,
    }

When enabled, the RFC 8414 metadata document advertises
``"client_id_metadata_document_supported": true``.

How it works
------------

When an authorization or token request arrives with a ``client_id`` that is an ``https`` URL and no
application is stored for it, the server fetches and validates the document, then persists a single
public :class:`~oauth2_provider.models.Application` keyed on the URL, with ``registration_source``
set to ``"cimd"``.
Subsequent requests (and refresh-token exchanges) load that stored application without re-fetching,
until its cached metadata expires (``cimd_expires_at``), at which point the next use re-fetches.

Because the application is keyed on the URL, distinct clients map to distinct rows and the store is
bounded by the number of distinct client URLs rather than growing per registration.

Validation follows the spec: the document's ``client_id`` must equal the URL it was fetched from, the
client must be public — ``token_endpoint_auth_method`` must be ``none`` (the spec forbids shared-secret
methods, and asymmetric methods such as ``private_key_jwt`` are not implemented) and the document must
not contain a ``client_secret`` — and redirect URIs are matched exactly as for any other application.

Settings
--------

``CIMD_ENABLED`` (default ``False``)
    Master switch. When ``False`` a URL ``client_id`` is treated as an unknown client.

``CIMD_METADATA_FETCHER`` (default ``"oauth2_provider.cimd.SafeMetadataFetcher"``)
    Import path to the fetcher. Override it to route fetches through an egress proxy or to apply
    site-specific policy. A fetcher's ``fetch(client_id)`` returns ``(metadata_dict, max_age_seconds)``
    or raises :class:`~oauth2_provider.cimd.CIMDError`.

``CIMD_REGISTRATION_PERMISSION_CLASSES`` (default ``("oauth2_provider.cimd.AllowAllCIMDPermission",)``)
    Permission classes run before any fetch; each must implement
    ``has_permission(client_id) -> bool`` and all must pass, an empty value denies everything. The
    default allows any URL, because resolution happens on the pre-auth authorize/token path where no
    authenticated user exists. Configure
    :class:`~oauth2_provider.cimd.HostAllowlistCIMDPermission` to restrict registration to known
    hosts.

``CIMD_ALLOWED_HOSTS`` (default ``[]``)
    Hosts accepted by ``HostAllowlistCIMDPermission``, using the same syntax as Django's
    ``ALLOWED_HOSTS``: an exact hostname, ``".example.com"`` for a domain and its subdomains, or
    ``"*"``.

``CIMD_FETCH_TIMEOUT_SECONDS`` (default ``5``)
    Connect and read timeout for the metadata fetch.

``CIMD_MAX_DOCUMENT_SIZE`` (default ``16384``)
    Maximum accepted document size in bytes. The draft recommends metadata documents stay around
    5 KB; the default leaves headroom while still bounding memory.

``CIMD_METADATA_MIN_AGE_SECONDS`` / ``CIMD_METADATA_MAX_AGE_SECONDS`` (defaults ``300`` / ``86400``)
    Lower and upper bounds on the cache lifetime. The document's ``Cache-Control: max-age`` is honoured
    within these bounds; ``no-store`` / ``no-cache`` use the lower bound; absence uses the upper bound.

``CIMD_FAILURE_BACKOFF_SECONDS`` (default ``60``)
    After a failed fetch, the same URL is not fetched again for this long.

``CIMD_MAX_CONCURRENT_FETCHES`` (default ``10``)
    Maximum number of in-flight fetches. Requests over the cap fail fast rather than queue. Set to
    ``0`` or ``None`` to disable the cap.

.. _cimd-security:

Security model
--------------

The fetch is an outbound HTTP request to a client-controlled URL, made inside the authorization
request flow (``validate_client_id`` runs before the user authenticates). That makes it the sensitive
part of the feature, and the default ``SafeMetadataFetcher`` and resolver are built around the threats
below.

Server-Side Request Forgery (SSRF)
    A malicious ``client_id`` URL could try to make the server reach an internal service or a cloud
    metadata endpoint. The default fetcher:

    - requires the ``https`` scheme, a path, and a valid port, and rejects URLs with a userinfo or
      fragment component or ``.``/``..`` path segments;
    - resolves the host and rejects it if **any** resolved address is non-public (private, loopback,
      link-local including ``169.254.169.254``, CGNAT, multicast, reserved), refusing the whole host
      rather than cherry-picking so a split public/internal result cannot be exploited. IPv6 forms that
      embed an internal IPv4 (IPv4-mapped, 6to4, the NAT64 ``64:ff9b::/96`` prefix) are decoded and
      judged by the embedded address, since those can otherwise read as globally routable;
    - connects to the validated IP while using the hostname only for TLS SNI, certificate verification
      and the ``Host`` header, so a second DNS lookup cannot rebind the connection to another address
      after validation;
    - does not follow redirects, bounds the whole fetch with a total-time deadline (so a slow-drip body
      cannot hold a worker past the timeout), caps the response size, and requires a JSON content type.

Denial of service
    Because a fetch happens on first sight of a URL, a flood of distinct bad URLs could otherwise tie
    up workers. This is bounded by the tight ``CIMD_FETCH_TIMEOUT_SECONDS`` (connect, read, and total),
    the ``CIMD_MAX_CONCURRENT_FETCHES`` in-flight cap (excess requests fail fast), and the
    ``CIMD_FAILURE_BACKOFF_SECONDS`` per-URL backoff that suppresses repeated fetches of a failing URL.
    Both the cap and the backoff are **per process** (the backoff lives in Django's cache; under the
    default local-memory backend it is per process), so across *N* server processes the real ceilings
    are ``× N``. Using a shared cache backend and adding per-source-IP rate limiting on the
    authorization endpoint (a reverse proxy or middleware) is **highly recommended** to make these
    bounds effective.

    A *successful* fetch persists an ``Application`` row. Rows are keyed on the URL, so the store is
    bounded by the number of *distinct* client URLs — but those are attacker-mintable (one public host
    can serve a valid document at unlimited paths). Two controls bound the row count: the
    ``CIMD_REGISTRATION_PERMISSION_CLASSES`` gate (with ``HostAllowlistCIMDPermission`` +
    ``CIMD_ALLOWED_HOSTS``, only allowlisted hosts can mint rows at all), and the
    :ref:`clearcimdapplications` management command, which prunes expired CIMD rows that hold no live
    tokens. Rate-limiting ``/authorize`` is still recommended, and deployments that cannot enumerate
    client hosts should run the pruning command on a schedule.

Consent phishing
    A CIMD document fully controls its ``client_name`` and ``redirect_uris``, and the draft does not
    require them to be same-origin with the ``client_id`` URL (§6.1, for Solid-OIDC compatibility). An
    attacker can therefore publish a document named after a well-known product with redirect URIs on an
    unrelated host, and ``refresh_if_stale`` overwrites a stored app's name/redirect URIs on refresh
    with no re-consent. A same-origin restriction is *not* imposed by default because the native
    clients this feature targets legitimately register loopback (``http://localhost``) redirects that
    are never same-origin with their ``https`` ``client_id``. Deployments enabling CIMD should surface
    the ``client_id`` **host** on the consent screen (draft §6.4) so users can see who they are
    authorizing.

Metadata binding
    The document's ``client_id`` must equal the URL it was fetched from, so a document cannot claim to
    be a different client or overwrite another URL's stored application. A URL that collides with a
    manually provisioned (non-CIMD) application is refused rather than taking it over.

Operational notes
    Resolution has a side effect: on first sight of a CIMD URL, a ``GET`` to ``/authorize`` triggers an
    outbound fetch and persists an ``Application`` on the default database. Deployments using a
    read-replica router should ensure the authorize/token views can write to the default database.
    Serving the last known-good document when a re-fetch fails is a deliberate choice of
    availability over freshness; it does not cache an error response (the draft forbids that),
    it just avoids locking out a client over a transient blip.
