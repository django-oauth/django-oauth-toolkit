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

Native and desktop clients (a primary CIMD audience) usually listen on a loopback redirect whose
port is assigned at runtime. A metadata document is static, so such a client registers a portless
loopback redirect URI (e.g. ``http://localhost/callback``) and relies on the RFC 8252 §7.3 any-port
exemption at authorization time. That exemption covers the ``127.0.0.1`` / ``[::1]`` literals out of
the box, but the ``localhost`` spelling additionally requires ``ALLOW_LOCALHOST_LOOPBACK``, so
deployments enabling CIMD for such clients will usually want that setting too.

How it works
------------

When an authorization or token request arrives with a ``client_id`` that is an ``https`` URL and no
application is stored for it, the server fetches and validates the document, then persists a single
:class:`~oauth2_provider.models.Application` keyed on the URL, with ``registration_source`` set to
``"cimd"``. ``can_introspect`` is not client metadata: the row gets the default ``True``, and a
later re-fetch leaves it as it is, so a value an administrator set in the admin survives refreshes
(see :ref:`introspection-authorization`). A CIMD client using ``none`` is public, so it can
introspect only with an access token carrying the ``introspection`` scope; one using
``private_key_jwt`` is confidential and can also introspect by authenticating with a client
assertion. To turn the flag off as CIMD clients are first seen, see
:ref:`introspection-open-registration`.
Subsequent requests (and refresh-token exchanges) load that stored application without re-fetching,
until its cached metadata expires (``cimd_expires_at``), at which point the next use re-fetches.

Because the application is keyed on the URL, distinct clients map to distinct rows and the store is
bounded by the number of distinct client URLs rather than growing per registration.

Validation follows the spec: the document's ``client_id`` must equal the URL it was fetched from, and
the document must register at least one redirect URI (only redirect-based grants are supported),
matched exactly as for any other application. The document carries no ``client_secret``. A client is
either public, with ``token_endpoint_auth_method`` ``none`` (the default when the document omits it),
or confidential with ``private_key_jwt``: it then publishes exactly one of an inline ``jwks`` or an
HTTPS ``jwks_uri`` (an empty ``jwks_uri`` counts as absent), is stored as a confidential application
with that key source, and authenticates at the token endpoint with an RFC 7523 client assertion
verified by the same machinery as a manually registered client, including the hardened fetch and
caching of a ``jwks_uri`` (see :doc:`rfc7523`).
A ``private_key_jwt`` client must use the authorization code grant: the implicit grant issues tokens
at the authorization endpoint without any client authentication, which the draft (section 6.2) does
not allow for a client that registered keys.
Whatever the method, a document carrying both ``jwks`` and a non-empty ``jwks_uri`` is refused, as
RFC 7591 section 2 requires and as Dynamic Client Registration does. Earlier releases accepted such a
document when it chose ``none``, ignoring both fields; a client stored from one keeps its last good
registration but no longer picks up document changes until one of the two fields is removed.
The method is recorded in the application's ``token_endpoint_auth_method`` field.

A document choosing ``none`` is always accepted, although the default advertised lists do not name
that method. One choosing ``private_key_jwt`` is accepted only when the server advertises the method
in ``OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED`` and, with OpenID Connect enabled, in
``OIDC_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED`` as well (see :doc:`settings`), since its client may
have picked it from either discovery document. The lists are read by
whichever process performs the fetch and the result is persisted for every node sharing the
database, so all nodes must agree on them: a node that omits ``private_key_jwt`` refuses a document
that chooses it, and will not load a client already stored with it, whichever node registered the
client before. Such a client can then neither start an authorization request at that node nor
authenticate to it as a client, so it obtains no new tokens there, not even by refreshing; access
tokens already issued to it stay valid until they expire or are revoked. The stored application is
left as it is, so advertising the method again restores the
client without a re-fetch. The refusal is a policy decision rather than a failed fetch, so it does
not arm the failure backoff that the nodes share; it arms a backoff of its own, also lasting
``CIMD_FAILURE_BACKOFF_SECONDS``, whose cache key includes a digest of the node's policy. Refetches
of a refused document are bounded, but the refusal neither blocks nodes with a different policy nor
outlives a policy change. Any other method is refused, including every shared-secret one, which the
draft forbids (section 4.1) because CIMD provides no way to establish a shared secret.

A document may also publish ``token_endpoint_auth_methods_supported``, listing every method the client
can use. The parameter is defined by `OpenID Connect RP Metadata Choices 1.0
<https://openid.net/specs/openid-connect-rp-metadata-choices-1_0.html>`_ and registered in the IANA
OAuth client metadata registry, which the draft uses for client metadata. When the method it chose in
``token_endpoint_auth_method`` is not one this server registers,
the first offered method this server does register is used instead; when the chosen method is
registrable here, it is honoured as chosen and never downgraded, because the spec (section 6.2) has the
authorization server require client authentication of the registered type. Shared-secret methods are
never registered, whatever a document offers. ChatGPT's published document has this shape: it chooses
``private_key_jwt`` and offers ``["none", "private_key_jwt"]``, so a server that advertises
``private_key_jwt`` registers it as a confidential client authenticating with a client assertion, while
one that does not registers it as the public client it can also be. A document refused because the
methods it names are registrable but not advertised here is a policy refusal, with the backoff described
above. Both fields are validated like the rest of the document: the single value must be a string and
the plural one an array of strings, a document that declares a shared-secret method is rejected whatever
the plural field offers (the draft forbids the declaration itself), and a declared method must appear in
the plural list when both are present, as RP Metadata Choices requires. A document that omits the single
value is read as choosing ``none`` unless it carries a plural list, in which case the list alone decides.

A client negotiated to ``none`` is a public client in every respect: it must call the token endpoint
with no client authentication, and any ``jwks`` or ``jwks_uri`` in its document is not stored. A client
that picks its method from the server's advertised ``token_endpoint_auth_methods_supported`` will only
find ``none`` if the server advertises it, so add ``"none"`` to
``OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED`` (and ``OIDC_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED`` when
OpenID Connect is enabled; see :doc:`settings`) on a server that expects such clients.

The same policy applies when the document of a client stored with ``none`` switches to
``private_key_jwt``. A node that does not advertise the method refuses the re-fetched document, and
a refused re-fetch keeps the last good registration, so that node goes on serving the client as
public, with its stored metadata, and picks up none of the document's changes until the document
stops choosing ``private_key_jwt`` or the node advertises it. A node that does advertise the method
applies the switch for every node sharing the database, after which the nodes that do not advertise
it refuse the client as described above, so in a fleet whose nodes disagree, what such a client gets
depends on which node re-fetches first. Operators should advertise ``private_key_jwt`` consistently
across nodes. Bounding how long a stale registration is served is tracked in #1873.

The stored application is provisioned to sign ID Tokens with ``RS256`` whenever OpenID Connect is
enabled and the server has an ``OIDC_RSA_PRIVATE_KEY``, so a CIMD client can use OpenID Connect
without any manual step. This is the OpenID Connect Dynamic Client Registration 1.0 default for
``id_token_signed_response_alg``, and the only algorithm a CIMD client can use: ``HS256`` signs with
the client secret, which no CIMD client, public or confidential, can use (it is generated and
hashed, never disclosed). A document may name ``id_token_signed_response_alg`` explicitly; a value the
server cannot honour, which today means anything other than ``RS256``, makes the document invalid
rather than being silently replaced, since a CIMD client receives no registration response in which
a substituted value could be reported. Without OpenID Connect and a server key the application is
stored with no signing algorithm and cannot be issued ID Tokens; plain OAuth 2.0 flows still work.
The algorithm is re-derived on every re-fetch, so configuring the key later takes effect once the
cached metadata expires, and a row provisioned with the default drops ``RS256`` again once the key
is removed. The derivation uses the settings of whichever process performs the re-fetch and is
persisted for every node sharing the database, so all nodes must agree on ``OIDC_ENABLED`` and
``OIDC_RSA_PRIVATE_KEY``: one node without them would strip ``RS256`` from the row for all of them
until the next expiry. A re-fetch that changes the algorithm is logged at ``INFO`` by the
``oauth2_provider.authorization_server.cimd`` logger. A document that asks for ``RS256`` explicitly
is instead refused on re-fetch in that
state, like any other document the server cannot honour, so its last good registration is kept,
still marked ``RS256``: plain OAuth 2.0 flows keep working, ``openid`` requests fail until the key
returns or the document changes. The same applies to a document that names any other algorithm: it
was accepted before this behaviour existed, with the parameter ignored, and is now refused on every
re-fetch, so such a client keeps its last good registration but no longer picks up document changes
until the parameter is removed or set to ``RS256``.

Grant types the server does not support are dropped rather than fatal, which RFC 7591 section 2
permits by replacing requested metadata values with suitable defaults (section 3.2.1): a document
is rejected only when none of its ``grant_types`` is one this library registers. Because an
application stores a single grant, ``authorization_code`` is chosen when the document declares
more than one supported grant.

Settings
--------

``CIMD_ENABLED`` (default ``False``)
    Master switch for CIMD *resolution*: when ``False``, a URL ``client_id`` that is not already
    stored is treated as an unknown client — no document is fetched and no application is
    auto-registered. It does not disable URL ``client_id`` values wholesale: an application already
    stored with a URL ``client_id`` (for example one created manually, or persisted while CIMD was
    enabled) keeps working as an ordinary stored client.

``CIMD_METADATA_FETCHER`` (default ``"oauth2_provider.authorization_server.cimd.SafeMetadataFetcher"``)
    Import path to the fetcher. Override it to route fetches through an egress proxy or to apply
    site-specific policy. A fetcher's ``fetch(client_id)`` returns ``(metadata_dict, max_age_seconds)``
    or raises :class:`~oauth2_provider.authorization_server.cimd.CIMDError`.

``CIMD_REGISTRATION_PERMISSION_CLASSES`` (default ``("oauth2_provider.authorization_server.cimd.AllowAllCIMDPermission",)``)
    Permission classes run before any fetch; each must implement
    ``has_permission(request, client_id) -> bool`` and all must pass, an empty value denies
    everything. ``request`` is the *oauthlib* request the client_id arrived on (not a Django
    ``HttpRequest``; its ``headers`` carry the HTTP headers, for e.g. IP-bound policies). The
    default allows any URL, because resolution happens on the pre-auth authorize/token path where no
    authenticated user exists. Configure
    :class:`~oauth2_provider.authorization_server.cimd.HostAllowlistCIMDPermission` to restrict registration to known
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
    After a failed fetch, the same URL is not fetched again for this long. A document refused by the
    server's authentication-method policy is not fetched again for this long by nodes with the same
    policy.

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
    - does not follow redirects, bounds the whole fetch — every connection attempt across all resolved
      addresses — with a single total-time deadline (so neither a slow-drip body nor a hostname that
      resolves to many IPs can hold a worker past ``CIMD_FETCH_TIMEOUT_SECONDS``), caps the response
      size, and requires a JSON content type.

Client key retrieval
    A ``private_key_jwt`` document that publishes a ``jwks_uri`` adds a second client-controlled
    outbound fetch, made when the client's assertion is verified at the token, introspection or
    revocation endpoint. It uses the same SSRF-hardened transport as the metadata fetch, with its own
    size cap, timeout, cache and failure backoff (the ``CLIENT_ASSERTION_JWKS_*`` settings; see
    :doc:`rfc7523`), but it is **not** covered by the CIMD controls: ``CIMD_ALLOWED_HOSTS`` bounds
    which hosts may register, not where a registered document may point its ``jwks_uri``, and the
    CIMD in-flight cap and backoff do not apply to it. A deployment that relies on the host allowlist
    to bound outbound traffic should account for the key fetch; a document that publishes its keys
    inline causes none.

    The fetched set is cached for ``CLIENT_ASSERTION_JWKS_CACHE_TIMEOUT``. An assertion whose ``kid``
    the cached set does not hold can force a cache-bypassing refetch before its signature is
    verified, but at most one per ``CLIENT_ASSERTION_JWKS_REFETCH_INTERVAL_SECONDS`` for each
    ``jwks_uri``, and none while the failure backoff for that URL is armed; other such assertions
    are checked against the cached set. A client must therefore publish a new key at its
    ``jwks_uri`` at least one interval before it signs with it. :doc:`rfc7523` describes the limit
    and what it does not bound. It is kept per exact ``jwks_uri`` string, so it bounds the fetches
    for each URL but not the number of URLs: with open registration, anyone can host documents whose
    ``jwks_uri`` values differ only trivially, each with its own cached set and its own refetch
    allowance. ``HostAllowlistCIMDPermission`` limits who can publish such documents, and
    per-source rate limiting on the endpoints that accept client assertions limits how fast a caller
    can use them.

Denial of service
    Because a fetch happens on first sight of a URL, a flood of distinct bad URLs could otherwise tie
    up workers. This is bounded by the tight ``CIMD_FETCH_TIMEOUT_SECONDS`` (connect, read, and total),
    the ``CIMD_MAX_CONCURRENT_FETCHES`` in-flight cap (excess requests fail fast), and the
    ``CIMD_FAILURE_BACKOFF_SECONDS`` per-URL backoff that suppresses repeated fetches of a failing URL.
    A document refused by the server's authentication-method policy (described above) is fetched
    successfully, so it does not arm that shared backoff, but it arms a backoff of the same length
    scoped to the node's policy, so neither first sight of such a document nor a stored client whose
    method was de-advertised can make the server refetch it on every request, while a node with a
    different policy is never blocked and a policy change takes effect at once. Both the cap and the
    backoffs are **per process** (the backoffs live in Django's cache; under the default local-memory
    backend they are per process), so across *N* server processes the real ceilings
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

Confidential clients by registration
    A CIMD client registered with ``private_key_jwt`` is a confidential client wherever the server
    authenticates clients, including token introspection (it keeps the default ``can_introspect``)
    and any view built on ``ClientProtectedResourceView``. With open registration (the default
    ``AllowAllCIMDPermission``) anyone able to host a document can mint one, so a server that
    advertises ``private_key_jwt`` with CIMD enabled should bound registration with
    ``HostAllowlistCIMDPermission`` and ``CIMD_ALLOWED_HOSTS``, and turn ``can_introspect`` off as
    such clients are first seen unless they should introspect (see
    :ref:`introspection-open-registration`).

Credential changes on refresh
    A re-fetch replaces the stored authentication method and key source with whatever the document
    now publishes: a rotated inline key set takes effect at the next re-fetch, and a client may move
    between ``none`` and ``private_key_jwt``. The set behind a ``jwks_uri`` is re-read when its
    cached copy expires, or earlier for an assertion with an unknown ``kid``, but at most once per
    ``CLIENT_ASSERTION_JWKS_REFETCH_INTERVAL_SECONDS``, so a key published there at least one
    interval before the client signs with it is normally accepted on first use (see :doc:`rfc7523`).
    The draft (§6.3.1) leaves it to the server whether a change of method or keys should revoke
    tokens or consent. This implementation keeps existing tokens and grants, treating rotation as
    routine hygiene, and logs every method change and every change to the stored key source at
    ``INFO`` on the ``oauth2_provider.authorization_server.cimd`` logger; a deployment that wants a
    stricter policy can act on those messages. Only the stored key source is compared: an inline
    ``jwks``, or the ``jwks_uri`` value itself. The key set behind a ``jwks_uri`` is fetched when an
    assertion is verified and is never compared, so a rotation published there is not logged,
    although §6.3.1 lists a change in "the contents at the jwks_uri" among those a server may act
    on.

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
