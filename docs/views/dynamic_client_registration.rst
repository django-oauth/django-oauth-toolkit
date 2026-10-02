Dynamic Client Registration
===========================

Django OAuth Toolkit includes support for the OAuth 2.0 Dynamic Client Registration Protocol
(`RFC 7591 <https://datatracker.ietf.org/doc/html/rfc7591>`_) and the OAuth 2.0 Dynamic Client
Registration Management Protocol (`RFC 7592 <https://datatracker.ietf.org/doc/html/rfc7592>`_).

These views are automatically available when you use
``include("oauth2_provider.urls")``.

When ``DCR_ENABLED`` is on, the registration endpoint is advertised as
``registration_endpoint`` in the :doc:`RFC 8414 authorization server metadata
document </oauth2_server_metadata>`, so clients can discover it without
out-of-band configuration.


Endpoints
---------

POST /o/register/
~~~~~~~~~~~~~~~~~

Creates a new OAuth2 application (RFC 7591).  Authentication is controlled by
``DCR_REGISTRATION_PERMISSION_CLASSES``.

**Request body (JSON):**

.. code-block:: json

   {
     "redirect_uris": ["https://example.com/callback"],
     "grant_types": ["authorization_code"],
     "client_name": "My Application",
     "token_endpoint_auth_method": "client_secret_basic"
   }

**Response (201):**

.. code-block:: json

   {
     "client_id": "abc123",
     "client_id_issued_at": 1767225600,
     "client_secret": "...",
     "client_secret_expires_at": 0,
     "redirect_uris": ["https://example.com/callback"],
     "grant_types": ["authorization_code", "refresh_token"],
     "response_types": ["code"],
     "token_endpoint_auth_method": "client_secret_basic",
     "client_name": "My Application",
     "registration_access_token": "...",
     "registration_client_uri": "https://example.com/o/register/abc123/"
   }

``client_secret`` is returned only for clients that authenticate with it, and always together with
``client_secret_expires_at``, which is ``0`` because the toolkit's client secrets do not expire
(`RFC 7591 section 3.2.1 <https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1>`_).
``client_id_issued_at`` is the time the application was created, in seconds since the epoch.

Applications created through this endpoint are flagged with ``registration_source="dcr"`` on
the ``Application`` model, so dynamically registered clients can be distinguished from manually
provisioned ones (``registration_source="manual"``) — the Django admin's application list can be
filtered on this field.

``can_introspect`` is not client metadata: a registered client gets the default ``True``, and
neither registration nor an RFC 7592 update can set or change it; only an administrator can, in
the Django admin (see :ref:`introspection-authorization`). So anyone the registration permission
classes admit can register a confidential client and introspect with it straight away; to turn the
flag off as clients register, see :ref:`introspection-open-registration`.

GET/PUT/DELETE /o/register/{client_id}/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Read, update, or delete the client configuration (RFC 7592).  Requires a
``Bearer {registration_access_token}`` header issued during registration.

- **GET** — returns current client metadata (same format as the registration response, except
  ``client_secret`` and ``client_secret_expires_at``, which are only returned once on the initial
  ``POST`` since the secret is hashed at rest
  and cannot be recovered afterward)
- **PUT** — full replacement of the client metadata
  (`RFC 7592 section 2.2 <https://datatracker.ietf.org/doc/html/rfc7592#section-2.2>`_): accepts the
  same JSON body as POST and **must include every metadata field the client wants to keep**. Omitted
  fields are reset to their registration defaults — for example, an omitted ``token_endpoint_auth_method``
  reverts the client to confidential and an omitted ``client_name`` clears the name. Read the current
  configuration with ``GET`` first, modify it, and send the complete document back. Every
  ``token_endpoint_auth_method`` other than ``client_secret_jwt`` stores the secret hashed, whether
  the client was registered with it or switched to it by a later ``PUT``, and a hash cannot be turned
  back into the secret. A ``PUT`` switching such a client to ``client_secret_jwt``, whose HMAC key is
  the plaintext secret, is therefore refused with ``invalid_client_metadata``; register a new client
  instead.
- **DELETE** — deletes the application and all associated tokens; returns 204


Field Mapping
-------------

+-------------------------------------+-----------------------------------+----------------------------------+
| RFC 7591 field                      | DOT Application field             | Notes                            |
+=====================================+===================================+==================================+
| ``redirect_uris`` (array)           | ``redirect_uris`` (space-joined)  |                                  |
+-------------------------------------+-----------------------------------+----------------------------------+
| ``client_name``                     | ``name``                          |                                  |
+-------------------------------------+-----------------------------------+----------------------------------+
| ``grant_types`` (array)             | ``authorization_grant_type``      | ``refresh_token`` is ignored;    |
|                                     |                                   | only one non-refresh grant type  |
|                                     |                                   | is supported per application,    |
|                                     |                                   | except ``authorization_code``    |
|                                     |                                   | with ``implicit``, which maps to |
|                                     |                                   | ``openid-hybrid``; see the note  |
|                                     |                                   | below                            |
+-------------------------------------+-----------------------------------+----------------------------------+
| ``response_types`` (array)          | (not stored)                      | Checked against ``grant_types``  |
|                                     |                                   | and derived from them in         |
|                                     |                                   | responses; see the note below    |
+-------------------------------------+-----------------------------------+----------------------------------+
| ``token_endpoint_auth_method: none``| ``client_type = "public"``        |                                  |
+-------------------------------------+-----------------------------------+----------------------------------+
| ``token_endpoint_auth_method: ...`` | ``client_type = "confidential"``  | Default                          |
+-------------------------------------+-----------------------------------+----------------------------------+
| ``id_token_signed_response_alg``    | ``algorithm``                     | ``RS256`` by default when OIDC   |
|                                     |                                   | is enabled and the server has an |
|                                     |                                   | ``OIDC_RSA_PRIVATE_KEY``; see    |
|                                     |                                   | the note below                   |
+-------------------------------------+-----------------------------------+----------------------------------+

.. note::
    An application serves one grant type, so ``grant_types`` may name only one besides
    ``refresh_token``. The exception is an OpenID Connect hybrid client, whose response types need
    both ``authorization_code`` and ``implicit`` (`OpenID Connect Dynamic Client Registration 1.0
    section 2 <https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata>`_):
    that pair registers an application with the OpenID Connect hybrid grant, reported in responses
    as ``["authorization_code", "implicit", "refresh_token"]``. The pair is refused when the server
    serves none of the hybrid response types, as without OpenID Connect enabled.

    ``response_types`` is optional and not stored. When it is sent, every value must be one the
    registered grant can use on this server, or the request is refused with
    ``invalid_client_metadata`` (`RFC 7591 section 2.1
    <https://datatracker.ietf.org/doc/html/rfc7591#section-2.1>`_). A grant can use:

    - ``authorization_code``: ``code``;
    - ``implicit``: ``token``, ``id_token`` and ``id_token token``;
    - ``authorization_code`` with ``implicit``: ``code id_token``, ``code token`` and
      ``code id_token token``. A hybrid client cannot also use plain ``code``;
    - any other grant type: none;

    each only while the server advertises it: it must be listed in
    ``OIDC_RESPONSE_TYPES_SUPPORTED`` when OpenID Connect is enabled, otherwise in
    ``OAUTH2_RESPONSE_TYPES_SUPPORTED``, and the implicit ones are dropped while
    ``COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT`` is enabled, as in the discovery documents. The order
    of the space-separated values in a response type does not matter, but a repeated value is
    refused.

    Registration and management responses report those response types for the registered grant,
    in that canonical form, whether or not the request sent ``response_types``: the server
    provisions every response type the grant serves (RFC 7591 sections 2 and 3.2.1). A grant with
    none reports an empty list, because an omitted ``response_types`` would mean ``code``. Sending
    the reported list back in a ``PUT`` passes the check.

.. note::
    ``id_token_signed_response_alg`` (`OpenID Connect Dynamic Client Registration 1.0 section 2
    <https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata>`_) selects the
    algorithm the application signs ID Tokens with. When omitted, the OpenID Connect default of
    ``RS256`` applies whenever OpenID Connect is enabled and the server has an
    ``OIDC_RSA_PRIVATE_KEY``, so a dynamically registered client can use OpenID Connect without any
    manual step; otherwise the application is stored with no signing algorithm and cannot be issued
    ID Tokens. An explicit value the server cannot honour is rejected with ``invalid_client_metadata``
    rather than substituted.

    Registration accepts ``RS256`` only, which needs OpenID Connect enabled and an
    ``OIDC_RSA_PRIVATE_KEY``. ``HS256`` is not offered to dynamically registered clients, whatever
    their ``token_endpoint_auth_method``, because it would make the client secret the ID Token
    signing key. ``RS256`` is the algorithm `OpenID Connect Core 1.0 section 15.1
    <https://openid.net/specs/openid-connect-core-1_0.html#ServerMTI>`_ requires of an OpenID Provider
    that signs its ID Tokens, and the one OpenID Connect Discovery requires in
    ``id_token_signing_alg_values_supported``. Requesting ``HS256`` is refused with
    ``invalid_client_metadata``.

    The registered value is reported in registration and management responses, and ``PUT``
    re-derives it like every other field: a client registered before the server could sign gains
    ``RS256`` on its next update, and omitting the parameter resets it to the default. Because RFC
    7592 has the client send back every field it was given, a ``PUT`` may also echo the value a
    previous response reported, even one set outside registration:

    - an ``HS256`` an administrator set is kept when echoed, even while OpenID Connect is disabled,
      provided the client remains eligible for it: a confidential client using
      ``client_secret_jwt`` (the one method that keeps the secret in plaintext, as the HMAC key), a
      grant other than the implicit or hybrid one, and a stored client secret of at least 32 octets
      (`OpenID Connect Core 1.0 section 16.19
      <https://openid.net/specs/openid-connect-core-1_0.html#SymmetricKeyEntropy>`_; the default
      ``CLIENT_SECRET_GENERATOR_LENGTH`` of 128 satisfies it). Otherwise the ``PUT`` is refused with
      the reason and the application is left unchanged. A ``PUT`` asking for ``HS256`` when the
      application does not already have it is refused as at registration;
    - any other value an administrator set that registration does not offer, such as one a swapped
      application model allows, is likewise kept when echoed while the client stays on
      ``client_secret_jwt`` with a grant other than the implicit or hybrid one;
    - an echoed ``RS256`` is kept only while the server can still sign with it, that is with OpenID
      Connect enabled and an ``OIDC_RSA_PRIVATE_KEY``.

.. note::
    ``client_secret_basic`` and ``client_secret_post`` are both accepted at registration, since
    DOT's token endpoint authenticates confidential clients through either HTTP Basic auth or
    request-body credentials. The Application model does not record which method was requested, so
    per `RFC 7591 section 2 <https://datatracker.ietf.org/doc/html/rfc7591#section-2>`_ (the server
    "MAY replace any of the client's requested metadata values ... with suitable values") responses
    normalize the registered value to ``client_secret_basic``; clients may nevertheless use either
    method at the token endpoint.


Configuration
-------------

Add the following keys to ``OAUTH2_PROVIDER`` in your Django settings.  All are optional and have
sensible defaults.

``DCR_ENABLED``
    Set to ``True`` to activate the Dynamic Client Registration endpoints.
    When ``False`` (the default), both endpoints return ``404`` even though the
    URL patterns are always registered.

    Default: ``False``

``DCR_REGISTRATION_PERMISSION_CLASSES``
    A tuple of importable class paths whose instances are instantiated and called as
    ``instance.has_permission(request) -> bool``.  All classes must pass (AND logic).

    Default: ``("oauth2_provider.dcr.IsAuthenticatedDCRPermission",)``

    Built-in classes:

    * ``oauth2_provider.dcr.IsAuthenticatedDCRPermission`` — requires Django session authentication.
    * ``oauth2_provider.dcr.AllowAllDCRPermission`` — open registration; no authentication required.

    .. note::
        The registration view itself is ``csrf_exempt`` so that anonymous and
        ``Authorization``-header clients can POST to it. CSRF protection for
        session-cookie-authenticated requests is enforced by
        ``IsAuthenticatedDCRPermission`` instead: such requests must include a
        valid CSRF token or they are rejected. If you write a custom permission
        class that accepts Django session authentication, call
        ``oauth2_provider.dcr.enforce_csrf(request)`` for cookie-authenticated
        requests to keep the endpoint CSRF-protected.

``DCR_REGISTRATION_SCOPE``
    The scope string stored on the registration ``AccessToken`` used to protect the RFC 7592
    management endpoints.

    Default: ``"oauth2_provider:registration"``

``DCR_REGISTRATION_TOKEN_EXPIRE_SECONDS``
    Number of seconds until the registration access token expires, or ``None`` for a
    far-future expiry (year 9999, effectively non-expiring).

    Default: ``None``

``DCR_ROTATE_REGISTRATION_TOKEN_ON_UPDATE``
    When ``True``, a PUT request to the management endpoint revokes the current registration
    access token and issues a new one, returning it in the response.

    Default: ``True``


Examples
--------

Open registration (no auth required):

.. code-block:: python

    OAUTH2_PROVIDER = {
        "DCR_ENABLED": True,
        "DCR_REGISTRATION_PERMISSION_CLASSES": ("oauth2_provider.dcr.AllowAllDCRPermission",),
    }

.. note::
    With open registration anyone can register ``private_key_jwt`` clients with a ``jwks_uri``.
    The limit on cache-bypassing JWK Set re-fetches
    (``CLIENT_ASSERTION_JWKS_REFETCH_INTERVAL_SECONDS``, see :doc:`/rfc7523`) is kept per exact
    ``jwks_uri`` string, so registering many clients whose ``jwks_uri`` values differ only
    trivially (a query string, a path segment) multiplies the number of fetches unauthenticated
    requests can cause by the number of distinct values. Rate-limit or otherwise restrict the
    registration endpoint accordingly.

Custom permission class (e.g. initial-access token):

.. code-block:: python

    # myapp/permissions.py
    from oauth2_provider.utils import parse_bearer_token


    class InitialAccessTokenPermission:
        def has_permission(self, request) -> bool:
            # parse_bearer_token implements RFC 7235 / RFC 6750 semantics
            # (exact, case-insensitive scheme match); None means the header
            # is not a well-formed Bearer authorization.
            token = parse_bearer_token(request.META.get("HTTP_AUTHORIZATION", ""))
            if token is None:
                return False
            return MyInitialToken.objects.filter(token=token, active=True).exists()

    # settings.py
    OAUTH2_PROVIDER = {
        "DCR_ENABLED": True,
        "DCR_REGISTRATION_PERMISSION_CLASSES": ("myapp.permissions.InitialAccessTokenPermission",),
    }

Smoke test with ``curl``:

.. code-block:: bash

    # Register (open mode)
    curl -X POST https://example.com/o/register/ \\
      -H "Content-Type: application/json" \\
      -d '{"redirect_uris":["https://app.example.com/cb"],"grant_types":["authorization_code"]}'

    # Read configuration
    curl https://example.com/o/register/{client_id}/ \\
      -H "Authorization: Bearer {registration_access_token}"
