Dynamic Client Registration
===========================

Django OAuth Toolkit includes support for the OAuth 2.0 Dynamic Client Registration Protocol
(`RFC 7591 <https://datatracker.ietf.org/doc/html/rfc7591>`_) and the OAuth 2.0 Dynamic Client
Registration Management Protocol (`RFC 7592 <https://datatracker.ietf.org/doc/html/rfc7592>`_).

These views are automatically available when you use
``include("oauth2_provider.urls")``.


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
     "client_secret": "...",
     "redirect_uris": ["https://example.com/callback"],
     "grant_types": ["authorization_code", "refresh_token"],
     "token_endpoint_auth_method": "client_secret_basic",
     "client_name": "My Application",
     "registration_access_token": "...",
     "registration_client_uri": "https://example.com/o/register/abc123/"
   }

Applications created through this endpoint are flagged with ``dcr_created=True`` on the
``Application`` model, so dynamically registered clients can be distinguished from manually
provisioned ones — the Django admin's application list can be filtered on this field.

GET/PUT/DELETE /o/register/{client_id}/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Read, update, or delete the client configuration (RFC 7592).  Requires a
``Bearer {registration_access_token}`` header issued during registration.

- **GET** — returns current client metadata (same format as registration response)
- **PUT** — accepts the same JSON body as POST; updates the application
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
|                                     |                                   | is supported per application     |
+-------------------------------------+-----------------------------------+----------------------------------+
| ``token_endpoint_auth_method: none``| ``client_type = "public"``        |                                  |
+-------------------------------------+-----------------------------------+----------------------------------+
| ``token_endpoint_auth_method: ...`` | ``client_type = "confidential"``  | Default                          |
+-------------------------------------+-----------------------------------+----------------------------------+

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
