OAuth 2.0 Authorization Server Metadata
========================================

Django OAuth Toolkit provides an authorization server metadata endpoint based on
`RFC 8414 <https://www.rfc-editor.org/rfc/rfc8414>`_. This allows OAuth 2.0 clients
to discover the server's capabilities and endpoint locations automatically, without
requiring OIDC to be enabled.

The endpoint is available at ``/.well-known/oauth-authorization-server`` (e.g.
``/o/.well-known/oauth-authorization-server`` if you have mounted
``django-oauth-toolkit`` at ``/o/``).

Example response::

    HTTP/1.1 200 OK
    Content-Type: application/json
    Access-Control-Allow-Origin: *

    {
      "issuer": "https://example.com/o",
      "authorization_endpoint": "https://example.com/o/authorize/",
      "token_endpoint": "https://example.com/o/token/",
      "revocation_endpoint": "https://example.com/o/revoke_token/",
      "introspection_endpoint": "https://example.com/o/introspect/",
      "jwks_uri": "https://example.com/o/.well-known/jwks.json",
      "response_types_supported": ["code", "token"],
      "grant_types_supported": [
        "authorization_code",
        "implicit",
        "password",
        "client_credentials",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:device_code"
      ],
      "scopes_supported": ["read", "write"],
      "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic"
      ],
      "code_challenge_methods_supported": ["plain", "S256"]
    }

``jwks_uri`` is only included when OIDC is enabled and an RSA private key is
configured (see :ref:`OIDC_RSA_PRIVATE_KEY <oidc-rsa-private-key>`). When OIDC
is disabled, ``jwks_uri`` is omitted since the JWKS endpoint is not reachable.

The issuer URL is derived from the incoming request by default. To set it
explicitly, configure ``OIDC_ISS_ENDPOINT`` in your ``OAUTH2_PROVIDER`` settings
(see :doc:`settings`).

The response fields ``response_types_supported``, ``grant_types_supported``, and
``token_endpoint_auth_methods_supported`` can be customised via settings — see
:doc:`settings` for details.
