OAuth 2.0 Authorization Server Metadata
========================================

Django OAuth Toolkit provides an authorization server metadata endpoint based on
`RFC 8414 <https://www.rfc-editor.org/rfc/rfc8414>`_. This allows OAuth 2.0 clients
to discover the server's capabilities and endpoint locations automatically, without
requiring OIDC to be enabled.

URL Configuration
-----------------

RFC 8414 locates the metadata document at the *origin's*
``/.well-known/oauth-authorization-server`` (an RFC 8615 well-known URI). When the
issuer is the server's root URL (e.g. ``https://example.com``) the document is at
``https://example.com/.well-known/oauth-authorization-server``. When the issuer has a
path component (e.g. ``https://example.com/o``) the strict RFC 8414 location appends
that path *after* the well-known suffix:
``https://example.com/.well-known/oauth-authorization-server/o``. In practice, some
OAuth 2.0 clients instead fall back to OIDC-style appending — issuer +
``/.well-known/oauth-authorization-server`` — when they cannot reach the domain root.

For maximum client compatibility, a deployment whose issuer lives under a path
(e.g. ``https://example.com/o``) should therefore expose discovery at all three URLs:

1. ``/o/.well-known/openid-configuration`` — OpenID Connect Discovery 1.0 (served by
   ``oidc_urlpatterns``; requires OIDC to be enabled).
2. ``/.well-known/oauth-authorization-server/o`` — the strict RFC 8414 form: the
   well-known URI at the domain root with the issuer's path appended.
3. ``/o/.well-known/oauth-authorization-server`` — the pragmatic fallback: the
   well-known suffix appended to the issuer URL.

The default ``urlpatterns`` in ``oauth2_provider.urls`` include
``metadata_urlpatterns``, so a prefixed include provides (1) and (3) automatically.
Add a root-mounted include of ``metadata_urlpatterns`` to also serve (2):

.. code-block:: python

    from django.urls import include, path

    from oauth2_provider.urls import metadata_urlpatterns

    urlpatterns = [
        # Strict RFC 8414 well-known URIs at the domain root. The distinct
        # instance namespace keeps reverse("oauth2_provider:...") for the
        # endpoints unambiguously pointing at the prefixed mount below.
        path(
            "",
            include((metadata_urlpatterns, "oauth2_provider"), namespace="oauth2_metadata"),
        ),
        # The toolkit — including OIDC discovery and the fallback metadata
        # routes — under your chosen prefix.
        path("o/", include("oauth2_provider.urls")),
    ]

All three documents report the same issuer: the fallback form derives it from the URL
segment *before* ``/.well-known/`` while the strict form uses the path component
*after* it, so every URL above yields ``https://example.com/o``. If you cannot serve
URLs at the domain root, strict RFC 8414 clients cannot discover a path-based issuer —
forms (1) and (3) remain available to everything else.

If you use ``include("oauth2_provider.urls")`` without a prefix, everything works
out of the box — ``metadata_urlpatterns`` is included in the default ``urlpatterns``
and the issuer is the server root.

Example response::

    HTTP/1.1 200 OK
    Content-Type: application/json
    Access-Control-Allow-Origin: *

    {
      "issuer": "https://example.com",
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
      "revocation_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic"
      ],
      "introspection_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic"
      ],
      "code_challenge_methods_supported": ["plain", "S256"]
    }

``jwks_uri`` is only included when OIDC is enabled and an RSA private key is
configured (see :ref:`OIDC_RSA_PRIVATE_KEY <oidc-rsa-private-key>`). When OIDC
is disabled, ``jwks_uri`` is omitted since the JWKS endpoint is not reachable.

The issuer URL is derived from the incoming request by default, by splitting the
request URL around the ``/.well-known/oauth-authorization-server`` marker:

* whatever precedes the marker becomes the issuer base, so a mount prefix is
  preserved (``https://example.com/o/.well-known/oauth-authorization-server`` yields
  the issuer ``https://example.com/o``);
* any RFC 8414 path component that follows the marker is appended back to the base
  (``https://example.com/.well-known/oauth-authorization-server/tenant1`` yields the
  issuer ``https://example.com/tenant1``).

To set the issuer explicitly instead, configure ``OIDC_ISS_ENDPOINT`` in your
``OAUTH2_PROVIDER`` settings (see :doc:`settings`); its value is then returned
verbatim.

The endpoint URLs (``authorization_endpoint``, ``token_endpoint`` …) are resolved
from wherever the toolkit routes are mounted and are independent of the issuer path.

The ``code_challenge_methods_supported``, ``token_endpoint_auth_methods_supported``,
``revocation_endpoint_auth_methods_supported`` and
``introspection_endpoint_auth_methods_supported`` fields are only included when the
endpoint they describe is registered; the three auth-methods fields reuse the
``token_endpoint_auth_methods_supported`` value.

The response fields ``response_types_supported``, ``grant_types_supported``, and
``token_endpoint_auth_methods_supported`` can be customised via settings — see
:doc:`settings` for details.
