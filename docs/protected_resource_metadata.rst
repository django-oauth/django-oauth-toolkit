OAuth 2.0 Protected Resource Metadata
=====================================

Django OAuth Toolkit provides a protected resource metadata endpoint based on
`RFC 9728 <https://www.rfc-editor.org/rfc/rfc9728>`_. This lets OAuth 2.0 clients
discover, for a given protected resource (API), which authorization server(s) issue
tokens for it, which scopes and bearer methods it accepts, and human-readable
details — the resource-server counterpart to the :doc:`authorization server
metadata <oauth2_server_metadata>` endpoint (RFC 8414).

URL Configuration
-----------------

RFC 9728 locates the metadata document at the *origin's*
``/.well-known/oauth-protected-resource`` (an RFC 8615 well-known URI). When the
resource identifier is the server's root URL (e.g. ``https://example.com``) the
document is at ``https://example.com/.well-known/oauth-protected-resource``. When the
resource identifier has a path component (e.g. ``https://example.com/api``) RFC 9728
appends that path *after* the well-known suffix:
``https://example.com/.well-known/oauth-protected-resource/api``.

The endpoint is registered in ``metadata_urlpatterns`` alongside the RFC 8414 routes,
so it is served out of the box by the default ``urlpatterns`` in
``oauth2_provider.urls``. To serve the strict path-component form at the domain root
for a resource whose identifier lives under a path, mount ``metadata_urlpatterns`` at
the root the same way as for RFC 8414:

.. code-block:: python

    from django.urls import include, path

    from oauth2_provider.urls import metadata_urlpatterns

    urlpatterns = [
        # Well-known metadata URIs (RFC 8414 + RFC 9728) at the domain root.
        path(
            "",
            include((metadata_urlpatterns, "oauth2_provider"), namespace="oauth2_metadata"),
        ),
        # The toolkit under your chosen prefix.
        path("api/", include("oauth2_provider.urls")),
    ]

Example response::

    HTTP/1.1 200 OK
    Content-Type: application/json
    Access-Control-Allow-Origin: *

    {
      "resource": "https://example.com",
      "authorization_servers": ["https://example.com/o"],
      "scopes_supported": ["read", "write"],
      "bearer_methods_supported": ["header"]
    }

The ``resource`` identifier is derived from the incoming request by default, by
splitting the request URL around the ``/.well-known/oauth-protected-resource`` marker
(any RFC 9728 path component that follows the marker is appended back to the base).
Set ``OAUTH2_PROTECTED_RESOURCE_IDENTIFIER`` to return an explicit value instead.

``authorization_servers`` defaults to this server's own authorization-server issuer:
``OIDC_ISS_ENDPOINT`` when configured, otherwise derived from the RFC 8414 metadata
route. Configure ``OAUTH2_PROTECTED_RESOURCE_AUTHORIZATION_SERVERS`` to advertise a
specific list. The optional ``resource_name``, ``resource_documentation``,
``resource_policy_uri`` and ``resource_tos_uri`` fields are only included when their
corresponding settings are set (see :doc:`settings`).

Every advertised value is produced by a ``get_*`` method on
``OAuthProtectedResourceMetadataView``, so a deployment serving several protected
resources (the RFC 9728 path-component form) can subclass the view and customise the
document per resource.

Advertising metadata in ``WWW-Authenticate`` challenges
-------------------------------------------------------

RFC 9728 §5.1 lets a protected resource point clients at its metadata document by
adding a ``resource_metadata`` parameter to the ``WWW-Authenticate: Bearer`` challenge
it returns on an authentication failure (per RFC 6750, a ``401 Unauthorized`` for a
missing/invalid token or a ``403 Forbidden`` for ``insufficient_scope``). This
behaviour is **opt-in** so the toolkit's existing resource-protection views,
decorators and authenticator keep their current behaviour unchanged. Opt in
explicitly per resource by using the dedicated RFC 9728 constructs:

* **Class-based views / mixin** —
  :class:`~oauth2_provider.views.mixins.ProtectedResourceMetadataMixin` and the
  ready-made views ``ProtectedResourceMetadataView``,
  ``ScopedProtectedResourceMetadataView``,
  ``ReadWriteScopedProtectedResourceMetadataView`` and
  ``ClientProtectedResourceMetadataView`` (in ``oauth2_provider.views.generic``). Set
  ``www_authenticate_realm`` on the view to advertise a realm.
* **Function-based views / decorators** — ``protected_resource_metadata`` and
  ``rw_protected_resource_metadata`` (in ``oauth2_provider.decorators``), the RFC 9728
  variants of ``protected_resource`` / ``rw_protected_resource``.
* **Django REST Framework** — ``OAuth2ProtectedResourceAuthentication`` (in
  ``oauth2_provider.contrib.rest_framework``), a subclass of ``OAuth2Authentication``.
  List it in a view's ``authentication_classes``.

Each of these returns a ``WWW-Authenticate`` header carrying a ``resource_metadata``
parameter pointing at the metadata document (with the RFC 6750 status described
above — ``401`` for a missing/invalid token, ``403`` for ``insufficient_scope``). The
parameter is omitted automatically when the metadata route cannot be resolved.

By default the advertised URL is derived by reversing the toolkit's
``oauth-resource-metadata`` route, so it points at wherever ``oauth2_provider.urls``
is mounted — e.g. ``https://example.com/.well-known/oauth-protected-resource`` for a
root mount, or ``https://example.com/o/.well-known/oauth-protected-resource`` under an
``o/`` prefix. Because it reverses the default ``oauth2_provider`` instance namespace,
a split/root ``metadata_urlpatterns`` mount under a *different* namespace (see the
:doc:`RFC 8414 docs <oauth2_server_metadata>`) is not used for the default; the
``o/`` toolkit mount in that layout supplies the URL instead.

To advertise a specific document — the strict RFC 9728 domain-root URL, or the
path-component form (``.../.well-known/oauth-protected-resource/<path>``) for a
resource whose identifier includes a path (e.g. a multi-tenant deployment) — set
``resource_metadata_url`` (or override ``get_resource_metadata_url(request)``) on the
mixin / DRF authenticator, or pass ``resource_metadata_url=`` to the decorators. RFC
9728 §3.3 expects the advertised metadata URL — and the ``resource`` value it returns
— to match the resource identifier, so path-based resources should advertise their
path-component URL.

.. note::

    The plain (non-metadata) ``ProtectedResourceView`` family and the
    ``protected_resource`` / ``rw_protected_resource`` decorators continue to return a
    bare ``403 Forbidden`` with no challenge, exactly as before.
