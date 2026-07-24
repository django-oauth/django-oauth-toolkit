Pushed Authorization Requests (PAR)
===================================

`RFC 9126 <https://www.rfc-editor.org/rfc/rfc9126>`_ defines the *pushed authorization request*
(PAR) endpoint. Instead of sending the authorization request parameters through the user agent as
query parameters, the client pushes them directly to the authorization server over an
authenticated back channel and receives a short-lived, single-use ``request_uri`` in exchange. The
subsequent call to the authorization endpoint carries only ``client_id`` and ``request_uri``.

This protects the request's integrity and confidentiality, lets the server authenticate the client
before any user interaction, and avoids authorization-request URLs growing too large. A copy of the
RFC is vendored at ``rfcs/rfc9126.txt``.

PAR is enabled by default and served at ``par/`` (relative to where you mounted
``oauth2_provider.urls``). When enabled, the RFC 8414 metadata document advertises the
``pushed_authorization_request_endpoint``.

Pushing a request
-----------------

The client authenticates exactly as it would at the token endpoint (HTTP Basic, ``client_secret``
in the body, etc.) and POSTs the authorization-request parameters:

.. code-block:: http

    POST /o/par/ HTTP/1.1
    Host: example.com
    Content-Type: application/x-www-form-urlencoded
    Authorization: Basic <base64(client_id:client_secret)>

    response_type=code&client_id=s6BhdRkqt3&state=af0ifjsldkj
    &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
    &scope=read+write&code_challenge=K2-...&code_challenge_method=S256

On success the server responds with ``201 Created``:

.. code-block:: json

    {
      "request_uri": "urn:ietf:params:oauth:request_uri:bwc4JK-ESC0w8acc191e-Y1LTC2",
      "expires_in": 60
    }

The client then starts the authorization flow with just the reference:

.. code-block:: http

    GET /o/authorize/?client_id=s6BhdRkqt3&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Abwc4JK-ESC0w8acc191e-Y1LTC2 HTTP/1.1

Behavior and limitations
------------------------

* **Single use.** A ``request_uri`` is consumed the first time it is presented to the authorization
  endpoint; presenting it again (or after it expires) is rejected. Its lifetime is controlled by
  ``PAR_REQUEST_URI_LIFETIME_SECONDS`` (default 60 seconds).
* **Client binding.** The ``request_uri`` is bound to the client that pushed it (RFC 9126 §2.2); a
  mismatched ``client_id`` at the authorization endpoint is rejected.
* **Authoritative parameters.** The pushed request is authoritative: any authorization-request
  parameters supplied alongside ``request_uri`` at the authorization endpoint (other than the
  ``client_id`` used for the binding check) are ignored, which prevents parameter injection.
* **Client authentication.** Confidential clients must authenticate; public clients are identified
  by ``client_id`` and should use PKCE. New/unregistered ``redirect_uri`` values (RFC 9126 §2.4) are
  **not** supported — redirect URIs must be pre-registered and match exactly.
* **Request objects.** JWT-Secured Authorization Requests (the ``request`` parameter, RFC 9126 §3 /
  RFC 9101) are **not** supported yet; such requests are rejected.

Requiring PAR
-------------

To require that clients use PAR to initiate authorization, set
``REQUIRE_PUSHED_AUTHORIZATION_REQUESTS`` to ``True``. Any authorization request without a
``request_uri`` is then rejected, and the metadata document advertises
``"require_pushed_authorization_requests": true``.

.. code-block:: python

    OAUTH2_PROVIDER = {
        "REQUIRE_PUSHED_AUTHORIZATION_REQUESTS": True,
    }

Enforcement can also be scoped to a single client by setting the application's
``require_pushed_authorization_requests`` field to ``True`` (RFC 9126 §6). The server-wide setting
is a floor: a per-client value never relaxes it.
