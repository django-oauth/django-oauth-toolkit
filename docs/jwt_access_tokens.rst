JWT Access Tokens (RFC 9068)
============================

By default ``django-oauth-toolkit`` issues opaque access tokens: random strings
that a resource server must send to the :doc:`introspection endpoint
<resource_server>` to learn anything about. `RFC 9068
<https://www.rfc-editor.org/rfc/rfc9068>`_ defines a standard JSON Web Token
(JWT) profile for access tokens ("``at+jwt``") so that a resource server can
validate the token and read its claims locally — verifying the signature against
the authorization server's published keys — without an introspection round trip.

The distinguishing feature is the JWT header ``typ`` value ``at+jwt``, which lets
a resource server tell an access token apart from an OpenID Connect ID token and
refuse to accept one in place of the other.

Enabling JWT access tokens
--------------------------

JWT access tokens reuse the same signing infrastructure as :doc:`OpenID Connect
<oidc>` ID tokens, so the signing key must be configured first:

* For ``RS256`` set ``OIDC_RSA_PRIVATE_KEY`` (see :ref:`Creating RSA private key
  <oidc>`).
* For ``HS256`` the application's (unhashed) ``client_secret`` is used as the HMAC
  key.

Then, per application, choose a signing ``algorithm`` and switch on
``jwt_access_token``::

    application.algorithm = Application.RS256_ALGORITHM  # or HS256_ALGORITHM
    application.jwt_access_token = True
    application.save()

Every access token that application is subsequently issued — through any grant —
is a signed ``at+jwt`` JWT instead of an opaque string. Applications that leave
``jwt_access_token`` at its default (``False``) are unaffected and keep receiving
opaque tokens, so the two styles can coexist on the same server.

Enabling ``jwt_access_token`` without a signing ``algorithm`` is rejected by
``Application.clean()``: a JWT access token must be signed.

Claims
------

The issued token carries the RFC 9068 claim set:

============= ===================================================================
Claim         Value
============= ===================================================================
``iss``       The issuer, as configured for OIDC (``OIDC_ISS_ENDPOINT`` or derived
              from the request).
``exp``       Expiry, ``ACCESS_TOKEN_EXPIRE_SECONDS`` after issuance.
``iat``       Issued-at time.
``aud``       The RFC 8707 ``resource`` parameter(s) when the client sent them;
              otherwise the application's ``client_id`` as the default audience.
``sub``       The user's primary key for grants involving a resource owner; the
              ``client_id`` for the client credentials grant (no resource owner).
``client_id`` The requesting client's ``client_id``.
``jti``       A unique token identifier.
``scope``     The granted scope, when any was requested.
============= ===================================================================

The JWT header contains ``typ: at+jwt`` and ``alg`` (the application's algorithm);
for ``RS256`` it also includes the ``kid`` of the signing key so a resource server
can select it from the JWKS.

Validating tokens as a resource server
--------------------------------------

The issued JWT is still stored as a normal ``AccessToken`` row, so for an
authorization server co-located with its resource server, token revocation and the
introspection endpoint keep working unchanged — an ``at+jwt`` is validated by the
usual database lookup.

For a resource server that validates tokens *locally* (RFC 9068 §4) — without a
database record or an introspection round trip — enable
``VALIDATE_JWT_ACCESS_TOKENS``::

    OAUTH2_PROVIDER = {
        # ...
        "VALIDATE_JWT_ACCESS_TOKENS": True,
    }

When on, a presented bearer token that is not found locally is validated as an
``at+jwt`` per RFC 9068 §4: the header ``typ`` must be ``at+jwt`` and ``alg`` must
be ``RS256`` (``none`` is rejected); the signature is verified against the server's
configured RSA keys (``OIDC_RSA_PRIVATE_KEY`` and
``OIDC_RSA_PRIVATE_KEYS_INACTIVE`` — the same keys published at the
:doc:`JWKS endpoint <oidc>`); the ``iss`` claim must exactly match the issuer; and
the current time must be before ``exp``. A token carrying RFC 8707 resource
indicators in ``aud`` is additionally audience-checked against the request URI, as
for opaque resource-restricted tokens.

Only asymmetric (``RS256``) tokens are validated this way; ``HS256`` uses a
per-client secret that a resource server does not hold. Because a locally validated
token is accepted on its signature and ``exp`` rather than on a live database
record, **revocation before expiry does not apply** to it — keep ``exp`` short.

Discovery
---------

A resource server discovers what it needs to validate tokens from the server's
metadata: the ``issuer`` to match against ``iss`` and the ``jwks_uri`` to fetch the
signing keys. Both are published by the :doc:`OpenID Connect discovery document
<oidc>` and by the :doc:`RFC 8414 authorization server metadata
<oauth2_server_metadata>` endpoint (``/.well-known/oauth-authorization-server``),
and the signing algorithms are advertised as
``id_token_signing_alg_values_supported``. RFC 9068 does not define a dedicated
discovery parameter for JWT access tokens.

Notes
-----

* JWT access tokens are readable by anyone who holds them. Do not place sensitive
  attributes in them without considering RFC 9068 §6 (Privacy Considerations); a
  client must treat the access token as opaque and must not depend on its contents.
* ``auth_time``, ``acr`` and ``amr`` (RFC 9068 §2.2.1) and the
  ``groups``/``roles``/``entitlements`` authorization claims (§2.2.3.1) are
  optional and are not emitted by default.
