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

A resource server validates an ``at+jwt`` token per RFC 9068 §4: confirm the
header ``typ`` is ``at+jwt``, reject ``alg: none``, verify the signature using the
authorization server's keys published at the :doc:`JWKS endpoint <oidc>`
(``jwks_uri``), and check that ``iss`` matches the expected issuer, ``aud``
contains the resource server's identifier, and the current time is before ``exp``.

The issued JWT is still stored as a normal ``AccessToken`` row, so token
revocation and the introspection endpoint continue to work unchanged for
authorization servers that co-locate with their resource servers.

Notes
-----

* JWT access tokens are readable by anyone who holds them. Do not place sensitive
  attributes in them without considering RFC 9068 §6 (Privacy Considerations); a
  client must treat the access token as opaque and must not depend on its contents.
* ``auth_time``, ``acr`` and ``amr`` (RFC 9068 §2.2.1) and the
  ``groups``/``roles``/``entitlements`` authorization claims (§2.2.3.1) are
  optional and are not emitted by default.
