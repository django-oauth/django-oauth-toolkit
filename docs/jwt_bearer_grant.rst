JWT Bearer Authorization Grant (RFC 7523)
=========================================

`RFC 7523 <https://www.rfc-editor.org/rfc/rfc7523>`_ §2.1 defines the
``urn:ietf:params:oauth:grant-type:jwt-bearer`` authorization grant, built on the
RFC 7521 assertion framework. A client presents a **signed JWT assertion** at the
token endpoint and, when the assertion is trusted and its subject maps to a
resource owner, receives an access token — without an interactive authorization
step. It is the standard way to do service-to-service delegation and
trusted-issuer (STS / federation) token exchange.

.. note::
   This is the *authorization grant* profile (RFC 7523 §2.1). The separate
   *client authentication* profile (RFC 7523 §2.2, ``private_key_jwt`` /
   ``client_secret_jwt``) is documented in :doc:`rfc7523`. The two share the
   ``client_jwks`` / ``client_jwks_uri`` application fields and the
   ``CLIENT_ASSERTION_*`` low-level settings.

The grant is disabled by default. Enable it with:

.. code-block:: python

    OAUTH2_PROVIDER = {
        "JWT_BEARER_GRANT_ENABLED": True,
    }

When enabled, the RFC 8414 metadata document adds the grant identifier to
``grant_types_supported``.

How it works
------------

A client POSTs to the token endpoint:

.. code-block:: text

    POST /o/token/
    Content-Type: application/x-www-form-urlencoded

    grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
    &assertion=<signed JWT>
    &client_id=<client id>
    &scope=read

The authorization server then:

1. **Identifies the client.** RFC 7521 makes client authentication optional for
   the assertion grant, but django-oauth-toolkit still requires the client to be
   *identifiable* — via ``client_id`` (public clients) or client credentials
   (confidential clients) — so the grant can be authorized per application. The
   application must be registered for the ``jwt-bearer`` grant type.
2. **Resolves the issuer's keys** (see `Trust model`_) and verifies the
   assertion's signature. Only asymmetric algorithms are accepted
   (``RS*``/``ES*``/``PS*``); ``none`` and HMAC are rejected.
3. **Validates the registered claims** (RFC 7523 §3): ``iss``, ``sub``, ``aud``
   and ``exp`` are required; ``exp`` must be in the future and ``nbf`` (if
   present) not in the future, within ``CLIENT_ASSERTION_LEEWAY`` of clock
   skew; ``aud`` must identify this server (see `Audience`_); the validity period
   must not exceed ``JWT_BEARER_MAX_ASSERTION_LIFETIME_SECONDS``; and ``jti`` is
   required (``JWT_BEARER_REQUIRE_JTI``) and checked against a replay cache.
4. **Maps the subject to a user** via ``JWT_BEARER_SUBJECT_RESOLVER`` and issues
   the access token bound to that user. No refresh token is issued unless
   ``JWT_BEARER_ISSUE_REFRESH_TOKENS`` is set — re-assertion is expected instead.

Trust model
-----------

An assertion is only accepted if its ``iss`` can be tied to keys the server
trusts. Resolution order:

**1. Client-issued assertions** (``iss`` equals the authenticated client's
``client_id``). The assertion is verified with the keys registered on the
:class:`~oauth2_provider.models.Application`:

* ``client_jwks`` — an inline JWK Set (RFC 7517) document, or
* ``client_jwks_uri`` — a URL the JWK Set is fetched from (the fetch is
  SSRF-hardened and cached).

This is the common service-account case: a client signs an assertion for one of
its users.

**2. Trusted third-party issuers.** For assertions minted by an external
identity provider or security token service, list the issuer in
``JWT_BEARER_TRUSTED_ISSUERS``:

.. code-block:: python

    OAUTH2_PROVIDER = {
        "JWT_BEARER_GRANT_ENABLED": True,
        "JWT_BEARER_TRUSTED_ISSUERS": {
            "https://sts.example.com": {"jwks_uri": "https://sts.example.com/jwks.json"},
            # or an inline JWK Set:
            # "https://other.example.com": {"jwks": {"keys": [ ... ]}},
        },
    }

Any other ``iss`` is rejected. A ``manage.py check`` warning (``W011``) fires
when the grant is enabled but neither an application key nor a trusted issuer is
configured, because no assertion could be accepted.

Audience
~~~~~~~~

The assertion ``aud`` must identify this authorization server. The accepted set
is ``JWT_BEARER_AUDIENCES`` plus the OIDC issuer (when ``OIDC_ISS_ENDPOINT`` is
set) and a best-effort derivation of the token endpoint URL from the request.
**Deployments behind a TLS-terminating proxy should set ``JWT_BEARER_AUDIENCES``
explicitly** to the value clients use, since the derived URL depends on the
forwarded host/scheme.

Mapping subjects to users
-------------------------

``JWT_BEARER_SUBJECT_RESOLVER`` is an import string for a callable
``resolver(claims, application, request) -> User | None``. The default,
:func:`oauth2_provider.rfc7523.resolve_subject_by_username`, looks the ``sub``
claim up against the user model's ``USERNAME_FIELD`` and returns the user only if
it exists and is active. Returning ``None`` rejects the request with
``invalid_grant``.

Override it to implement your own policy — for example, mapping an opaque
external subject id, or restricting which subjects a given client may assert:

.. code-block:: python

    def resolve_subject(claims, application, request):
        from myapp.models import ServiceIdentity

        try:
            identity = ServiceIdentity.objects.get(external_id=claims["sub"])
        except ServiceIdentity.DoesNotExist:
            return None
        # Only let each client assert its own identities.
        if identity.owner_client_id != application.client_id:
            return None
        return identity.user

    OAUTH2_PROVIDER = {
        "JWT_BEARER_GRANT_ENABLED": True,
        "JWT_BEARER_SUBJECT_RESOLVER": "myapp.oauth.resolve_subject",
    }

Replay protection
-----------------

Each accepted assertion's ``(iss, jti)`` is recorded in the Django cache named by
the default Django cache until the assertion expires; a second presentation is
rejected as ``invalid_grant``. Replay protection is only as strong as the cache:
a per-process backend (e.g. ``LocMemCache``) does **not** detect replays across
worker processes. **Use a shared cache (Redis / memcached) in production.**

Generating assertions (client helper)
-------------------------------------

:func:`oauth2_provider.rfc7523.build_jwt_bearer_assertion` is a library-only
helper for building grant assertions on the client side (it performs no network
I/O):

.. code-block:: python

    from jwcrypto import jwk
    from oauth2_provider.rfc7523 import build_jwt_bearer_assertion

    private_key = jwk.JWK.from_json(open("client-private.jwk").read())
    assertion = build_jwt_bearer_assertion(
        key=private_key,
        issuer="my-client-id",              # the client's client_id
        subject="alice",                    # the resource owner's username
        audience="https://as.example.com/o/token/",
        lifetime_seconds=300,
        algorithm="RS256",
    )

    import requests

    resp = requests.post(
        "https://as.example.com/o/token/",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
            "client_id": "my-client-id",
            "scope": "read",
        },
    )

The public half of ``private_key`` must be registered on the application as
``client_jwks`` (or served from ``client_jwks_uri``).

Security considerations
-----------------------

* Assertions are restricted to asymmetric signatures; ``none`` and HMAC are
  rejected on the grant path.
* Audience restriction to this server's identifiers prevents an assertion minted
  for one server from being replayed at another.
* ``jti`` replay detection plus a bounded maximum lifetime limit the replay
  window; keep assertion lifetimes short.
* The subject resolver is the single place to enforce which subjects a client may
  assert; the default rejects unknown and inactive users.
* The grant is opt-in and authorized per application, so a leaked assertion alone
  is insufficient without a registered client allowed to use the grant.

Settings
--------

See :doc:`settings` for the full list. The grant adds the ``JWT_BEARER_*``
policy settings and reuses the shared ``CLIENT_ASSERTION_*`` knobs (clock-skew
leeway and JWK Set fetch timeout/size/cache) that also back RFC 7523 §2.2 JWT
client authentication (see :doc:`rfc7523`).
