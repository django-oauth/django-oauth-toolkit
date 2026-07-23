RFC 9700 Security Best Current Practice
=======================================

`RFC 9700 <https://datatracker.ietf.org/doc/html/rfc9700>`_ ("Best Current Practice
for OAuth 2.0 Security", BCP 240) updates and extends the security advice in
`RFC 6749 <https://datatracker.ietf.org/doc/html/rfc6749>`_,
`RFC 6750 <https://datatracker.ietf.org/doc/html/rfc6750>`_, and
`RFC 6819 <https://datatracker.ietf.org/doc/html/rfc6819>`_. This page maps each
relevant recommendation to django-oauth-toolkit (DOT) behavior and the setting that
controls it.

.. _rfc9700-gates:

Gated behaviors and the 3.x → 4.0 transition
--------------------------------------------

Every RFC 9700 recommendation is covered by a ``COMPLIANT_BCP_RFC9700_<topic>`` boolean
gate: ``True`` means the recommendation is enforced, ``False`` (the current default)
preserves the legacy behavior. There are two kinds:

**Behavior gates** control whether DOT itself performs a discouraged behavior:

* ``False`` (the current default) — the insecure/legacy behavior is allowed. The
  request-time gates (implicit grant, password grant, ``plain`` PKCE, access token in
  the query string) emit a ``DeprecationWarning`` each time the behavior is exercised.
  The two ambient gates (``COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS`` and
  ``COMPLIANT_BCP_RFC9700_TOKEN_STORAGE``) would fire on every request,
  so they are surfaced by ``manage.py check --deploy`` (``W005``/``W006``) instead of a
  per-request/per-token warning.
* ``True`` — the behavior is enforced: the insecure request is rejected, or the
  secure behavior is performed instead.

**Config-validation gates** cover recommendations that are expressed through existing
settings (``REFRESH_TOKEN_REUSE_PROTECTION``, ``ALLOWED_REDIRECT_URI_SCHEMES``,
``ALLOW_URI_WILDCARDS``, ``PKCE_REQUIRED``). The gate does not replace the setting —
the setting stays canonical and in control of runtime behavior. Instead the gate sets
the severity of the ``manage.py check --deploy`` message when the setting is on a
non-compliant value:

* ``False`` (the current default) — an insecure value produces a check **Warning**.
* ``True`` — an insecure value produces a check **Error**, so a non-compliant
  configuration cannot pass deploy checks. (A compliant value produces nothing in
  either position.)

The config-validation gates are ``COMPLIANT_BCP_RFC9700_REFRESH_TOKEN``
(§4.14.2), ``COMPLIANT_BCP_RFC9700_REDIRECT_URI_SCHEME`` (§2.1),
``COMPLIANT_BCP_RFC9700_REDIRECT_URI_MATCHING`` (§4.1.1), and
``COMPLIANT_BCP_RFC9700_PKCE_REQUIRED`` (§2.1.1).

**These defaults are scheduled to flip to** ``True`` **in the 4.0 release.** Set them
to ``True`` now to adopt the compliant behavior early and silence the warnings.

Run ``python manage.py check --deploy`` to get a checklist of every recommendation that
is currently on a non-compliant value (warnings while the gates are ``False``, errors
once they are ``True``).

Compliant settings block
-------------------------

To adopt the RFC 9700 recommendations today, add the following to your
``OAUTH2_PROVIDER`` setting. Hashed token storage is left commented out because it is
opt-in and incompatible with a non-zero refresh-token grace period (see the caveat
below); enable it once you have confirmed ``REFRESH_TOKEN_GRACE_PERIOD_SECONDS`` is
``0``::

    OAUTH2_PROVIDER = {
        # ... your existing settings ...

        # RFC 9700 gates (default False today; will default True in 4.0)
        "COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT": True,
        "COMPLIANT_BCP_RFC9700_PASSWORD_GRANT": True,
        "COMPLIANT_BCP_RFC9700_PKCE_METHOD": True,
        "COMPLIANT_BCP_RFC9700_ACCESS_TOKEN_TRANSPORT": True,
        "COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS": True,

        # Canonical settings whose defaults also change in 4.0
        "REFRESH_TOKEN_REUSE_PROTECTION": True,
        "ALLOWED_REDIRECT_URI_SCHEMES": ["https"],

        # Config-validation gates: turn any remaining insecure value of the
        # settings above (plus ALLOW_URI_WILDCARDS / PKCE_REQUIRED) into a
        # `check --deploy` error instead of a warning
        "COMPLIANT_BCP_RFC9700_REFRESH_TOKEN": True,
        "COMPLIANT_BCP_RFC9700_REDIRECT_URI_SCHEME": True,
        "COMPLIANT_BCP_RFC9700_REDIRECT_URI_MATCHING": True,
        "COMPLIANT_BCP_RFC9700_PKCE_REQUIRED": True,

        # Optional, opt-in hardening (see the caveat below)
        # "COMPLIANT_BCP_RFC9700_TOKEN_STORAGE": True,
    }

Recommendation-by-recommendation
--------------------------------

PKCE (§2.1.1)
~~~~~~~~~~~~~
PKCE is required by default (``PKCE_REQUIRED`` is ``True``). RFC 9700 also
discourages the ``plain`` ``code_challenge_method`` in favor of ``S256``; set
``COMPLIANT_BCP_RFC9700_PKCE_METHOD = True`` to reject ``plain`` challenges and
drop it from the authorization-server metadata. A deployment that sets
``PKCE_REQUIRED = False`` is flagged by the
``COMPLIANT_BCP_RFC9700_PKCE_REQUIRED`` validation gate (``W010`` while the gate
is ``False``, ``E005`` once it is ``True``; a callable ``PKCE_REQUIRED`` is a per-client
policy and is not flagged).

Redirect URI matching (§2.1)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
DOT already performs exact redirect-URI matching (scheme, host, port, and path), with
wildcards off (``ALLOW_URI_WILDCARDS`` defaults to ``False``). Set
``ALLOWED_REDIRECT_URI_SCHEMES = ["https"]`` to disallow registering plaintext ``http``
redirect URIs. Two validation gates cover these settings:
``COMPLIANT_BCP_RFC9700_REDIRECT_URI_SCHEME`` flags ``http`` in the scheme list
(``W008``/``E003``) and ``COMPLIANT_BCP_RFC9700_REDIRECT_URI_MATCHING`` flags
``ALLOW_URI_WILDCARDS = True`` (``W009``/``E004``).

.. note::
   Requiring ``https`` also disallows native-app loopback callbacks
   (``http://127.0.0.1``/``[::1]``, `RFC 8252 <https://datatracker.ietf.org/doc/html/rfc8252>`_),
   because redirect URIs are validated against ``ALLOWED_REDIRECT_URI_SCHEMES`` by
   scheme. Keep ``"http"`` in the list if you must support them.
   ``ALLOW_LOCALHOST_LOOPBACK`` only extends the any-port loopback exemption to
   ``http://localhost`` — it does not re-enable the ``http`` scheme.

Implicit grant (§2.1.2)
~~~~~~~~~~~~~~~~~~~~~~~~
The implicit grant MUST NOT be used. Set
``COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT = True`` to reject the ``token`` /
``id_token`` response types and stop advertising ``implicit`` in the
authorization-server metadata.

Resource owner password credentials grant (§2.4)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The password grant MUST NOT be used. Set
``COMPLIANT_BCP_RFC9700_PASSWORD_GRANT = True`` to reject
``grant_type=password`` and stop advertising it.

Access tokens in the query string (§4.3.2)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Access tokens MUST NOT be transmitted in the URI query string. Set
``COMPLIANT_BCP_RFC9700_ACCESS_TOKEN_TRANSPORT = True`` to reject requests that
present an ``access_token`` query parameter at the resource server. The
``Authorization`` header (and form-encoded body per
`RFC 6750 <https://datatracker.ietf.org/doc/html/rfc6750>`_) are unaffected.

Mix-up attacks / issuer identification (§4.4, RFC 9207)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Set ``COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS = True`` to include the ``iss``
parameter (`RFC 9207 <https://datatracker.ietf.org/doc/html/rfc9207>`_) in the
authorization response and advertise
``authorization_response_iss_parameter_supported`` in the metadata. The ``iss``
value matches the metadata ``issuer`` (``OIDC_ISS_ENDPOINT`` when configured,
otherwise derived from the request).

.. note::
   Multi-tenant deployments that use the RFC 8414 path-component issuer form
   (``/.well-known/oauth-authorization-server/<issuer_path>``) MUST set
   ``OIDC_ISS_ENDPOINT`` (per issuer) so the ``iss`` parameter matches the published
   metadata ``issuer``; the issuer suffix cannot be derived from the authorization
   request itself.

Refresh-token rotation and replay detection (§4.14)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Rotation is on by default (``ROTATE_REFRESH_TOKEN``). Set
``REFRESH_TOKEN_REUSE_PROTECTION`` to ``True`` to revoke the entire token family when
a refresh token is replayed (§4.14.2). Note that reuse detection only treats a replay
as an attack after ``REFRESH_TOKEN_GRACE_PERIOD_SECONDS``. The
``COMPLIANT_BCP_RFC9700_REFRESH_TOKEN`` validation gate flags
``REFRESH_TOKEN_REUSE_PROTECTION = False`` (``W007`` while the gate is ``False``,
``E002`` once it is ``True``).

Token storage at rest (§4)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
By default DOT stores access and refresh tokens in cleartext (alongside a SHA-256
``token_checksum`` used for lookup). Set
``COMPLIANT_BCP_RFC9700_TOKEN_STORAGE = True`` to store only the
token hash, so a database read no longer discloses usable tokens. Existing cleartext
tokens are left in place and age out as they expire or rotate.

.. warning::
   Hashed token storage is incompatible with the refresh-token grace period, which
   must return a previously issued (cleartext) token from the database. When
   ``COMPLIANT_BCP_RFC9700_TOKEN_STORAGE`` is ``True`` you must set
   ``REFRESH_TOKEN_GRACE_PERIOD_SECONDS = 0`` (the default); ``manage.py check --deploy``
   raises ``oauth2_provider.E001`` otherwise.

Out of scope
------------

Sender-constrained access tokens (DPoP,
`RFC 9449 <https://datatracker.ietf.org/doc/html/rfc9449>`_, and mutual-TLS,
`RFC 8705 <https://datatracker.ietf.org/doc/html/rfc8705>`_; RFC 9700 §2.2/§4.13) are
not implemented. DOT issues bearer tokens only.
