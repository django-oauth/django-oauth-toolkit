Standards Compliance
====================

Django OAuth Toolkit (DOT) aims to be *a standards compliant OAuth2/OIDC Identity
Provider that adheres to best practices out of the box*. This page is a single,
authoritative reference for **which specifications the toolkit implements**, at what
level, and where the behavior lives in the code or settings.

DOT acts in the OAuth 2.0 **authorization server** (AS / OpenID **Provider**) and
**resource server** roles. It is *not* a relying party (client) library, so
client-only specifications are out of scope by design.

Most low-level protocol logic is delegated to
`OAuthLib <https://github.com/oauthlib/oauthlib>`_; JWT/JWK handling uses
`jwcrypto <https://jwcrypto.readthedocs.io/>`_. DOT supplies the Django request
validator, models, views, settings, and endpoints on top of those libraries.

.. note::

   Status reflects the current ``main`` branch. "Opt-in" means the feature ships but is
   gated behind a setting (for example ``OIDC_ENABLED`` or ``DCR_ENABLED``). See
   :doc:`settings` for every referenced setting.

Legend
------

* **Supported** — implemented and enabled by default.
* **Opt-in** — implemented, enabled via a setting.
* **Partial** — implemented for internal use or with documented limitations.
* **Not supported** — no implementation at this time.

OAuth 2.0 and extensions
------------------------

.. list-table::
   :header-rows: 1
   :widths: 30 15 55

   * - Specification
     - Status
     - Notes / evidence
   * - `RFC 6749 <https://www.rfc-editor.org/rfc/rfc6749>`_ — OAuth 2.0 core
     - Supported
     - All five grants: authorization code, implicit, resource owner password,
       client credentials, refresh token. Advertised via
       ``OAUTH2_GRANT_TYPES_SUPPORTED``.
   * - `RFC 6750 <https://www.rfc-editor.org/rfc/rfc6750>`_ — Bearer token usage
     - Supported
     - Resource access via ``OAuth2Authentication`` / ``protected_resource``
       decorators and mixins.
   * - `RFC 7009 <https://www.rfc-editor.org/rfc/rfc7009>`_ — Token revocation
     - Supported
     - ``revoke_token/`` endpoint (``RevokeTokenView``).
   * - `RFC 7636 <https://www.rfc-editor.org/rfc/rfc7636>`_ — PKCE
     - Supported
     - Required by default (``PKCE_REQUIRED = True``); ``plain`` and ``S256``
       advertised as ``code_challenge_methods_supported``.
   * - `RFC 7662 <https://www.rfc-editor.org/rfc/rfc7662>`_ — Token introspection
     - Supported
     - ``introspect/`` endpoint; DOT can also act as a resource server that
       introspects against a remote AS.
   * - `RFC 8252 <https://www.rfc-editor.org/rfc/rfc8252>`_ — OAuth 2.0 for native apps
     - Partial
     - Custom-scheme redirect handling via ``ALLOWED_REDIRECT_URI_SCHEMES``, plus the
       RFC 8252 §7.3 any-port loopback exemption (extendable to ``http://localhost`` with
       ``ALLOW_LOCALHOST_LOOPBACK``); no separate endpoint.
   * - `RFC 8414 <https://www.rfc-editor.org/rfc/rfc8414>`_ — Authorization server metadata
     - Supported
     - ``/.well-known/oauth-authorization-server`` (see
       :doc:`oauth2_server_metadata`).
   * - `RFC 8628 <https://www.rfc-editor.org/rfc/rfc8628>`_ — Device authorization grant
     - Supported
     - Device flow views and the ``device_code`` grant.
   * - `RFC 7591 <https://www.rfc-editor.org/rfc/rfc7591>`_ — Dynamic client registration
     - Opt-in
     - ``DCR_ENABLED``; ``register/`` endpoint (see
       :doc:`views/dynamic_client_registration`).
   * - `RFC 7592 <https://www.rfc-editor.org/rfc/rfc7592>`_ — DCR management
     - Opt-in
     - Client configuration endpoint, gated with DCR.
   * - `RFC 7519 <https://www.rfc-editor.org/rfc/rfc7519>`_ — JSON Web Token
     - Partial
     - Used internally for OIDC ID tokens and JWT handling (via jwcrypto); not a
       standalone user feature.
   * - `RFC 9700 <https://www.rfc-editor.org/rfc/rfc9700>`_ — OAuth 2.0 Security BCP
     - Supported
     - Per-recommendation ``COMPLIANT_BCP_RFC9700_*`` gates (reject implicit/password
       grants, S256-only PKCE, no query-string tokens, RFC 9207 ``iss`` in authorization
       responses, hashed token storage, refresh-token reuse protection, redirect-URI
       matching), a ``--deploy`` security system check, and :doc:`security`. Gates default
       to legacy behavior (with warnings) and flip to enforcing in 4.0.
   * - `RFC 7523 <https://www.rfc-editor.org/rfc/rfc7523>`_ — JWT client assertions
       (``private_key_jwt``)
     - Not supported
     - Token-endpoint auth is ``client_secret_post`` / ``client_secret_basic`` only.
   * - `RFC 9068 <https://www.rfc-editor.org/rfc/rfc9068>`_ — JWT access tokens
       (``at+jwt``)
     - Not supported
     - Access tokens are opaque random strings.
   * - `RFC 9126 <https://www.rfc-editor.org/rfc/rfc9126>`_ — Pushed authorization
       requests (PAR)
     - Not supported
     -
   * - `RFC 9396 <https://www.rfc-editor.org/rfc/rfc9396>`_ — Rich authorization
       requests (RAR)
     - Not supported
     -
   * - `RFC 9449 <https://www.rfc-editor.org/rfc/rfc9449>`_ — DPoP
     - Not supported
     -
   * - `RFC 8707 <https://www.rfc-editor.org/rfc/rfc8707>`_ — Resource indicators
     - Supported
     - Clients may pass ``resource``; the binding is stored on the grant/token and the
       introspection response returns the ``aud`` claim.
   * - `RFC 8705 <https://www.rfc-editor.org/rfc/rfc8705>`_ — mTLS client authentication
     - Not supported
     -
   * - `RFC 9728 <https://www.rfc-editor.org/rfc/rfc9728>`_ — Protected resource metadata
     - Opt-in
     - ``/.well-known/oauth-protected-resource`` plus ``ProtectedResourceMetadataMixin`` /
       ``protected_resource_metadata`` and the ``OAuth2ProtectedResourceAuthentication`` DRF
       authenticator, which advertises it via the ``resource_metadata`` ``WWW-Authenticate``
       challenge parameter.
   * - OAuth 1.0 / 1.0a
     - Not supported
     - DOT is an OAuth 2.0 toolkit; only ``oauthlib.oauth2`` / ``oauthlib.openid``
       are used.

OpenID Connect
--------------

OpenID Connect features are enabled with ``OIDC_ENABLED`` and an RSA signing key
(``OIDC_RSA_PRIVATE_KEY``). See :doc:`oidc` for configuration.

.. list-table::
   :header-rows: 1
   :widths: 30 15 55

   * - Specification
     - Status
     - Notes / evidence
   * - `OpenID Connect Core 1.0 <https://openid.net/specs/openid-connect-core-1_0.html>`_
     - Opt-in
     - ID tokens, ``nonce``, ``at_hash``, claims, UserInfo; authorization code,
       implicit, and hybrid flows.
   * - `OpenID Connect Discovery 1.0 <https://openid.net/specs/openid-connect-discovery-1_0.html>`_
     - Opt-in
     - ``/.well-known/openid-configuration`` and ``jwks.json``.
   * - `OIDC RP-Initiated Logout 1.0 <https://openid.net/specs/openid-connect-rpinitiated-1_0.html>`_
     - Opt-in
     - ``logout/`` endpoint with ``post_logout_redirect_uris`` support.
   * - `OIDC Session Management 1.0 <https://openid.net/specs/openid-connect-session-1_0.html>`_
     - Not supported
     - Spec text is bundled in ``rfcs/`` but no implementing code exists yet.
   * - `OIDC Front-Channel Logout 1.0 <https://openid.net/specs/openid-connect-frontchannel-1_0.html>`_
     - Not supported
     -
   * - `OIDC Back-Channel Logout 1.0 <https://openid.net/specs/openid-connect-backchannel-1_0.html>`_
     - Not supported
     - Spec text is bundled in ``rfcs/`` but no implementing code exists yet.
   * - OpenID Connect Dynamic Client Registration 1.0
     - Partial
     - RFC 7591 / 7592 DCR is supported; the OIDC-specific registration profile is
       not separately implemented.

Profile / suite conformance
---------------------------

Named profiles ("suites") are *bundles of the specifications above* with additional
mandatory, forbidden, or recommended behavior layered on. DOT's standing against the
common profiles:

* **OAuth 2.0** — Supported. Core framework plus the widely used extensions
  (revocation, introspection, PKCE, device grant, metadata).
* **OpenID Connect (Basic/Core)** — Supported (opt-in). Core, Discovery, and
  RP-Initiated Logout.
* **OAuth 2.1** (draft) — Configurable. DOT's defaults already align with 2.1 (PKCE
  required, exact redirect-URI matching), and the RFC 9700 gates above let you reject the
  implicit and password grants, enforce S256-only PKCE, and add the ``iss`` parameter — the
  defining 2.1 behaviors. The gates preserve the legacy grants by default in 3.4 (with
  deprecation warnings) and flip to compliant in 4.0.
* **FAPI 2.0** — Not supported. Requires sender-constrained tokens (mTLS or DPoP),
  PAR, and ``at+jwt``, none of which are implemented.
* **MCP authorization** — Supported (configurable). DOT ships every spec the MCP
  authorization profile requires — protected-resource metadata (RFC 9728), resource
  indicators (RFC 8707), authorization-server metadata (RFC 8414), PKCE, Dynamic Client
  Registration, and, through the RFC 9700 gates above, an OAuth 2.1 posture. To run an
  MCP-compliant deployment, enable the RFC 9700 gates and add the protected-resource-metadata
  mixin / DRF authenticator to your resource server.

Gaps that block the advanced profiles, in rough priority order: ``private_key_jwt``
(RFC 7523), JWT access tokens (RFC 9068), PAR (RFC 9126), DPoP (RFC 9449), and OIDC
back-channel logout.

Verifying at runtime
--------------------

A running server advertises much of the above through its discovery documents. Fetch
``/.well-known/oauth-authorization-server`` (and, when OIDC is enabled,
``/.well-known/openid-configuration``) and inspect ``grant_types_supported``,
``response_types_supported``, ``code_challenge_methods_supported``, and
``token_endpoint_auth_methods_supported`` to confirm what a given deployment exposes.
