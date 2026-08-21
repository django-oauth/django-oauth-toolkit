Upgrading
=========

This page collects the upgrade steps for every release of Django OAuth Toolkit that needs one, so
you don't have to reconstruct them from the :doc:`changelog`. If a release required something of
you — a breaking change to accommodate, a behavior change that can surface in a running deployment,
an action to take on the way through — it has a section here. Releases that need nothing beyond
installing them are deliberately absent, so an empty gap between two versions is an answer, not an
omission. The changelog remains the authoritative, complete record — always read the entries
between your current version and your target version before upgrading.

General upgrade procedure
-------------------------

#. **Read the changelog** for every release between your current and target version, not only the
   target — breaking changes are sometimes introduced in one release and then have follow-ups in
   later ones.
#. **Pin the exact version** you are upgrading to and test in a staging environment before
   production.
#. **Run migrations.** After upgrading the package, run ``python manage.py migrate``.
#. **Regenerate migrations for swapped models.** If you have :ref:`swapped any of the toolkit's
   models <extend_app_model>` (application or token models), run ``python manage.py makemigrations``
   for your app and then ``migrate``, so your custom models pick up the same schema changes.
#. **Check for removed deprecations.** Major releases remove things that earlier releases warned
   about with a ``DeprecationWarning``. Run your test suite with warnings enabled
   (``python -W all``) on the *previous* version first to surface anything you still rely on.

Upgrading to 2.0
----------------

2.0.0 is a major release with breaking changes. The two most likely to surface in a running
deployment are the client-secret hashing change — which shows up as an ``{"error":
"invalid_client"}`` response at the token endpoint — and PKCE now being required, which instead
fails with an ``invalid_request`` / ``invalid_grant`` error for clients that don't send a PKCE
challenge.

* **Client secrets are now hashed on save (#1093).** Existing cleartext
  ``application.client_secret`` values are migrated to Django password-style hashes on upgrade, and
  the hashing cannot be reversed. When you create or edit an application (in the admin or via the
  API), copy the generated/entered secret **before** saving — afterwards only the hash is stored.
  Clients configured with the old cleartext value keep working; only *reading back* a secret is no
  longer possible. If you have automation that reads ``client_secret`` out of the database, it must
  be updated.

* **PKCE is now required by default (#1129).** ``PKCE_REQUIRED`` defaults to ``True``, so
  authorization-code clients that do not send a PKCE ``code_challenge``/``code_verifier`` will fail.
  Either add PKCE to those clients (recommended) or set ``PKCE_REQUIRED`` to ``False`` to retain the
  pre-2.x behavior. Note that it is namespaced under the ``OAUTH2_PROVIDER`` setting, not a
  top-level Django setting::

      OAUTH2_PROVIDER = {
          # ...
          "PKCE_REQUIRED": False,
      }

* **OIDC standard scopes now gate claims (#1108).** Default OIDC scopes now determine which claims
  are returned. If you customized OIDC responses and want the pre-2.x behavior, set
  ``oidc_claim_scope = None`` in your ``OAuth2Validator`` subclass.

* **The ``oob`` redirect URIs were removed (#1124).** Support for the insecure
  ``urn:ietf:wg:oauth:2.0:oob`` and ``urn:ietf:wg:oauth:2.0:oob:auto`` redirect URIs is gone,
  replaced by `RFC 8252 <https://datatracker.ietf.org/doc/html/rfc8252>`_ "OAuth 2.0 for Native
  Apps". If you still rely on ``oob``, migrate those native clients to a loopback or custom-scheme
  redirect before upgrading.

Upgrading to 3.0
----------------

3.0.0 requires a schema migration and drops support for older Django versions.

* **Run ``migrate`` — the ``AccessToken`` model changed (#1447).** The ``token`` column became a
  ``TextField`` (removing the 255-character limit so JWT access tokens with extra claims fit), and a
  new ``token_checksum`` (SHA-256) field is used to look tokens up. Run ``python manage.py migrate``
  after upgrading; if you use swapped models, run ``makemigrations`` for your app first.

  .. warning::
     **Swapped access token models need a manual ``token_checksum`` backfill.** The built-in
     migration backfills ``token_checksum`` for the *default* ``AccessToken`` only — it deliberately
     skips a swapped access token model (and logs a warning to that effect). Until you backfill the
     checksum for your existing rows, those access tokens will fail validation. Backfill it in a data
     migration on your app, computing ``hashlib.sha256(token.encode("utf-8")).hexdigest()`` for each
     existing row (mirroring what ``oauth2_provider``'s ``0012_add_token_checksum`` migration does for
     the default model).

* **Models now use ``pk`` instead of ``id`` (#1446).** This lets swapped models use a different
  primary-key field. If any of your code assumed an ``id`` attribute on the toolkit's models, use
  ``pk`` instead.
* **Django < 4.2 is no longer supported (#1455).** Upgrade Django to 4.2 or newer first.
* **Deprecations from 2.4.0 were removed (#1425).** ``RedirectURIValidator`` and ``WildcardSet``
  (deprecated in #1345) are gone — replace any imports of them. The deprecated *importable*
  ``validate_logout_request`` helper was also removed (#1274); note that this is distinct from the
  ``RPInitiatedLogoutView.validate_logout_request`` *method*, which still exists — so if you grep
  the codebase and still find ``validate_logout_request``, that method is expected to be there.
* **Token cleanup writes now honor database routers (#1450).** If you run a multi-database setup,
  ensure your routers direct the token models to the correct database (see
  :ref:`the multiple-databases note <extend_token_models>`).

Upgrading to 3.4.1
------------------

3.4.1 tightens redirect URI matching and refresh token handling. Most deployments need to do
nothing beyond installing it, running ``migrate`` and running ``collectstatic``, but several
behaviors that were previously accepted are now rejected, so work through this list before rolling
it out.

* **Redirect URIs are now matched exactly (RFC 9700 §2.1).** A request may no longer carry query
  parameters, path parameters (``;key=value``), credentials (``https://user@host/cb``) or a
  fragment that the registered URI does not have. If any of your clients pass per-request data
  through the ``redirect_uri`` query string, they will start failing with
  ``redirect_uri_mismatch``: either register the full URI including its query (matched in the same
  order), or move that data into the ``state`` parameter, which is what it is for. Applications
  whose registered ``redirect_uris`` carry no query component are unaffected.

* **Some registered redirect URIs are no longer valid and must be re-registered.** A URI ending in
  a bare ``#`` is now rejected at registration (#1801); previously it was stored and would then
  never match anything. A rootless private-use scheme URI (``com.example.app:oauth2redirect``) is
  also rejected (#1796) — it used to be silently rewritten to ``com.example.app://oauth2redirect``,
  registering ``oauth2redirect`` as a *hostname*, which no client matches. Re-register those in the
  RFC 8252 §7.1 single-slash form, ``com.example.app:/oauth2redirect``.

* **Run ``collectstatic``.** The shipped templates no longer load Bootstrap from a third-party CDN
  (#730); ``oauth2_provider/base.html`` links a stylesheet distributed with the package instead,
  served through ``staticfiles``. Until you collect static files, the built-in authorization and
  application pages render unstyled. Substituting your own styles through the ``css`` block of
  ``base.html`` works exactly as before.

* **``REFRESH_TOKEN_EXPIRE_SECONDS`` is now enforced when a refresh token is presented (#746),**
  not only by the ``cleartokens`` sweep. Expiry is idle-based — a refresh token is rejected that
  many seconds after its access token expires, and the deadline slides forward on every refresh —
  so actively-used tokens are unaffected. If you set this, expect idle tokens that are already past
  their lifetime to be rejected on upgrade, forcing those clients to re-authenticate. The default
  (``None``) still never expires refresh tokens.

* **Revoking an access token now revokes the refresh token bound to it** — through the RFC 7009
  ``/revoke/`` endpoint (#746), the authorized-tokens page (#1510) and the admin. Previously the
  refresh token survived and could immediately mint a new access token, defeating the revocation.
  If you depend on the old behavior, note that whether a refresh token may survive access-token
  revocation becomes a configurable policy in 4.0.

* **The revocation endpoint only revokes tokens issued to the authenticated client (#727).** If you
  have automation that revokes another application's tokens through ``/o/revoke_token/``, it will
  silently stop having an effect — the endpoint still returns ``200`` (RFC 7009 §2.2) without
  disclosing whether the token exists.

* **A revoked refresh token is no longer honored inside the grace window (#1816).** This only
  affects deployments that set a non-zero ``REFRESH_TOKEN_GRACE_PERIOD_SECONDS``; the default of
  ``0`` was never exposed. Genuine rotation retries inside the window still work.

* **If you swap in your own refresh token model,** run ``makemigrations`` for your app to pick up
  the new index on ``token_family`` (#1809), and if you override ``revoke()``, override
  ``revoke_family()`` to match — reuse detection now revokes a compromised family as a set rather
  than row by row, so anything extra your ``revoke()`` does has to happen in ``revoke_family()``
  too. See :ref:`extend_token_models`.

* **If you wrapped or patched ``redirect_to_uri_allowed()``** to influence
  ``AbstractApplication.redirect_uri_allowed()`` or ``post_logout_redirect_uri_allowed()``, target
  the new ``check_redirect_to_uri_allowed()`` instead (#681) — those methods now call it rather
  than the old helper.

* **``Application.clean()`` now reports validation errors per field (#1343)** instead of as
  non-field errors, and reports all of them at once. ``ValidationError.message_dict`` is keyed by
  field name, so callers of ``Application.full_clean()`` see the field alongside the message. A
  custom ``ModelForm`` that omits one of those fields still receives the message as a non-field
  error, provided it subclasses ``oauth2_provider.forms.ApplicationForm``.

* **``JSONOAuthLibCore`` is deprecated (#1773)** and now emits a ``DeprecationWarning``. If you set
  ``OAUTH2_BACKEND_CLASS`` to it, plan to move off it: the JSON request-body mode is non-standard
  (RFC 6749, RFC 7662 and RFC 7009 define those endpoints as
  ``application/x-www-form-urlencoded``), and it is scheduled for removal in 4.0.

Upgrading to 3.5
----------------

3.5 reorganizes ``oauth2_provider`` by OAuth2 role. Every import path that shipped in an earlier
release still works — the old modules remain as shims that re-export from the new canonical
location and emit a ``DeprecationWarning`` — so ordinary use needs no change beyond silencing or
acting on those warnings before 4.0, when the shims are removed. Run your test suite with
``python -W error::DeprecationWarning`` to find the paths you still import.

Two changes go beyond a moved import and can bite code that *subclasses* or *patches* the
toolkit rather than merely importing from it.

* **``OAuthLibMixin`` is no longer a base class of the shipped views (#1765).** It was a single
  mixin carrying both authorization-server and resource-server behavior; it is now decomposed into
  a shared ``oauth2_provider.core.views.OAuthLibCoreMixin`` plus
  ``AuthorizationServerViewMixin`` and ``ResourceServerViewMixin``. The combined class is still
  importable from ``oauth2_provider.views.mixins`` and still usable as a base, but it is now a
  *recombination* of the two halves rather than their ancestor, so it no longer appears in any
  shipped view's MRO. Two consequences, both silent:

  - ``issubclass(TokenView, OAuthLibMixin)`` and the equivalent ``isinstance`` checks are now
    ``False`` for every shipped view. Dispatch or registry code keyed on that check stops matching.
  - Setting or patching an attribute on the combined mixin — ``OAuthLibMixin.server_class = ...``,
    or ``mock.patch("oauth2_provider.views.mixins.OAuthLibMixin.get_oauthlib_core")`` — no longer
    reaches the views. Nothing raises; the patch simply has no effect and the real code path runs.
    Retarget to the role mixin that actually defines the attribute, or to the concrete view class.

  Relatedly, each view now exposes only its own role's methods. Authorization-server views no
  longer have ``verify_request``, ``authenticate_client`` or ``unauthenticated_response``;
  resource-server views no longer have ``error_response`` or the ``create_*_response`` builders.
  A subclass that called across roles gets an ``AttributeError`` and should inherit the mixin for
  the role it needs.

* **Some module-level patch targets moved with their code (#1765).** The resource-server slice of
  ``OAuth2Validator`` now lives in ``oauth2_provider.resource_server.validators``. The public class
  and its behavior are unchanged, but names that were module globals of
  ``oauth2_provider.oauth2_validators`` — including ``requests``, ``datetime`` and the
  ``AccessToken`` model reference — are globals of the new module now. Tests doing
  ``mock.patch("oauth2_provider.oauth2_validators.requests")`` (or ``.datetime``, ``.AccessToken``)
  must patch ``oauth2_provider.resource_server.validators`` instead. This affects test doubles
  only; runtime behavior is identical.

  The same applies to the split view mixins: patching a module global such as
  ``SAFE_HTTP_METHODS`` at the old path no longer affects the code that reads it, because a
  re-export shim binds a *copy of the reference*, not the defining module's namespace. The name is
  still importable from the old path; patch it at
  ``oauth2_provider.resource_server.mixins`` to change behavior.

* **``OAuthLibMixin`` is no longer importable from the view modules it sat beside.** Through 3.4.1
  ``oauth2_provider.views.base``, ``.device`` and ``.oidc`` each imported the mixin to use as a base
  class, so ``from oauth2_provider.views.base import OAuthLibMixin`` happened to work. Those modules
  no longer reference it, and they are now whole-module aliases to their canonical replacements, so
  the name is gone from them. Import it from ``oauth2_provider.views.mixins`` — or better, from the
  role mixin that replaces it. The same applies to other names that were only ever incidentally
  visible because a module imported them for its own use (``requests`` and ``datetime`` on
  ``oauth2_provider.oauth2_validators``, ``socket`` and ``ssl`` on ``oauth2_provider.cimd``, and
  similar): import them from their real homes.

* **Submodules are no longer bound as attributes by a bare ``import oauth2_provider``.** The package
  now loads its submodules lazily, so ``import oauth2_provider`` followed by
  ``oauth2_provider.utils.…`` raises ``AttributeError`` where it previously worked by accident of
  import order. Use an explicit import — ``from oauth2_provider import utils`` or
  ``import oauth2_provider.utils`` — which works for every submodule, on both the old and the new
  paths. The laziness is deliberate: it keeps importing the package from touching the app registry
  before ``django.setup()``.

.. note::
   For the full, authoritative list of changes in every release — including the releases that
   asked nothing of you and so have no section here — see the :doc:`changelog`.
