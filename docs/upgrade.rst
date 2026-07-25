Upgrading
=========

This page collects the breaking changes and upgrade steps for **major** version bumps of Django
OAuth Toolkit, so you don't have to reconstruct them from the :doc:`changelog`. The changelog
remains the authoritative, complete record — always read the entries between your current version
and your target version before upgrading. This page summarizes the changes most likely to break a
running deployment.

General upgrade procedure
-------------------------

#. **Read the changelog** for every release between your current and target version, not only the
   target — breaking changes are sometimes introduced in a major release and then have follow-ups
   in later ones.
#. **Pin the exact version** you are upgrading to and test in a staging environment before
   production.
#. **Run migrations.** After upgrading the package, run ``python manage.py migrate``. Major
   releases frequently ship model changes.
#. **Regenerate migrations for swapped models.** If you have :ref:`swapped any of the toolkit's
   models <extend_app_model>` (application or token models), run ``python manage.py makemigrations``
   for your app and then ``migrate``, so your custom models pick up the same schema changes.
#. **Check for removed deprecations.** Major releases remove things that earlier releases warned
   about with a ``DeprecationWarning``. Run your test suite with warnings enabled
   (``python -W all``) on the *previous* version first to surface anything you still rely on.

Upgrading to 2.0
----------------

2.0.0 is a major release with breaking changes. The two that most often surface — both as an
``{"error": "invalid_client"}`` response — are the client-secret hashing and PKCE changes.

* **Client secrets are now hashed on save (#1093).** Existing cleartext
  ``application.client_secret`` values are migrated to Django password-style hashes on upgrade, and
  the hashing cannot be reversed. When you create or edit an application (in the admin or via the
  API), copy the generated/entered secret **before** saving — afterwards only the hash is stored.
  Clients configured with the old cleartext value keep working; only *reading back* a secret is no
  longer possible. If you have automation that reads ``client_secret`` out of the database, it must
  be updated.

* **PKCE is now required by default (#1129).** ``PKCE_REQUIRED`` defaults to ``True``, so
  authorization-code clients that do not send a PKCE ``code_challenge``/``code_verifier`` will fail.
  Either add PKCE to those clients (recommended) or set ``PKCE_REQUIRED = False`` in your settings
  to retain the pre-2.x behavior.

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

.. note::
   For the full, authoritative list of changes in every release — including minor and patch
   releases not covered here — see the :doc:`changelog`.
