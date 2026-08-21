==============
Package Layout
==============

The ``oauth2_provider`` package is organized by the OAuth2/OIDC **role** each
piece of code serves, so a contributor can tell at a glance whether they are
working on the authorization server or the resource server. This page is the
source of truth for where code lives and where new code should go.

Roles
=====

* **Authorization Server (AS)** — the *provider* side: issuing authorization and
  tokens, client registration, grant behavior, RFC 8414 metadata, and the
  **OpenID Connect Provider (OP)** identity layer (ID tokens, JWKS, discovery,
  userinfo, and the RP-Initiated Registration/Logout endpoints that *serve*
  external relying parties). This library is primarily the OP.
* **Resource Server (RS)** — validating bearer tokens (RFC 7662 introspection,
  RFC 8707 audience) and advertising RFC 9728 protected-resource metadata.
* **Client** — the *other* side of the wire: helpers used to talk **to** some
  authorization server, which may not be this one. Small and standalone today
  (RFC 7523 client assertions). Note the resource server imports from here when
  it authenticates to a *remote* authorization server's introspection endpoint —
  in that exchange it **is** a client. OpenID Connect calls this role the
  *Relying Party*; see **Naming** below.
* **Core / shared** — plumbing used by more than one role (settings, scopes,
  exceptions, the oauthlib bridge, the shared view base, …).

Naming
------

OAuth2 and OpenID Connect name the participants differently — OAuth2 has
*authorization server*, *resource server* and *client*; OIDC has *OpenID
Provider*, *Relying Party* and *End-User*. The packages follow one rule so the
two vocabularies do not get mixed arbitrarily:

   Name a package for the **protocol role its code plays on the wire**, using the
   vocabulary of the specification that *defines* that role.

* OAuth2 defines authorization server, resource server and client, so those are
  the top-level packages. OAuth2 is the base vocabulary because it is the only
  one that names every role this library implements — OIDC has no word for
  "resource server".
* A specification that **specializes** an existing role becomes a facet one level
  down. OIDC's OpenID Provider is a specialized authorization server, so it is
  ``authorization_server/oidc/``; its Relying Party is a specialized client, so
  it would be ``client/oidc/``.
* A specification that introduces a role OAuth2 does **not** have earns its own
  package under that specification's own name (see *Federation* below).

.. note::
   **``client/`` is code this library runs** *as* **a client**, and nothing else.
   It is deliberately small and standalone: nothing in it imports
   ``authorization_server``, touches the app registry, or needs a model, so a
   plain client application can use it. Today that is RFC 7523 client
   authentication assertions (``make_client_assertion``).

   Do **not** file provider code under ``client/`` because it *mentions* clients:
   registering clients (``dcr``, ``cimd``) and the OP endpoints that *serve*
   external relying parties (RP-Initiated Login/Logout) are authorization-server
   code. The test is which side of the wire the code runs on, not which side it
   talks about.

Package map
===========

.. code-block:: text

    oauth2_provider/
      core/                     shared plumbing
        scopes, exceptions, utils, http, compat, signals, checks,
        bcp (RFC 9700 best-current-practice gates),
        safe_fetch (SSRF-hardened HTTPS fetching),
        rfc7523 (client-assertion protocol constant, shared by AS/RS/client),
        backends_oauthlib, views.py (OAuthLibCoreMixin — shared view base)
      authorization_server/     provider side
        dcr, cimd, forms, admin,
        client_assertions (RFC 7523 assertion *verification*),
        par (RFC 9126 pushed authorization requests),
        urls.py (server-metadata / base / management / DCR patterns)
        views/                  base, introspect, device, par (RFC 9126),
                                dynamic_client_registration, application, token,
                                metadata (RFC 8414), mixins (AuthorizationServerViewMixin)
        oidc/                   OpenID Connect Provider facet
          views.py, mixins.py (OIDC gating), urls.py
      resource_server/          resource server side
        www_authenticate, backends, decorators, middleware,
        validators.py (ResourceServerValidatorMixin + RFC 8707 helpers),
        mixins.py (protected-resource mixins), urls.py
        views/                  generic (protected-resource views), metadata (RFC 9728)
      client/                   client side — talking *to* an authorization
                                server (see Naming above)
        client_assertions (RFC 7523 assertion *building*)
      contrib/                  third-party framework integrations (see below)
        rest_framework/         DRF authentication + scope permissions
        ninja/                  Django Ninja bearer-token security
      settings.py, models.py, generators.py, validators.py, oauth2_validators.py
                                stay at the top level (see below)

Some role packages **re-export their public API** so it can be imported by role,
e.g. ``from oauth2_provider.resource_server import ProtectedResourceView`` or
``from oauth2_provider.authorization_server import AuthorizationView``. View- and
model-backed names are re-exported lazily (PEP 562) so importing a role package
never touches the app registry before ``django.setup()``.

Federation
==========

Federation is why the naming rule above is stated generally rather than as
"always use OAuth2 words". No federation code exists yet —
``Application.RegistrationSource`` reserves ``FEDERATION`` for it — but the rule
already says where it would go.

* **Brokering needs no new package.** A deployment that is an authorization
  server to its own clients *and* a client to an upstream authorization server is
  authorization-server code plus client code, composed. The layout already works
  this way: ``resource_server/validators.py`` imports ``make_client_assertion``
  from ``client`` because a resource server authenticating to a *remote*
  introspection endpoint is itself acting as a client. Code is filed by the role
  it plays **in a given exchange**, not by what the deployment *is* — which is
  what lets one deployment be several roles at once.
* **OpenID Federation does add roles OAuth2 lacks.** A Trust Anchor or
  Intermediate — publishing subordinate statements, answering resolve queries —
  is neither an authorization server, a resource server, nor a client. Under the
  third clause of the rule those take a ``federation/`` package, named for the
  specification that defines them.
* **Expected shape** (illustrative, not committed): ``core/federation/`` for the
  role-neutral trust layer (entity statements, trust chains, metadata policy,
  trust marks — reusing ``core/safe_fetch``); ``authorization_server/federation``
  for OP-side automatic/explicit registration from a validated trust chain,
  beside the existing ``dcr`` and ``cimd`` registration paths; and
  ``client/federation`` for the relying-party side.

Framework integrations (``contrib/``)
=====================================

``oauth2_provider/contrib/`` holds optional integrations with **third-party web
frameworks** — Django REST Framework (``contrib/rest_framework``: the
``OAuth2Authentication`` authenticators and the ``TokenHasScope`` family of
permissions) and Django Ninja (``contrib/ninja``: bearer-token security). By
*role* these are all **Resource Server** functionality — they let a DRF/Ninja app
act as an OAuth2-protected resource server — and their internal imports use the
canonical resource-server / core paths.

They are deliberately **not** moved under ``resource_server/``. ``contrib`` is the
established Django-ecosystem location for optional per-framework integrations, so
it is organized by **framework** — an axis orthogonal to the AS/RS/core role split
(much like ``views/`` is split by view type). It is also the most heavily-imported
public surface (``from oauth2_provider.contrib.rest_framework import
OAuth2Authentication, TokenHasScope``), so keeping it stable avoids a disruptive
deprecation for the least structural gain. A new integration for another framework
goes under ``contrib/<framework>/``.

Where new code goes
===================

* Put new code in the **role package** for the concern it implements
  (``authorization_server`` / ``authorization_server/oidc`` /
  ``resource_server`` / ``client`` / ``core``). Pick by **which side of the wire
  the code runs on**, not by which side it mentions. Do **not** add code to the
  deprecated top-level shim modules, and do not add new top-level modules.
* **First-party code MUST import the canonical role path**, never a deprecated
  shim — importing a shim emits a ``DeprecationWarning``, so importing a shim
  from library code would make the toolkit warn during normal use. (Example:
  import ``from oauth2_provider.core.scopes import get_scopes_backend``, not
  ``from oauth2_provider.scopes import ...``.)
* **Views** live under ``<role>/views/``; the shared oauthlib view base is
  ``core/views.OAuthLibCoreMixin`` (authorization-server response builders are on
  ``authorization_server.views.mixins.AuthorizationServerViewMixin``,
  resource-server verification on ``resource_server.mixins.ResourceServerViewMixin``).
* **URLs** are defined per role (``<role>/urls.py`` / ``authorization_server/oidc/urls.py``)
  and aggregated by ``oauth2_provider/urls.py``; keep ``include("oauth2_provider.urls")``
  and the public ``*_urlpatterns`` names working.
* **Settings** in ``oauth2_provider/settings.py`` ``DEFAULTS`` are grouped by
  role; add new settings to the matching group, and point dotted-string defaults
  at canonical module paths.

What stays at the top level (do not move)
=========================================

These are intentionally **not** relocated, because moving them is unsafe or
breaking:

* ``settings.py`` — ``oauth2_settings`` is imported almost everywhere (first-party
  and downstream), so relocating it would maximize churn and make nearly every
  project see a deprecation. It stays at ``oauth2_provider/settings.py``; the
  ``DEFAULTS`` dict is only reorganized *internally* by role.
* ``models.py`` — swappable models rely on the ``oauth2_provider`` app label, and
  historical migrations import ``oauth2_provider.models``.
* ``generators.py`` and ``validators.py`` — referenced as model-field
  defaults/validators, so their import path is frozen into migration
  ``deconstruct()`` output; moving them would force a spurious migration.
* ``oauth2_validators.OAuth2Validator`` keeps its import path (it is the swappable
  ``OAUTH2_VALIDATOR_CLASS`` and is widely subclassed); its resource-server slice
  is composed in from ``resource_server.validators``.

Backward-compatible moves (deprecation policy)
==============================================

When a module or symbol moves to a role package, keep the old import path working
for one release cycle:

* Leave a **shim** at the old path that re-exports from the new canonical module
  and emits a ``DeprecationWarning`` (removal targeted at the next major, 4.0).
  For a whole-module move, aliasing ``sys.modules[__name__]`` to the moved module
  preserves object identity for every name (public and private).
* A shim whose old path is imported by a framework at startup (e.g.
  ``oauth2_provider.admin``, imported by Django admin autodiscovery) is **silent**
  (no warning) for the cycle.
* Update **all first-party imports** and any dotted-string settings defaults to
  the canonical path so the library never warns about its own imports.
* Add an entry to the CHANGELOG ``Deprecated`` section with the old → new mapping.

Verifying a reorganization
==========================

A move/split must be behavior-preserving. Check:

* ``python -m pytest`` (the full suite) passes unchanged, and importing the
  library / URLconf raises **no** first-party ``DeprecationWarning``.
* ``manage.py makemigrations --check --dry-run`` reports no changes (guards the
  migration-frozen modules above).
* ``ruff check`` and ``ruff format --check`` are clean.
* Old import paths still resolve to the same objects as the new canonical paths
  (see ``tests/test_import_compat.py``).
