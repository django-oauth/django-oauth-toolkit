Part 7 - Managing applications and tokens in the Django admin
=============================================================

Scenario
--------
In :doc:`Part 1 <tutorial_01>` you created your own :term:`Authorization Server` and registered
an application through the front-end ``/o/applications/`` views. Django OAuth Toolkit also
registers all of its models with the `Django admin site
<https://docs.djangoproject.com/en/stable/ref/contrib/admin/>`_, which gives staff users a
single place to review and manage applications, issued tokens, authorization codes and OIDC ID
tokens. This part walks through that admin UI.

Enabling the admin
------------------
The admin is set up exactly as in a normal Django project — nothing OAuth-specific is required.
As shown in :doc:`Part 1 <tutorial_01>`, add ``django.contrib.admin`` to ``INSTALLED_APPS`` and
route it in your ``urls.py``:

.. code-block:: python

    from django.contrib import admin

    urlpatterns = [
        path("admin/", admin.site.urls),
        # ...
    ]

Log in at http://localhost:8000/admin/ with a staff account. Under the **DJANGO OAUTH TOOLKIT**
section you will find five model admins:

* **Applications** — the OAuth clients you have registered.
* **Access tokens** — bearer tokens issued to those clients.
* **Refresh tokens** — tokens used to obtain a new access token.
* **Grants** — short-lived authorization codes exchanged for tokens.
* **ID tokens** — OpenID Connect ID tokens (only relevant when you use OIDC).

If you have :ref:`swapped any of these models <extend_app_model>`, your custom models appear
here instead, under their own app.

Managing applications
---------------------
Open **Applications** to see the registered clients. The changelist shows the primary key,
name, owning user, client type, authorization grant type and registration source, and can be
filtered by client type, grant type, ``skip_authorization`` and registration source, or searched
by application name (and user email, when your user model has one).

Click **Add application** (or an existing row) to open the application form. The most important
fields are:

* **User** — the user the application belongs to. It uses a raw-id widget, so enter or look up
  the user's primary key.
* **Redirect uris** — a space-separated list of allowed redirect URIs. A client using the
  authorization-code or implicit grant must register at least one.
* **Post logout redirect uris** — space-separated URIs allowed after an RP-initiated OIDC logout.
* **Allowed origins** — space-separated origins for which CORS is enabled on the token endpoint.
* **Client type** — ``confidential`` or ``public`` (:rfc:`2.1`).
* **Authorization grant type** — the flow this application uses (authorization-code, implicit,
  password, client-credentials or openid-hybrid).
* **Name** — a friendly label shown to users on the authorization form.
* **Skip authorization** — when enabled, users are never shown the authorization form for this
  application, even on first use. Enable it only for applications you fully trust (see
  :ref:`skip-auth-form`).
* **Algorithm** — the OIDC token signing algorithm (``No OIDC support``, ``RS256`` or ``HS256``).

.. note::
   **Client secrets are hashed and shown only once.** By default the toolkit stores a hash of
   ``client_secret`` (like a password), so the raw value cannot be recovered after you save. When
   you create an application — or paste a new secret into an existing one — copy the secret
   *before* clicking **Save**. If you lose it, generate a new one by saving a fresh random value
   into both the admin and your client. ``registration_source`` and ``cimd_expires_at`` are
   maintained by the toolkit (they mark applications created via Dynamic Client Registration or
   :doc:`CIMD <../cimd>`) and are read-only.

Reviewing and revoking tokens
-----------------------------
The **Access tokens**, **Refresh tokens**, **Grants** and **ID tokens** admins let you inspect
what the server has issued and revoke it by deleting rows. A few behaviors are specific to these
credential admins:

* **You cannot create tokens by hand.** Tokens, refresh tokens, authorization codes and ID
  tokens are issued by the OAuth/OIDC flows, so the **Add** button is disabled for all four.
* **Secret values are masked.** Access/refresh token values and authorization codes are stored in
  cleartext, so the admin never shows the usable value: the changelist displays only a short
  masked suffix, the raw value is hidden on the change form, and you can search only by
  non-secret identifiers (application client id / name, and user) — never by the token itself.
  This keeps live, replayable credentials out of the admin UI and out of ``?q=`` search URLs
  captured in server logs and browser history.
* **Deleting an access token also revokes its refresh token.** Removing an access token from the
  admin revokes the refresh token bound to it, so a deleted access token cannot be silently
  refreshed back into existence.

To revoke a user's access, delete their access token (and, if present, refresh token) from these
changelists. For bulk, scheduled cleanup of *expired* tokens, use the :ref:`cleartokens`
management command rather than deleting rows by hand.
