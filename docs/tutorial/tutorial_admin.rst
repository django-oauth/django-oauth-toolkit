Part 7 - Managing applications and tokens in the Django admin
=============================================================

Scenario
--------
In :doc:`Part 1 <tutorial_01>` you set up your own :term:`Authorization Server` and registered an
application through the ``/o/applications/`` pages. Those pages let each user manage their own
applications. As a site administrator you often need a broader view — every application on the
site, and the tokens the server has issued — so you can help users, register applications on their
behalf, and cut off access when something goes wrong. Django OAuth Toolkit adds all of this to the
built-in `Django admin site <https://docs.djangoproject.com/en/stable/ref/contrib/admin/>`_. This
part walks through it.

Enabling the admin
------------------
The admin is the standard Django admin — nothing OAuth-specific is required. As shown in
:doc:`Part 1 <tutorial_01>`, add ``django.contrib.admin`` to ``INSTALLED_APPS`` and route it in
your ``urls.py``:

.. code-block:: python

    from django.contrib import admin
    from django.urls import path

    urlpatterns = [
        path("admin/", admin.site.urls),
        # ...
    ]

Log in at http://localhost:8000/admin/ with a staff account. Under the **Django OAuth Toolkit**
heading you will find five sections:

* **Applications** — the OAuth clients registered on your site.
* **Access tokens** — the tokens clients use to call your protected APIs.
* **Refresh tokens** — the tokens clients use to get a new access token.
* **Grants** — short-lived authorization codes, created during the authorization flow and
  exchanged for tokens.
* **ID tokens** — OpenID Connect ID tokens (only relevant if you use OIDC).

Managing applications
---------------------
Open **Applications** to see every client registered on the site. You can filter the list by
client type, grant type and whether authorization is skipped, or search for an application by name
(and by owner email, if your users have one).

Click **Add application**, or an existing row, to open the application form. The fields you will
usually care about are:

* **User** — the person the application belongs to. Click the lookup (magnifying-glass) icon next
  to the field to search for and select them.
* **Redirect uris** — the URLs the client is allowed to return to after login, one per line (or
  separated by spaces). A client that logs users in (the authorization-code, implicit or OpenID
  Connect hybrid flows) must list at least one, and the form won't save without it.
* **Post logout redirect uris** — the URLs a client may send the user to after they log out.
* **Allowed origins** — the web origins allowed to call the token endpoint from a browser.
* **Client type** — **Confidential** for apps that can keep a secret (a server-side app),
  **Public** for apps that cannot (a single-page or mobile app).
* **Authorization grant type** — how the application obtains tokens. The dropdown options are
  *Authorization code*, *Device Code*, *Implicit*, *Resource owner password-based*,
  *Client credentials* and *OpenID connect hybrid*.
* **Name** — the label users see on the consent screen when they authorize the application.
* **Skip authorization** — when on, users are never shown the consent screen for this application.
  Turn it on only for applications you completely trust (see :ref:`skip-auth-form`).
* **Algorithm** — the signing algorithm for OpenID Connect ID tokens: **No OIDC support** (the
  default), **RSA with SHA-2 256**, or **HMAC with SHA-2 256**.
* **Hash client secret** — whether the client secret is stored as a one-way hash (see the note).

.. note::
   **Copy the client secret before you save.** By default the secret is hashed and stored like a
   password, so it can never be shown again after you save the form. When you add an application —
   or set a new secret on an existing one — copy the secret first; if you lose it, your only option
   is to set a new one in both the admin and the client. (If you turn **Hash client secret** off,
   the secret stays readable on the form instead.) A few fields are filled in automatically and are
   read-only — for example, the ones marking applications that registered themselves through
   :doc:`dynamic client registration <../views/dynamic_client_registration>`.

Reviewing and revoking tokens
-----------------------------
The **Access tokens**, **Refresh tokens**, **Grants** and **ID tokens** sections show what the
server has issued to each application and user. Tokens are always created for you by the login and
token flows, so you can review and revoke them here but you can't add them by hand. The token
values themselves are hidden — the list shows only a short masked ending, and you look tokens up by
application or user, never by the secret value — so live credentials never sit in plain view.

To cut off an application or a user's access, open **Access tokens** or **Refresh tokens**, tick
the rows you want to stop, and choose **Revoke selected access tokens** or **Revoke selected
refresh tokens** from the actions menu. Revoking a token also revokes its partner — the matching
refresh or access token issued alongside it — so a revoked client can't quietly refresh its way
back in.

To clear out tokens that have simply *expired*, run the :ref:`cleartokens` management command on a
schedule — it removes expired tokens in bulk, so you don't have to hunt them down in the admin.
