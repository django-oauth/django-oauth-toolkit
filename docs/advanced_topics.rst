Advanced topics
+++++++++++++++

.. _extend_app_model:

Extending the Application model
===============================

An Application instance represents a :term:`Client` on the :term:`Authorization server`. Usually an Application is
issued to client's developers after they log in on an Authorization Server and pass in some data
which identify the Application itself (let's say, the application name). Django OAuth Toolkit
provides a very basic implementation of the Application model containing only the data strictly
required during all the OAuth processes but you will likely need some extra info, like application
logo, acceptance of some user agreement and so on.

.. class:: AbstractApplication(models.Model)

    This is the base class implementing the bare minimum for Django OAuth Toolkit to work

    * :attr:`client_id` The client identifier issued to the client during the registration process as described in :rfc:`2.2`
    * :attr:`user` ref to a Django user
    * :attr:`redirect_uris` The list of allowed redirect uri. The string consists of valid URLs separated by space
    * :attr:`post_logout_redirect_uris` The list of allowed redirect uris after an RP initiated logout. The string consists of valid URLs separated by space
    * :attr:`allowed_origins` The list of origin URIs to enable CORS for token endpoint. The string consists of valid URLs separated by space
    * :attr:`client_type` Client type as described in :rfc:`2.1`
    * :attr:`authorization_grant_type` Authorization flows available to the Application
    * :attr:`client_secret` Confidential secret issued to the client during the registration process as described in :rfc:`2.2`
    * :attr:`name` Friendly name for the Application

Django OAuth Toolkit lets you extend the AbstractApplication model in a fashion like Django's
custom user models.

If you need, let's say, application logo and user agreement acceptance field, you can do this in
your Django app (provided that your app is in the list of the ``INSTALLED_APPS`` in your settings
module)::

    from django.db import models
    from oauth2_provider.models import AbstractApplication

    class MyApplication(AbstractApplication):
        logo = models.ImageField()
        agree = models.BooleanField()

Then you need to tell Django OAuth Toolkit which model you want to use to represent applications.
Write something like this in your settings module::

    OAUTH2_PROVIDER_APPLICATION_MODEL = 'your_app_name.MyApplication'

Be aware that, when you intend to swap the application model, you should create and run the
migration defining the swapped application model prior to setting ``OAUTH2_PROVIDER_APPLICATION_MODEL``.
You'll run into ``models.E022`` in Core system checks if you don't get the order right.

You can force your migration providing the custom model to run in the right order by
adding::

    run_before = [
        ('oauth2_provider', '0001_initial'),
    ]

to the migration class.

That's all, now Django OAuth Toolkit will use your model wherever an Application instance is needed.

.. note:: ``OAUTH2_PROVIDER_APPLICATION_MODEL`` is the only setting variable that is not namespaced, this
    is because of the way Django currently implements swappable models.
    See `issue #90 <https://github.com/django-oauth/django-oauth-toolkit/issues/90>`_ for details.

.. _extend_token_models:

Extending the token models
==========================

The ``AccessToken``, ``RefreshToken`` and ``IDToken`` models are swappable in the same way as
``Application``: subclass their abstract base classes and point the corresponding settings at your
models. There is one extra constraint that does not apply to ``Application``, and getting it wrong is
the cause of the long-standing confusion tracked in
`issue #634 <https://github.com/django-oauth/django-oauth-toolkit/issues/634>`_.

**Swap AccessToken and RefreshToken together, into the same app.**
``AccessToken.source_refresh_token`` references ``RefreshToken`` and ``RefreshToken.access_token``
references ``AccessToken`` -- a circular foreign key. Because of this the two models must be swapped
into the **same app**: pointing ``OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL`` at a custom model while leaving
``RefreshToken`` on the default ``oauth2_provider.RefreshToken`` splits the circular reference across
two apps, and Django cannot order the migrations for that graph. This surfaces as
``fields.E304``/``fields.E305`` reverse-accessor clashes or ``lazy reference ... isn't installed``
errors. Django OAuth Toolkit ships a system check (``oauth2_provider.W011``) that warns when the
``AccessToken`` and ``RefreshToken`` models are not defined in the same app.

``AccessToken`` also references ``IDToken``, but only in one direction, so ``IDToken`` can be swapped
independently (or left on the default). It is often convenient to customize it alongside the other
token models, but that is not required.

As with the ``Application`` model, you do **not** need to repeat the ``swappable`` Meta option on your
replacement models -- it is already declared on the toolkit's base models, which is what marks them as
swap targets. Just subclass the abstract models and point the settings at them.

Put the interrelated models in a single app (here called ``my_oauth``)::

    from oauth2_provider.models import (
        AbstractAccessToken,
        AbstractApplication,
        AbstractRefreshToken,
    )


    class Application(AbstractApplication):
        pass


    class AccessToken(AbstractAccessToken):
        pass


    class RefreshToken(AbstractRefreshToken):
        pass

and point the settings at them::

    OAUTH2_PROVIDER_APPLICATION_MODEL = "my_oauth.Application"
    OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL = "my_oauth.AccessToken"
    OAUTH2_PROVIDER_REFRESH_TOKEN_MODEL = "my_oauth.RefreshToken"

Then run ``makemigrations`` and ``migrate``. On a fresh database this works out of the box.

.. note:: This is straightforward for a **new** project. Migrating an **existing** deployment that
    already has data in the default ``oauth2_provider`` tables is a data-migration exercise that is
    out of scope here: you would need to create the new tables, copy the rows across (rewriting the
    foreign keys), and only then switch the settings. Because the ``AccessToken``/``RefreshToken``
    foreign keys are circular, the migration that creates the tables must add the
    ``source_refresh_token`` field *after* both tables exist (mirroring what
    ``oauth2_provider/migrations/0001_initial.py`` does), or use
    ``django.db.migrations.operations.SeparateDatabaseAndState`` to decouple the state from the
    schema changes.

Configuring multiple databases
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There is no requirement that the tokens are stored in the default database or that there is a
default database provided the database routers can determine the correct Token locations. Because the
Tokens have foreign keys to the ``User`` model, you likely want to keep the tokens in the same database
as your User model. It is also important that all of the tokens are stored in the same database.
This could happen for instance if one of the Tokens is locally overridden and stored in a separate database.
The reason for this is transactions will only be made for the database where AccessToken is stored
even when writing to RefreshToken or other tokens.

Multiple Grants
~~~~~~~~~~~~~~~

The default application model supports a single OAuth grant (e.g. authorization code, client credentials). If you need
applications to support multiple grants, override the ``allows_grant_type`` method. For example, if you want applications
to support the authorization code *and* client credentials grants, you might do the following::

    from oauth2_provider.models import AbstractApplication

    class MyApplication(AbstractApplication):
        def allows_grant_type(self, *grant_types):
            # Assume, for this example, that self.authorization_grant_type is set to self.GRANT_AUTHORIZATION_CODE
            return bool( set([self.authorization_grant_type, self.GRANT_CLIENT_CREDENTIALS]) & grant_types )

.. _custom-scopes-backend:

Custom scopes backend
=====================

The set of scopes your server understands does not have to be hard-coded in settings. The
available scopes and their defaults (the ``SCOPES`` and ``DEFAULT_SCOPES`` settings) are read
through a *scopes backend*, and you can replace it with one of your own -- for example to store
scopes in the database and administer them through the Django admin, or to expose a different set
of scopes per application. (The ``READ_SCOPE`` and ``WRITE_SCOPE`` settings are *not* part of the
backend: they are read directly from settings by the read/write permission helpers, so they keep
applying regardless of the backend in use.)

The backend used is controlled by the ``SCOPES_BACKEND_CLASS`` setting, which defaults to
``oauth2_provider.scopes.SettingsScopes`` (the settings-driven backend). To write your own, subclass
``oauth2_provider.scopes.BaseScopes`` and implement its three methods::

    class BaseScopes:
        def get_all_scopes(self):
            """
            Return a dict-like mapping of every scope name the system knows about to its
            human-readable description, e.g. ``{"read": "Read scope", "write": "Write scope"}``.
            Used to render scope descriptions (for example on the authorization form) and to
            describe a token's scopes. Requested scopes are validated against
            ``get_available_scopes``, not this method.
            """

        def get_available_scopes(self, application=None, request=None, *args, **kwargs):
            """
            Return the list of scope names that may be requested for the given
            ``application``/``request``, e.g. ``["read", "write"]``. A scope not in this list
            cannot be granted.
            """

        def get_default_scopes(self, application=None, request=None, *args, **kwargs):
            """
            Return the list of scope names granted when a client requests authorization without
            specifying any scope. This MUST be a subset of ``get_available_scopes``.
            """

``get_available_scopes`` and ``get_default_scopes`` receive the ``application`` and ``request``
in play, so a backend can vary the offered scopes per application or per request.

Model-based scopes
~~~~~~~~~~~~~~~~~~

The following backend keeps scopes in the database. It lets you add or remove scopes (and pick
which ones a given application may use) from the Django admin without a code deploy or settings
change.

Define the models in one of your apps::

    from django.db import models

    from oauth2_provider.settings import oauth2_settings


    class Scope(models.Model):
        name = models.CharField(max_length=255, unique=True)
        description = models.TextField(blank=True)
        is_default = models.BooleanField(default=False)

        def __str__(self):
            return self.name


    class ApplicationScope(models.Model):
        # Which scopes each application is allowed to request. If an application has no rows
        # here, fall back to every scope (see the backend below).
        # oauth2_settings.APPLICATION_MODEL honors a swapped application model
        # (OAUTH2_PROVIDER_APPLICATION_MODEL); it is "oauth2_provider.Application" by default.
        application = models.ForeignKey(
            oauth2_settings.APPLICATION_MODEL, on_delete=models.CASCADE, related_name="scopes"
        )
        scope = models.ForeignKey(Scope, on_delete=models.CASCADE)

Then implement the backend::

    from oauth2_provider.scopes import BaseScopes

    from .models import ApplicationScope, Scope


    class ModelScopes(BaseScopes):
        def get_all_scopes(self):
            return dict(Scope.objects.values_list("name", "description"))

        def get_available_scopes(self, application=None, request=None, *args, **kwargs):
            if application is None:
                return list(Scope.objects.values_list("name", flat=True))
            available = ApplicationScope.objects.filter(application=application)
            if available.exists():
                return list(available.values_list("scope__name", flat=True))
            # No per-application restriction configured: allow all known scopes.
            return list(Scope.objects.values_list("name", flat=True))

        def get_default_scopes(self, application=None, request=None, *args, **kwargs):
            # Defaults MUST be a subset of get_available_scopes, so intersect the flagged
            # default scopes with what this application is actually allowed to request.
            available = set(self.get_available_scopes(application, request, *args, **kwargs))
            defaults = Scope.objects.filter(is_default=True).values_list("name", flat=True)
            return [name for name in defaults if name in available]

Finally point the setting at your backend::

    OAUTH2_PROVIDER = {
        # ...
        "SCOPES_BACKEND_CLASS": "your_app.scopes.ModelScopes",
    }

With a custom backend in place the ``SCOPES`` and ``DEFAULT_SCOPES`` settings are no longer
consulted (the backend becomes the single source of truth for the available scopes and their
defaults), so you can drop them. ``READ_SCOPE`` and ``WRITE_SCOPE`` are read directly from settings
by the read/write permission helpers (see :doc:`rest-framework/permissions`) and still apply, so
keep them if you use those helpers. Register the ``Scope`` and ``ApplicationScope`` models with the
admin as usual to manage scopes through the admin site.

.. _skip-auth-form:

Skip authorization form
=======================

Depending on the OAuth2 flow in use and the access token policy, users might be prompted for the
same authorization multiple times: sometimes this is acceptable or even desirable but other times it isn't.
To control DOT behaviour you can use the ``approval_prompt`` parameter when hitting the authorization endpoint.
Possible values are:

* ``force`` - users are always prompted for authorization.

* ``auto`` - users are prompted only the first time, subsequent authorizations for the same application
  and scopes will be automatically accepted.

Skip authorization completely for trusted applications
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You might want to completely bypass the authorization form, for instance if your application is an
in-house product or if you already trust the application owner by other means. To this end, you have to
set ``skip_authorization = True`` on the ``Application`` model, either programmatically or within the
Django admin. Users will *not* be prompted for authorization, even on the first use of the application.


.. _override-views:

Overriding views
================

You may want to override whole views from Django OAuth Toolkit, for instance if you want to
change the login view for unregistered users depending on some query params.

In order to do that, you need to write a custom urlpatterns

.. code-block:: python

    from django.urls import re_path
    from oauth2_provider import views as oauth2_views
    from oauth2_provider import urls

    from .views import CustomeAuthorizationView


    app_name = "oauth2_provider"

    urlpatterns = [
        # Base urls
        re_path(r"^authorize/", CustomeAuthorizationView.as_view(), name="authorize"),
        re_path(r"^token/$", oauth2_views.TokenView.as_view(), name="token"),
        re_path(r"^revoke_token/$", oauth2_views.RevokeTokenView.as_view(), name="revoke-token"),
        re_path(r"^introspect/$", oauth2_views.IntrospectTokenView.as_view(), name="introspect"),
    ] + urls.management_urlpatterns + urls.oidc_urlpatterns

You can then replace ``oauth2_provider.urls`` with the path to your urls file, but make sure you keep the
same namespace as before.

.. code-block:: python

    from django.urls import include, path

    urlpatterns = [
        ...
        path('o/', include('path.to.custom.urls', namespace='oauth2_provider')),
    ]

This method also allows to remove some of the urls (such as managements) urls if you don't want them.

.. _csp-authorization-form:

Content Security Policy and the authorization form
==================================================

If your project sends a `Content Security Policy
<https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy>`_ that
restricts ``form-action`` (for example ``form-action 'self'``, commonly configured through
`django-csp <https://django-csp.readthedocs.io/>`_), the authorization-code flow can fail
in Chromium-based browsers: clicking **Authorize** appears to do nothing and the browser
never reaches the client's ``redirect_uri``.

This happens because the authorization form posts to the authorization endpoint
(``/o/authorize/`` by default, wherever you mounted it) and the server answers with a
``302`` redirect to the client's registered ``redirect_uri`` — a *different* origin. Chromium enforces ``form-action`` against the redirect target of a form submission,
so the off-site redirect is blocked; Firefox and Safari historically check only the form's
own action (``'self'``) and are unaffected. This is a browser/CSP-policy interaction rather
than a defect in the toolkit — DOT issues a standard ``302`` — and it cannot be worked around
by setting an ``action`` attribute on the ``<form>`` element, because the block is on the
redirect *target*, not on the POST target.

To allow the flow under a strict ``form-action`` policy, add the requesting application's
registered redirect URIs to the ``form-action`` directive for the authorization response,
by overriding :class:`~oauth2_provider.views.AuthorizationView` (see :ref:`override-views`)::

    from urllib.parse import urlsplit, urlunsplit

    from oauth2_provider.views import AuthorizationView


    def csp_source(uri):
        # A CSP source expression matches scheme/host/port/path only. DOT permits
        # a query string (and fragment) in a redirect URI, but those are not valid
        # in a CSP source and would make the directive non-matching, so drop them.
        parts = urlsplit(uri)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


    class CSPAuthorizationView(AuthorizationView):
        def get(self, request, *args, **kwargs):
            response = super().get(request, *args, **kwargs)
            # Only the rendered consent page carries the form and needs the relaxed
            # directive; reuse the application the base view already put in the template
            # context rather than re-querying, and skip redirect / error responses
            # (skip_authorization, auto-approval, invalid client_id) that have no context.
            application = getattr(response, "context_data", {}).get("application")
            if application is not None:
                # django-csp: extend form-action with this client's redirect URIs so the
                # post-authorization redirect is allowed. The exact response attribute
                # (``_csp_replace`` / ``_csp_update``) and value format depend on your
                # django-csp version; consult its documentation.
                response._csp_replace = {
                    "form-action": [
                        "'self'",
                        *(csp_source(uri) for uri in application.redirect_uris.split()),
                    ]
                }
            return response

Scope the added origins as narrowly as possible — to the requesting application's redirect
URIs, as above — rather than relaxing ``form-action`` globally.
