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

Validating a custom Application model
=====================================

``AbstractApplication.clean()`` validates the fields that OAuth correctness depends on --
the redirect URIs, the CORS origins, and the signing algorithm together with the client
secret -- and raises a :class:`~django.core.exceptions.ValidationError` **keyed by field
name**. Django then reports each message on the field it belongs to: the built-in
application views and the Django admin render it next to the offending input, and
``ValidationError.message_dict`` carries the field name for anything calling
``Application.full_clean()`` directly. All problems found are reported together, so a
single submit shows every error rather than one per attempt.

When you add validation to a swapped application model, follow the same convention and
raise field-keyed errors from ``clean()``, calling ``super()`` so the built-in checks still
run::

    from django.core.exceptions import ValidationError
    from oauth2_provider.models import AbstractApplication

    class MyApplication(AbstractApplication):
        logo = models.ImageField()
        agree = models.BooleanField()

        def clean(self):
            super().clean()
            if not self.agree:
                raise ValidationError({"agree": "You must accept the user agreement."})

.. note:: Django raises ``ValueError`` when model validation names a field that the form
    does not include, which a custom form with a narrower ``Meta.fields`` can trigger.
    Subclass :class:`oauth2_provider.forms.ApplicationForm` to get those errors folded into
    non-field errors instead.

.. _custom-uri-validators:

Custom redirect URI and origin validators
=========================================

The rules ``clean()`` applies to ``redirect_uris`` and ``allowed_origins`` are not hard-coded.
``ALLOWED_REDIRECT_URI_SCHEMES`` and ``ALLOWED_SCHEMES`` cover the common case -- a fixed list of
schemes for the whole server -- but some policies cannot be written as a list: allowed schemes held
in the database and administered per tenant, a blacklist, or a scheme accepted only after the client
has been reviewed. Native apps are the usual reason, since :rfc:`8252` section 7.1 gives each app its own
private-use scheme (``com.example.app:/oauth2redirect``).

For those, replace the validator. There are two layers, and they compose exactly the way
``SCOPES_BACKEND_CLASS`` and ``Application.get_allowed_schemes()`` already do:

* the ``REDIRECT_URI_VALIDATOR`` and ``ALLOWED_ORIGIN_VALIDATOR`` settings set the default for the
  whole deployment, and need no custom application model;
* ``Application.get_redirect_uri_validator()`` and ``Application.get_allowed_origin_validator()``
  can be overridden on a swapped application model to vary the policy per application.

Each setting names a *factory*: a callable that receives the application and returns a callable
taking one URI string, which raises :class:`~django.core.exceptions.ValidationError` when the URI is
not acceptable. ``clean()`` calls the factory once per validation pass and then applies the result to
each URI, so a factory that queries the database does so once per save rather than once per URI.

A class is a callable, so the simplest custom validator is a subclass of
``oauth2_provider.validators.AllowedURIValidator`` that takes the application in ``__init__``. It
inherits all of the :rfc:`3986` and :rfc:`8252` parsing -- private-use schemes, authority rules,
optional wildcards -- and only replaces the scheme policy::

    # myapp/validators.py
    from oauth2_provider.validators import AllowedURIValidator

    class DBSchemeValidator(AllowedURIValidator):
        """Allow the schemes an operator approved for this client."""

        def __init__(self, application):
            schemes = ["https"]
            if application.pk:
                schemes += list(application.approved_schemes.values_list("scheme", flat=True))
            super().__init__(schemes, name="redirect uri", allow_path=True, allow_query=True)

    OAUTH2_PROVIDER = {
        "REDIRECT_URI_VALIDATOR": "myapp.validators.DBSchemeValidator",
    }

A factory can equally be a plain function, which suits policy that is a gate rather than a scheme
list -- for instance holding a client's custom scheme back until it has been reviewed::

    def review_gated_validator(application):
        approved = bool(application.pk) and application.review_state == "approved"
        schemes = ["https", application.custom_scheme] if approved else ["https"]
        return AllowedURIValidator(schemes, name="redirect uri", allow_path=True, allow_query=True)

Errors raised from a custom validator follow the same convention as the rest of ``clean()``: they are
collected and keyed to ``redirect_uris`` or ``allowed_origins``, so the admin and the built-in
application views render each message next to the offending input.

Two constraints are worth knowing before you write one.

**The application may be unsaved.** Registration through Dynamic Client Registration (:rfc:`7591`),
:doc:`CIMD <cimd>`, the ``createapplication`` command and the admin add form all validate before the
first save, so
``application.pk`` can be ``None`` and reverse relations may not exist yet. Guard accordingly, as
both examples above do.

**A factory may not be ``None``.** Both settings are mandatory, so an empty value raises rather than
silently disabling validation. If you really want no validation, say so explicitly with a factory
returning ``lambda uri: None``.

.. warning::
    These validators decide what may be **stored**. They do not affect request-time matching: an
    incoming ``redirect_uri`` is matched against the stored values by exact string comparison per
    :rfc:`9700` section 2.1, and nothing here can relax that. A validator that accepts a sloppy URI
    only stores a value that will never match.

    They are also not the whole story for schemes. ``Application.get_allowed_schemes()`` is consulted
    *again* when the redirect is issued, so accepting a new scheme here without adding it to
    ``ALLOWED_REDIRECT_URI_SCHEMES`` (or overriding ``get_allowed_schemes()``) produces an
    application that saves cleanly and then fails at redirect time. The same applies to origins:
    ``ALLOWED_SCHEMES`` is re-checked at request time by ``is_origin_allowed()``.

    On the Dynamic Client Registration and CIMD paths, no other check inspects redirect uri syntax,
    and a validator's message reaches the registering client verbatim in ``error_description``. Write
    client-facing messages, and remember that a permissive validator widens the open-redirect and
    phishing surface just as ``ALLOW_URI_WILDCARDS`` does.

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

.. note:: If your ``RefreshToken`` overrides ``revoke()``, override ``revoke_family()`` as well.
    ``revoke()`` invalidates a single token; ``revoke_family()`` is the set-based sweep that
    ``REFRESH_TOKEN_REUSE_PROTECTION`` runs over a whole token family, and it reproduces what
    ``revoke()`` does in bulk rather than calling it per row. Anything extra your ``revoke()``
    does needs to happen in ``revoke_family()`` too, or reuse detection will skip it.

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
            available = list(
                ApplicationScope.objects.filter(application=application).values_list(
                    "scope__name", flat=True
                )
            )
            # No per-application restriction configured: allow all known scopes.
            return available or list(Scope.objects.values_list("name", flat=True))

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
keep them if you use those helpers.

.. note::
   If you use the read/write helpers, your backend must offer the configured ``READ_SCOPE`` /
   ``WRITE_SCOPE`` names (``read`` and ``write`` by default) in **two** places:

   * ``get_available_scopes()`` -- so a token can actually be granted the scope. Requested scopes
     are validated against ``get_available_scopes()`` (``OAuth2Validator.validate_scopes``), so a
     name missing here can never be issued, and the read/write check would then always fail.
   * ``get_all_scopes()`` -- ``rw_protected_resource`` and ``ReadWriteScopedResourceMixin`` look the
     name up here and raise ``ImproperlyConfigured`` if it is missing. (The DRF permission classes
     ``TokenHasReadWriteScope`` / ``TokenHasResourceScope`` don't perform this check; they just
     require the token to carry the scope.)

   In the model-based example above, adding ``Scope`` rows named ``read`` and ``write`` satisfies
   both, since ``get_all_scopes()`` and the fallback ``get_available_scopes()`` both derive from the
   ``Scope`` table -- just make sure those rows are also in an application's ``ApplicationScope`` set
   if you restrict scopes per application.

Register the ``Scope`` and ``ApplicationScope`` models with the admin as usual to manage scopes
through the admin site.

.. _dynamic_access_token_lifetime:

Varying the access token lifetime per request
=============================================

``ACCESS_TOKEN_EXPIRE_SECONDS`` (see :ref:`settings_access_token_expire_seconds`) may be a
callable instead of a fixed number of seconds. It is called once per issued token with the
current ``oauthlib.common.Request`` and must return a number of seconds or a
``datetime.timedelta``. The value it returns is reported to the client as ``expires_in``
*and* stored as the token's ``expires``, so the two never drift apart.

The callable can be given directly, or as a dotted import path -- which is usually what you
want, since a Django settings module often cannot import a callable that touches models::

    OAUTH2_PROVIDER = {
        "ACCESS_TOKEN_EXPIRE_SECONDS": "myapp.oauth.access_token_expires_in",
    }

The request carries everything needed to make the decision:

``request.client``
    The ``Application`` instance the token is being issued to. This is how you give
    different clients different lifetimes -- add a field to a
    :ref:`custom Application model <extend_app_model>` and read it here::

        def access_token_expires_in(request):
            return request.client.access_token_lifetime or 36000

``request.grant_type``
    The grant being used, e.g. to keep tokens issued to a machine client short because no
    human is present to notice a leak::

        from datetime import timedelta

        def access_token_expires_in(request):
            if request.grant_type == "client_credentials":
                return timedelta(minutes=15)
            return timedelta(hours=10)

``request.scopes``
    The granted scopes, so a token that can move money expires sooner than one that can
    only read::

        def access_token_expires_in(request):
            if "transfer" in (request.scopes or []):
                return timedelta(minutes=5)
            return timedelta(hours=10)

``request.user``
    The resource owner, where one is involved. It is ``None`` for ``client_credentials``,
    so guard for that.

``request.headers``
    A copy of the Django request's ``META``, so an upstream session cookie is reachable and
    a token can be made not to outlive the session that authorized it.

Notes:

* The callable runs while the token is being issued, inside the token endpoint's
  transaction. Keep it cheap and side-effect free -- an extra query per token issued is a
  cost paid on the hot path.
* Raise nothing: an exception propagates out of the token endpoint. Fall back to a default
  rather than assuming a field is populated.
* Return a positive value. A non-positive or non-numeric return raises
  ``ImproperlyConfigured``.
* A refresh exchange is a fresh issuance, so the callable is consulted again with
  ``request.grant_type == "refresh_token"``; the new access token gets the lifetime that
  applies *then*, not the one the original token got.

``tests/app/idp/idp/oauth.py`` in this repository has a working example wired into the demo
IdP.

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

The rest of the shipped pages need no CSP exceptions: their styles come from a stylesheet
served with the package's own static files, so ``style-src 'self'`` is enough — no
third-party style host and no inline ``<style>``. See :ref:`default-stylesheet` if you
replace those styles with your own.

.. _debug-redirect-uri:

Debugging redirect URI mismatches
=================================

When a client sends a ``redirect_uri`` that does not match anything registered for it,
the authorization server answers with oauthlib's ``Mismatching redirect URI.`` and
nothing more. That is deliberate: the error is rendered to whoever made the request, so
naming the registered URIs there would let anyone holding a client ID enumerate that
client's callbacks. The response says nothing, and it stays that way.

The detail goes to the log instead. Django OAuth Toolkit logs to the ``oauth2_provider``
logger; set it to ``DEBUG`` to see which URIs were compared and which component of each
one differed::

    LOGGING = {
        "version": 1,
        "disable_existing_loggers": False,
        "handlers": {
            "console": {"class": "logging.StreamHandler"},
        },
        "loggers": {
            "oauth2_provider": {
                "handlers": ["console"],
                "level": "DEBUG",
            },
        },
    }

A failed match on the authorization endpoint then reports every registered candidate::

    DEBUG redirect_uri 'https://app.example.com/callback/' does not match any redirect_uri
    registered for client_id 'SDbfPCoJIzPeXwPGfMzZ1TIVfjBqvnMYCfSHTPSc':
    'https://app.example.com/callback': path differs;
    'http://app.example.com/callback/': scheme differs

The token endpoint compares against the URI recorded on the grant instead, which
RFC 6749 section 4.1.3 requires to be identical to the one used at authorization::

    DEBUG redirect_uri 'https://app.example.com/callback' does not match the redirect_uri
    'https://app.example.com/callback/' recorded on grant #42 at authorization time;
    RFC 6749 section 4.1.3 requires them to be identical

The same messages cover ``post_logout_redirect_uri`` for RP-initiated logout.

.. note::

    Both the requested URI and the registered URIs are truncated and escaped before
    being logged, and at most ten registered candidates are listed per message, since
    under dynamic client registration the registered URIs are supplied by the registrant
    rather than by you. The log still records that someone attempted a particular
    callback, so enable ``DEBUG`` on a server whose logs you treat accordingly; leaving
    the ``oauth2_provider`` logger at its default level keeps these messages off
    entirely.
