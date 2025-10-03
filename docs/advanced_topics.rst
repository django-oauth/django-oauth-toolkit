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
