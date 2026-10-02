Application Views
=================

A set of views is provided to let users handle application instances without accessing Django Admin
Site. Application views are listed at the url ``applications/`` and you can register a new one at the
url ``applications/register``. You can override default templates located in
:file:`templates/oauth2_provider` folder and provide a custom layout. Every view provides access only to
data belonging to the logged in user who performs the request.

Applications registered through these views get the default ``can_introspect=True``, so they
may call the token introspection endpoint like any other application. The views do not expose the
flag; an administrator turns it off in the Django admin (see :ref:`introspection-authorization`).
Anyone who can log in can therefore register a client that introspects; to turn the flag off as
applications are registered here, see :ref:`introspection-open-registration`.


.. automodule:: oauth2_provider.views.application
    :members:
