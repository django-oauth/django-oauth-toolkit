Application Views
=================

A set of views is provided to let users handle application instances without accessing Django Admin
Site. Application views are listed at the url ``applications/`` and you can register a new one at the
url ``applications/register``. You can override default templates located in
:file:`templates/oauth2_provider` folder and provide a custom layout. Every view provides access only to
data belonging to the logged in user who performs the request.


.. automodule:: oauth2_provider.views.application
    :members:
