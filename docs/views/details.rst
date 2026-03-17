Views code and details
======================


Generic
-------
Generic views are intended to use in a "batteries included" fashion to protect own views with OAuth2 authentication and
Scopes handling.

.. automodule:: oauth2_provider.views.generic
    :members:

.. _mixins:

Mixins
------
These views are mainly for internal use, but advanced users may use them as basic components to customize OAuth2 logic
inside their Django applications.

.. automodule:: oauth2_provider.views.mixins
    :members:

Base
----
Views needed to implement the main OAuth2 authorization flows supported by Django OAuth Toolkit.

.. automodule:: oauth2_provider.views.base
    :members:
