Separate Resource Server
========================
Django OAuth Toolkit allows to separate the :term:`Authorization Server` and the :term:`Resource Server`.
Based on the `RFC 7662 <https://rfc-editor.org/rfc/rfc7662.html>`_ Django OAuth Toolkit provides
a rfc-compliant introspection endpoint.
As well the Django OAuth Toolkit allows to verify access tokens by the use of an introspection endpoint.


Setup the Authentication Server
-------------------------------
Setup the :term:`Authorization Server` as described in the :doc:`tutorial/tutorial`.
Create a OAuth2 access token for the :term:`Resource Server` and add the
``introspection``-Scope to the settings.

.. code-block:: python

    'SCOPES': {
        'read': 'Read scope',
        'write': 'Write scope',
        'introspection': 'Introspect token scope',
        ...
    },

The :term:`Authorization Server` will listen for introspection requests.
The endpoint is located within the ``oauth2_provider.urls`` as ``/introspect/``.

Example Request::

    POST /o/introspect/ HTTP/1.1
    Host: server.example.com
    Accept: application/json
    Content-Type: application/x-www-form-urlencoded
    Authorization: Bearer 3yUqsWtwKYKHnfivFcJu

    token=uH3Po4KXWP4dsY4zgyxH

Example Response::

    HTTP/1.1 200 OK
    Content-Type: application/json

    {
      "active": true,
      "client_id": "oUdofn7rfhRtKWbmhyVk",
      "username": "jdoe",
      "scope": "read write dolphin",
      "exp": 1419356238
    }

Setup the Resource Server
-------------------------
Setup the :term:`Resource Server` like the :term:`Authorization Server` as described in the :doc:`tutorial/tutorial`.
Add ``RESOURCE_SERVER_INTROSPECTION_URL`` and **either** ``RESOURCE_SERVER_AUTH_TOKEN``
**or** ``RESOURCE_SERVER_INTROSPECTION_CREDENTIALS`` as a ``(id,secret)`` tuple to your settings.
The :term:`Resource Server` will try to verify its requests on the :term:`Authorization Server`.

.. code-block:: python

    OAUTH2_PROVIDER = {
        ...
        'RESOURCE_SERVER_INTROSPECTION_URL': 'https://example.org/o/introspect/',
        'RESOURCE_SERVER_AUTH_TOKEN': '3yUqsWtwKYKHnfivFcJu', # OR this but not both:
        # 'RESOURCE_SERVER_INTROSPECTION_CREDENTIALS': ('rs_client_id','rs_client_secret'),
        ...
    }

``RESOURCE_SERVER_INTROSPECTION_URL`` defines the introspection endpoint and
``RESOURCE_SERVER_AUTH_TOKEN`` an authentication token to authenticate against the
:term:`Authorization Server`.
As allowed by RFC 7662, some external OAuth 2.0 servers support HTTP Basic Authentication.
For these, use:
``RESOURCE_SERVER_INTROSPECTION_CREDENTIALS=('client_id','client_secret')`` instead
of ``RESOURCE_SERVER_AUTH_TOKEN``.
