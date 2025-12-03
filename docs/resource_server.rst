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
      "exp": 1419356238,
      "aud": ["https://api.example.com", "https://data.example.com"]
    }

The ``aud`` field (audience) is included when the token has resource binding per RFC 8707.
Tokens without resource restrictions will not include this field.

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


Token Audience Binding (RFC 8707)
==================================
Django OAuth Toolkit supports `RFC 8707 <https://rfc-editor.org/rfc/rfc8707.html>`_ Resource Indicators,
which allows clients to bind access tokens to specific resource servers. This prevents tokens from being
misused at unintended services.

How It Works
------------
Clients include a ``resource`` parameter in authorization and token requests to specify which
resource servers they want to access:

.. code-block:: http

    GET /o/authorize/?client_id=CLIENT_ID
        &response_type=code
        &redirect_uri=https://client.example.com/callback
        &scope=read
        &resource=https://api.example.com

The issued access token will be bound to ``https://api.example.com`` and should only be accepted
by that resource server.

Validating Token Audiences
---------------------------
Resource servers should validate that tokens are intended for them using the ``allows_audience()`` method:

.. code-block:: python

    from oauth2_provider.models import AccessToken

    def validate_request(request):
        """Validate that the token is intended for this resource server."""
        token_string = request.META.get('HTTP_AUTHORIZATION', '').split(' ')[-1]

        try:
            token = AccessToken.objects.get(token=token_string)

            # Check token is not expired
            if token.is_expired():
                return False

            # Check token audience (RFC 8707)
            if not token.allows_audience('https://api.example.com'):
                return False

            return True
        except AccessToken.DoesNotExist:
            return False

The ``allows_audience()`` method checks if the token's resource field includes the specified URI.
Tokens without resource restrictions (legacy tokens) will allow any audience for backward compatibility.

You can also retrieve all audiences for a token:

.. code-block:: python

    audiences = token.get_audiences()  # Returns list of resource URIs

Security Benefits
-----------------
RFC 8707 support provides important security benefits:

* **Prevents privilege escalation**: Tokens can only be used at authorized resource servers
* **Defense in depth**: Even if a token is stolen, it cannot be used at unintended services
* **Explicit authorization**: Users see which specific resources will be accessed

The authorization server validates that token requests only specify resources from the original
authorization, rejecting attempts to escalate privileges with an ``invalid_target`` error.
