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
Django OAuth Toolkit automatically validates token audiences when using ``validate_bearer_token()``.
By default, it uses **prefix-based matching** where the token's audience URI acts as a base URI.

Automatic Validation
~~~~~~~~~~~~~~~~~~~~
When a resource server validates a bearer token, DOT automatically checks if the request URI
matches the token's audience claim:

.. code-block:: python

    # In your Django REST Framework view or OAuth-protected endpoint
    # DOT automatically validates audience - no manual check needed!

    @require_oauth(['read'])
    def my_api_view(request):
        # If this executes, the token is valid AND authorized for this resource
        return Response({'data': 'secret'})

The default validator uses **prefix matching**: a token with audience ``https://api.example.com/v1``
will be accepted for requests to ``https://api.example.com/v1/users`` but rejected for
``https://api.example.com/v2/users``.

Resource indicators must be absolute URIs with a scheme and host, without userinfo or fragment
components (a query component is allowed per RFC 8707 but is ignored when matching). Other
absolute-URI forms, such as URNs, are rejected at issuance and never match the default
validator. Supporting them requires customization on both sides: a custom
``OAUTH2_VALIDATOR_CLASS`` overriding ``_validate_resource_uris()`` so the authorization server
accepts them at issuance, and a custom ``RESOURCE_SERVER_TOKEN_RESOURCE_VALIDATOR`` so the
resource server can match them.

Deployments Behind a Reverse Proxy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Audience validation compares the token's resource indicators against the request URI as
reconstructed by Django (``request.build_absolute_uri()``). If your resource server runs
behind a TLS-terminating reverse proxy or load balancer, Django must be configured so the
reconstructed scheme and host match the externally visible URI that clients put in the
``resource`` parameter. Otherwise resource-restricted tokens will be rejected with a
scheme (``http`` vs ``https``) or host mismatch.

Configure the standard Django settings for proxied deployments:

.. code-block:: python

    # settings.py
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    USE_X_FORWARDED_HOST = True  # if the proxy rewrites the Host header

and ensure your proxy sets the corresponding headers. See the `Django deployment docs
<https://docs.djangoproject.com/en/stable/ref/settings/#secure-proxy-ssl-header>`_ for
the security implications of these settings.

Custom Validation Logic
~~~~~~~~~~~~~~~~~~~~~~~~
You can customize the validation logic by providing your own validator function:

.. code-block:: python

    # myapp/validators.py
    def exact_match_validator(request_uri, audiences):
        """Custom validator that requires exact audience match."""
        # No audiences = unrestricted token (backward compat)
        if not audiences:
            return True

        # Require exact match
        return request_uri in audiences

    # settings.py
    OAUTH2_PROVIDER = {
        'RESOURCE_SERVER_TOKEN_RESOURCE_VALIDATOR': 'myapp.validators.exact_match_validator',
    }

To disable automatic validation entirely, set the validator to ``None``:

.. code-block:: python

    OAUTH2_PROVIDER = {
        'RESOURCE_SERVER_TOKEN_RESOURCE_VALIDATOR': None,
    }

Rejecting tokens of an unusable application
-------------------------------------------
``Application.is_usable(request)`` is a hook you can override on a
:ref:`swapped application model <extend_app_model>` to disable an application
dynamically — for example to freeze a deactivated account or enforce an IP allowlist. It
returns ``True`` by default.

``is_usable()`` is enforced on **both** sides of the flow: the authorization server checks it
at token issuance, and the resource server checks it in ``validate_bearer_token()``. A token
whose application returns ``is_usable() == False`` is therefore rejected with an
``invalid_token`` error even if the token itself is otherwise valid and unexpired. If you
override ``is_usable()``, keep in mind that returning ``False`` immediately stops the
application's existing access tokens from authenticating, not just new issuance.
