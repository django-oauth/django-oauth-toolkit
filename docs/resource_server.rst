Separate Resource Server
========================
Django OAuth Toolkit allows to separate the :term:`Authorization Server` and the :term:`Resource Server`.
Based on the `RFC 7662 <https://rfc-editor.org/rfc/rfc7662.html>`_ Django OAuth Toolkit provides
a rfc-compliant introspection endpoint.
As well the Django OAuth Toolkit allows to verify access tokens by the use of an introspection endpoint.


Setup the Authentication Server
-------------------------------
Setup the :term:`Authorization Server` as described in the :doc:`tutorial/tutorial`.
Register a confidential application for the :term:`Resource Server`, for example in the Django
admin or with the :ref:`createapplication <createapplication>` command. Its ``can_introspect``
flag is on by default (see :ref:`introspection-authorization`). The resource server can then
authenticate to the introspection endpoint as that client, or use an OAuth2 access token issued to
it; for the latter, add the ``introspection``-Scope to the settings.

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

.. _introspection-authorization:

Who may introspect
~~~~~~~~~~~~~~~~~~
To prevent token scanning,
`RFC 7662 section 2.1 <https://rfc-editor.org/rfc/rfc7662.html#section-2.1>`_ requires some form of
authorization to call the introspection endpoint, such as client authentication or a separate
access token, and `section 4 <https://rfc-editor.org/rfc/rfc7662.html#section-4>`_ requires the
authorization server to authenticate the protected resources that call it. Django OAuth Toolkit
accepts either, and also records on each application, in the ``can_introspect`` field, whether it
may introspect at all, and checks it on both ways of calling the endpoint:

* **Client authentication** (HTTP Basic, ``client_id``/``client_secret`` in the body, or an
  :doc:`RFC 7523 client assertion <rfc7523>`): the authenticated application must be a
  confidential client and have ``can_introspect`` set. A public client is refused even when it
  has a secret: it cannot keep credentials confidential
  (`RFC 6749 section 2.1 <https://rfc-editor.org/rfc/rfc6749.html#section-2.1>`_), so they do not
  authenticate the caller as RFC 7662 section 4 requires. This also keeps the validator's
  device-code shortcut, which accepts a public client with no secret at all, from opening the
  endpoint.
* **Bearer token**: the token must carry the ``introspection`` scope *and* the application it was
  issued to must have ``can_introspect`` set; it may be a public or a confidential client. A token
  with no application is refused, since there is no client to check. That includes access tokens
  created by hand without one, and the tokens a resource server configured with
  ``RESOURCE_SERVER_INTROSPECTION_URL`` caches from a remote introspection response (they are
  stored with no application), so such a resource server cannot relay them to this endpoint; give
  it a token issued to an application, or have it authenticate as one. The application checked
  is ``request.access_token.application`` whenever ``request.access_token`` has an
  ``application`` attribute, even one that is ``None``, and ``request.client`` only when it has
  none; either way it must be an instance of the (swappable) Application model. A custom
  ``OAUTH2_VALIDATOR_CLASS`` whose ``validate_bearer_token()`` sets neither (say, it keeps a
  JWT's claims in ``request.access_token``), or sets something other than an Application
  instance, leaves no client to check, so its tokens are refused.

A caller that fails either check receives the same bare ``403 Forbidden`` an unauthenticated
caller gets, with an empty body.

The client-authentication check calls the ``authenticate_client()`` of the configured
``OAUTH2_BACKEND_CLASS`` once, so a custom backend's own policy always applies, and then authorizes
the client that ``OAuthLibCore.authenticate_client_request()`` recorded on the request while that
call ran. A custom backend that subclasses ``OAuthLibCore`` therefore keeps working as long as its
``authenticate_client()`` either calls ``super().authenticate_client(request)`` (or
``self.authenticate_client_request(request)``), adding any checks of its own before it returns
the result, or returns ``False``. Returning ``True`` when that call did not authenticate the
client authorizes nobody, and is logged as a warning. A backend that authenticates clients without
going through ``OAuthLibCore.authenticate_client_request()``, such as one that does not subclass
``OAuthLibCore`` and runs the validator itself, has no supported way to report which client
authenticated, so the endpoint refuses client authentication for it. Each warning is logged the
first time it applies to a backend class in a process. Bearer tokens are still accepted.

``can_introspect`` is an opt-out capability: it defaults to ``True``, and every way of creating an
application keeps that default, including the self-service registration view, :doc:`Dynamic
Client Registration <views/dynamic_client_registration>` and :doc:`Client ID Metadata Documents
<cimd>`. So by default any confidential client can introspect with its own credentials, and any
client can introspect with an access token issued to it that carries the ``introspection`` scope.
That matches common identity provider practice, where a client can validate the tokens it holds.
The authentication requirement only keeps out callers who cannot get credentials, so whether it
stops token scanning depends on who can register a client; see
:ref:`introspection-open-registration`.

The flag is editable in the Django admin only, and with
``createapplication --can-introspect``/``--no-can-introspect``. It is not on the self-service
forms (a custom ``APPLICATION_FORM_CLASS`` must not expose it either; see
:ref:`custom-application-form`). It is not client metadata, so neither DCR nor a CIMD document can
set or change it, and a CIMD re-fetch keeps the value an administrator set.

`RFC 7662 section 4 <https://rfc-editor.org/rfc/rfc7662.html#section-4>`_ recommends answering only
callers *specifically authorized* to introspect. To follow it, turn ``can_introspect`` off for
every application except your resource servers, in the Django admin (the application list can be
filtered on it), and create new clients with ``createapplication --no-can-introspect`` (or
``can_introspect=False`` in code) unless they are resource servers. Clients that register
themselves get the default too; to turn it off as they register, see
:ref:`introspection-open-registration`.

A future release may also add an audience check, requiring the introspecting client to be an
audience of the token, as the Red Hat build of Keycloak 26.4.12 does. That is planned as a
follow-up.

.. _introspection-open-registration:

Introspection when registration is open
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
When anyone can register a client, the authentication requirement does not keep anyone from
scanning for tokens: they register a client and introspect with it straight away. That is the
case when :doc:`Dynamic Client Registration <views/dynamic_client_registration>` is enabled, with
``AllowAllDCRPermission`` (anyone) or with the default ``IsAuthenticatedDCRPermission`` (anyone who
can log in); when the self-service registration view (``oauth2_provider:register``) is mounted;
and when :doc:`CIMD <cimd>` is enabled. A confidential client registered through DCR or the
self-service view, or a CIMD client that uses ``private_key_jwt``, introspects with its own
credentials. Any of these clients can also introspect with an access token issued to it that
carries the ``introspection`` scope, which its registrant can obtain by authorizing it for that
scope; for a public CIMD client, one that uses ``none``, that is its only way.

Registration cannot set ``can_introspect``, so to keep these clients out, turn the flag off on the
rows they create. DCR and CIMD rows carry ``registration_source`` ``"dcr"`` and ``"cimd"``, so a
``pre_save`` receiver can turn it off for new rows from those sources::

    # your_app/signals.py
    def no_introspection_for_registered_clients(sender, instance, raw, **kwargs):
        """Turn can_introspect off for clients that registered through DCR or CIMD."""
        if raw or not instance._state.adding:
            return
        if instance.registration_source in (
            sender.RegistrationSource.DCR,
            sender.RegistrationSource.CIMD,
        ):
            instance.can_introspect = False

::

    # your_app/apps.py
    from django.apps import AppConfig


    class YourAppConfig(AppConfig):
        name = "your_app"

        def ready(self):
            from django.db.models.signals import pre_save

            from oauth2_provider.models import get_application_model

            from .signals import no_introspection_for_registered_clients

            pre_save.connect(
                no_introspection_for_registered_clients,
                sender=get_application_model(),
                dispatch_uid="no_introspection_for_registered_clients",
            )

It acts only when a row is created, so an administrator can turn the flag back on for a client in
the admin, and a later RFC 7592 update or CIMD re-fetch keeps that. It leaves fixtures
(``loaddata``) alone.

Rows created through the self-service registration view cannot be told apart that way: they get
``registration_source="manual"``, as do rows created in the admin, with ``createapplication`` and
in code. Turn the flag off in that view's form instead, with an ``APPLICATION_FORM_CLASS`` (see
:ref:`custom-application-form`)::

    # your_app/forms.py
    from oauth2_provider.authorization_server.forms import ApplicationForm


    class NoIntrospectionApplicationForm(ApplicationForm):
        """The self-service registration form: applications created with it cannot introspect."""

        def save(self, commit=True):
            if self.instance._state.adding:
                self.instance.can_introspect = False
            return super().save(commit)

::

    # settings.py
    OAUTH2_PROVIDER = {
        ...
        "APPLICATION_FORM_CLASS": "your_app.forms.NoIntrospectionApplicationForm",
    }

The update view uses the same form, but only a new application is changed, so editing one keeps
the value an administrator set. The Django admin does not use ``APPLICATION_FORM_CLASS``, so
applications created there keep the default. If you do not offer self-service registration, leave the view out of your
URLconf instead.

Both only act on applications created after you add them. Clients that registered earlier,
including every one that existed before the upgrade, keep ``can_introspect=True``. Turn it off
for the existing DCR and CIMD rows once, for example in a data migration or the Django shell::

    from oauth2_provider.models import get_application_model

    Application = get_application_model()
    Application.objects.filter(
        registration_source__in=(
            Application.RegistrationSource.DCR,
            Application.RegistrationSource.CIMD,
        )
    ).update(can_introspect=False)

Earlier self-service registrations cannot be selected that way, since they share
``registration_source="manual"`` with administrators' applications; review them in the admin,
which can filter applications by ``can_introspect``.

The migration that adds the field (``oauth2_provider`` ``0026_application_can_introspect``) gives
every existing application the default ``True``, so the flag itself takes nothing away on
upgrade. It skips a swapped Application model (``OAUTH2_PROVIDER_APPLICATION_MODEL``): a
deployment with one adds the field in a migration of its own app (``makemigrations`` generates
it); no data step is needed.

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

Authenticating with private_key_jwt (RFC 7523)
----------------------------------------------
When the external :term:`Authorization Server` expects :doc:`JWT client authentication <rfc7523>`
instead of a static token or Basic credentials, configure a signing key and audience; the
:term:`Resource Server` then generates a fresh ``private_key_jwt`` client assertion (new ``jti``,
short expiry) for every introspection request:

.. code-block:: python

    OAUTH2_PROVIDER = {
        ...
        'RESOURCE_SERVER_INTROSPECTION_URL': 'https://example.org/o/introspect/',
        'RESOURCE_SERVER_INTROSPECTION_JWT_CLIENT_ID': 'rs_client_id',
        'RESOURCE_SERVER_INTROSPECTION_JWT_PRIVATE_KEY': RS_PRIVATE_KEY_PEM,  # or a JWK JSON string
        'RESOURCE_SERVER_INTROSPECTION_JWT_AUDIENCE': 'https://example.org',  # the AS issuer
        ...
    }

All three settings must be set together. ``RESOURCE_SERVER_AUTH_TOKEN`` and
``RESOURCE_SERVER_INTROSPECTION_CREDENTIALS`` take precedence when configured. See
:doc:`settings` for the optional ``RESOURCE_SERVER_INTROSPECTION_JWT_ALG``, ``_LIFETIME`` and
``_KID`` settings.


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
