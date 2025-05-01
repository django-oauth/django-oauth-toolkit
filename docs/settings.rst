Settings
========

Our configurations are all namespaced under the ``OAUTH2_PROVIDER`` settings, with the exception
of the `List of non-namespaced settings`_.

For example:

.. code-block:: python

    OAUTH2_PROVIDER = {
        'SCOPES': {
            'read': 'Read scope',
            'write': 'Write scope',
        },

        'CLIENT_ID_GENERATOR_CLASS': 'oauth2_provider.generators.ClientIdGenerator',

    }


A big *thank you* to the guys from Django REST Framework for inspiring this.


List of available settings within OAUTH2_PROVIDER
-------------------------------------------------

ACCESS_TOKEN_EXPIRE_SECONDS
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Default: ``36000``

The number of seconds an access token remains valid. Requesting a protected
resource after this duration will fail. Keep this value high enough so clients
can cache the token for a reasonable amount of time.

ACCESS_TOKEN_GENERATOR
~~~~~~~~~~~~~~~~~~~~~~
Import path of a callable used to generate access tokens.
``oauthlib.oauth2.rfc6749.tokens.random_token_generator`` is (normally) used if not provided.

ALLOWED_REDIRECT_URI_SCHEMES
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Default: ``["http", "https"]``

A list of schemes that the ``redirect_uri`` field will be validated against.
Setting this to ``["https"]`` only in production is strongly recommended.

For Native Apps the ``http`` scheme can be safely used with loopback addresses in the
Application (``[::1]`` or ``127.0.0.1``). In this case the ``redirect_uri`` can be
configured without explicit port specification, so that the Application accepts randomly
assigned ports.

Note that you may override ``Application.get_allowed_schemes()`` to set this on
a per-application basis.

ALLOW_URI_WILDCARDS
~~~~~~~~~~~~~~~~~~~
Default: ``False``

SECURITY WARNING: Enabling this setting can introduce security vulnerabilities. Only enable
this setting if you understand the risks. https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
states "The redirection endpoint URI MUST be an absolute URI as defined by [RFC3986] Section 4.3." The
intent of the URI restrictions is to prevent open redirects and phishing attacks. If you do enable this
ensure that the wildcards restrict URIs to resources under your control. You are strongly encouragd not
to use this feature in production.

When set to ``True``, the server will allow wildcard characters in the domains for allowed_origins and
redirect_uris.

``*`` is the only wildcard character allowed.

``*`` can only be used as a prefix to a domain, must be the first character in
the domain, and cannot be in the top or second level domain.  Matching is done using an
endsWith check.

For example,
``https://*.example.com`` is allowed,
``https://*-myproject.example.com`` is allowed,
``https://*.sub.example.com`` is not allowed,
``https://*.com`` is not allowed, and
``https://example.*.com`` is not allowed.

This feature is useful for working with CI service such as cloudflare, netlify, and vercel that offer branch
deployments for development previews and user acceptance testing.

ALLOWED_SCHEMES
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Default: ``["https"]``

A list of schemes that the ``allowed_origins`` field will be validated against.
Setting this to ``["https"]`` only in production is strongly recommended.
Adding ``"http"`` to the list is considered to be safe only for local development and testing.
Note that `OAUTHLIB_INSECURE_TRANSPORT <https://oauthlib.readthedocs.io/en/latest/oauth2/security.html#envvar-OAUTHLIB_INSECURE_TRANSPORT>`_
environment variable should be also set to allow HTTP origins.

AUTHORIZATION_CODE_EXPIRE_SECONDS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Default: ``60``

The number of seconds an authorization code remains valid. Requesting an access
token after this duration will fail. :rfc:`4.1.2` recommends expire after a short lifetime,
with 10 minutes (600 seconds) being the maximum acceptable.

CLIENT_ID_GENERATOR_CLASS
~~~~~~~~~~~~~~~~~~~~~~~~~
The import string of the class responsible for generating client identifiers.
These are usually random strings.

CLIENT_SECRET_GENERATOR_CLASS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The import string of the class responsible for generating client secrets.
These are usually random strings.

CLIENT_SECRET_GENERATOR_LENGTH
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The length of the generated secrets, in characters. If this value is too low,
secrets may become subject to bruteforce guessing.

CLIENT_SECRET_HASHER
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The hasher for storing generated secrets. By default library will use the first hasher in PASSWORD_HASHERS.

EXTRA_SERVER_KWARGS
~~~~~~~~~~~~~~~~~~~
A dictionary to be passed to oauthlib's Server class. Three options
are natively supported: token_expires_in, token_generator,
refresh_token_generator. There's no extra processing so callables (every one
of those three can be a callable) must be passed here directly and classes
must be instantiated (callables should accept request as their only argument).

GRANT_MODEL
~~~~~~~~~~~
The import string of the class (model) representing your grants. Overwrite
this value if you wrote your own implementation (subclass of
``oauth2_provider.models.Grant``).

APPLICATION_ADMIN_CLASS
~~~~~~~~~~~~~~~~~~~~~~~
The import string of the class (model) representing your application admin class.
Overwrite this value if you wrote your own implementation (subclass of
``oauth2_provider.admin.ApplicationAdmin``).

ACCESS_TOKEN_ADMIN_CLASS
~~~~~~~~~~~~~~~~~~~~~~~~
The import string of the class (model) representing your access token admin class.
Overwrite this value if you wrote your own implementation (subclass of
``oauth2_provider.admin.AccessTokenAdmin``).

GRANT_ADMIN_CLASS
~~~~~~~~~~~~~~~~~
The import string of the class (model) representing your grant admin class.
Overwrite this value if you wrote your own implementation (subclass of
``oauth2_provider.admin.GrantAdmin``).

REFRESH_TOKEN_ADMIN_CLASS
~~~~~~~~~~~~~~~~~~~~~~~~~
The import string of the class (model) representing your refresh token admin class.
Overwrite this value if you wrote your own implementation (subclass of
``oauth2_provider.admin.RefreshTokenAdmin``).

OAUTH2_SERVER_CLASS
~~~~~~~~~~~~~~~~~~~
The import string for the ``server_class`` (or ``oauthlib.oauth2.Server`` subclass)
used in the ``OAuthLibMixin`` that implements OAuth2 grant types. It defaults
to ``oauthlib.oauth2.Server``, except when :doc:`oidc` is enabled, when the
default is ``oauthlib.openid.Server``.

OAUTH2_VALIDATOR_CLASS
~~~~~~~~~~~~~~~~~~~~~~
The import string of the ``oauthlib.oauth2.RequestValidator`` subclass that
validates every step of the OAuth2 process.

OAUTH2_BACKEND_CLASS
~~~~~~~~~~~~~~~~~~~~
The import string for the ``oauthlib_backend_class`` used in the ``OAuthLibMixin``,
to get a ``Server`` instance.

REFRESH_TOKEN_EXPIRE_SECONDS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The number of seconds before a refresh token gets removed from the database by
the ``cleartokens`` management command. Check :ref:`cleartokens` management command for further info.
Can be an ``Int`` or ``datetime.timedelta``.

NOTE: This value is completely ignored when validating refresh tokens.
If you don't change the validator code and don't run cleartokens all refresh
tokens will last until revoked or the end of time. You should change this.

REFRESH_TOKEN_GRACE_PERIOD_SECONDS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The number of seconds between when a refresh token is first used when it is
expired. The most common case of this for this is native mobile applications
that run into issues of network connectivity during the refresh cycle and are
unable to complete the full request/response life cycle. Without a grace
period the application, the app then has only a consumed refresh token and the
only recourse is to have the user re-authenticate. A suggested value, if this
is enabled, is 2 minutes.

REFRESH_TOKEN_REUSE_PROTECTION
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
When this is set to ``True`` (default ``False``), and ``ROTATE_REFRESH_TOKEN`` is used, the server will check
if a previously, already revoked refresh token is used a second time. If it detects a reuse, it will automatically
revoke all related refresh tokens.
A reused refresh token indicates a breach. Since the server can't determine which request came from the legitimate
user and which from an attacker, it will end the session for both. The user is required to perform a new login.

Can be used in combination with ``REFRESH_TOKEN_GRACE_PERIOD_SECONDS``

More details at https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-29#name-recommendations

ROTATE_REFRESH_TOKEN
~~~~~~~~~~~~~~~~~~~~
When is set to ``True`` (default) a new refresh token is issued to the client when the client refreshes an access token.
If ``False``, it will reuse the same refresh token and only update the access token with a new token value.
See also: validator's rotate_refresh_token method can be overridden to make this variable
(could be usable with expiring refresh tokens, in particular, so that they are rotated
when close to expiration, theoretically).

REFRESH_TOKEN_GENERATOR
~~~~~~~~~~~~~~~~~~~~~~~
See `ACCESS_TOKEN_GENERATOR`_. This is the same but for refresh tokens.
Defaults to access token generator if not provided.

REQUEST_APPROVAL_PROMPT
~~~~~~~~~~~~~~~~~~~~~~~
Can be ``'force'`` or ``'auto'``.
The strategy used to display the authorization form. Refer to :ref:`skip-auth-form`.

SCOPES_BACKEND_CLASS
~~~~~~~~~~~~~~~~~~~~
**New in 0.12.0**. The import string for the scopes backend class.
Defaults to ``oauth2_provider.scopes.SettingsScopes``, which reads scopes through the settings defined below.

SCOPES
~~~~~~
.. note:: (0.12.0+) Only used if ``SCOPES_BACKEND_CLASS`` is set to the SettingsScopes default.

A dictionary mapping each scope name to its human description.

.. _settings_default_scopes:

DEFAULT_SCOPES
~~~~~~~~~~~~~~
.. note:: (0.12.0+) Only used if ``SCOPES_BACKEND_CLASS`` is set to the SettingsScopes default.

A list of scopes that should be returned by default.
This is a subset of the keys of the ``SCOPES`` setting.
By default this is set to ``'__all__'`` meaning that the whole set of ``SCOPES`` will be returned.

.. code-block:: python

  DEFAULT_SCOPES = ['read', 'write']

READ_SCOPE
~~~~~~~~~~
.. note:: (0.12.0+) Only used if ``SCOPES_BACKEND_CLASS`` is set to the SettingsScopes default.

The name of the *read* scope.

WRITE_SCOPE
~~~~~~~~~~~
.. note:: (0.12.0+) Only used if ``SCOPES_BACKEND_CLASS`` is set to the SettingsScopes default.

The name of the *write* scope.

ERROR_RESPONSE_WITH_SCOPES
~~~~~~~~~~~~~~~~~~~~~~~~~~
When authorization fails due to insufficient scopes include the required scopes in the response.
Only applicable when used with `Django REST Framework <http://django-rest-framework.org/>`_

RESOURCE_SERVER_INTROSPECTION_URL
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The introspection endpoint for validating token remotely (RFC7662). This URL requires either an authorization
token (``RESOURCE_SERVER_AUTH_TOKEN``)
or HTTP Basic Auth client credentials (``RESOURCE_SERVER_INTROSPECTION_CREDENTIALS``).

RESOURCE_SERVER_AUTH_TOKEN
~~~~~~~~~~~~~~~~~~~~~~~~~~
The bearer token to authenticate the introspection request towards the introspection endpoint (RFC7662).

RESOURCE_SERVER_INTROSPECTION_CREDENTIALS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The HTTP Basic Auth Client_ID and Client_Secret to authenticate the introspection request
towards the introspect endpoint (RFC7662) as a tuple: ``(client_id, client_secret)``.

RESOURCE_SERVER_TOKEN_CACHING_SECONDS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The number of seconds an authorization token received from the introspection endpoint remains valid.
If the expire time of the received token is less than ``RESOURCE_SERVER_TOKEN_CACHING_SECONDS`` the expire time
will be used.

AUTHENTICATION_SERVER_EXP_TIME_ZONE
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The exp (expiration date) of Access Tokens must be defined in UTC (Unix Timestamp). Although its wrong, sometimes
a remote Authentication Server does not use UTC (eg. no timezone support and configured in local time other than UTC).
Prior to fix #1292 this could be fixed by changing your own time zone. With the introduction of this fix, this workaround
would not be possible anymore. This setting re-enables this workaround.

PKCE_REQUIRED
~~~~~~~~~~~~~
Default: ``True``

Can be either a bool or a callable that takes a client id and returns a bool.

Whether or not `Proof Key for Code Exchange <https://oauth.net/2/pkce/>`_ is required.

According to `OAuth 2.0 Security Best Current Practice <https://oauth.net/2/oauth-best-practice/>`_ related to the
`Authorization Code Grant <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.1.>`_

- Public clients MUST use PKCE `RFC7636 <https://datatracker.ietf.org/doc/html/rfc7636>`_
- For confidential clients, the use of PKCE `RFC7636 <https://datatracker.ietf.org/doc/html/rfc7636>`_ is RECOMMENDED.

OIDC_ENABLED
~~~~~~~~~~~~
Default: ``False``

Whether or not :doc:`oidc` support is enabled.

OIDC_RSA_PRIVATE_KEY
~~~~~~~~~~~~~~~~~~~~
Default: ``""``

The RSA private key used to sign OIDC ID tokens. If not set, OIDC is disabled.

OIDC_RSA_PRIVATE_KEYS_INACTIVE
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Default: ``[]``

An array of *inactive* RSA private keys. These keys are not used to sign tokens,
but are published in the jwks_uri location.

This is useful for providing a smooth transition during key rotation.
``OIDC_RSA_PRIVATE_KEY`` can be replaced, and recently decommissioned keys
should be retained in this inactive list.

OIDC_JWKS_MAX_AGE_SECONDS
~~~~~~~~~~~~~~~~~~~~~~~~~
Default: ``3600``

The max-age value for the Cache-Control header on jwks_uri.

This enables the verifier to safely cache the JWK Set and not have to re-download
the document for every token.

OIDC_USERINFO_ENDPOINT
~~~~~~~~~~~~~~~~~~~~~~
Default: ``""``

The url of the userinfo endpoint. Used to advertise the location of the
endpoint in the OIDC discovery metadata. Changing this does not change the URL
that ``django-oauth-toolkit`` adds for the userinfo endpoint, so if you change
this you must also provide the service at that endpoint.

If unset, the default location is used, eg if ``django-oauth-toolkit`` is
mounted at ``/o/``, it will be ``<server-address>/o/userinfo/``.


OIDC_RP_INITIATED_LOGOUT_ENABLED
~~~~~~~~~~~~~~~~~~~~~~~~
Default: ``False``

When is set to ``False`` (default) the `OpenID Connect RP-Initiated Logout <https://openid.net/specs/openid-connect-rpinitiated-1_0.html>`_
endpoint is not enabled. OpenID Connect RP-Initiated Logout enables an :term:`Client` (Relying Party)
to request that a :term:`Resource Owner` (End User) is logged out at the :term:`Authorization Server` (OpenID Provider).

OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Default: ``True``

Whether to always prompt the :term:`Resource Owner` (End User) to confirm a logout requested by a
:term:`Client` (Relying Party). If it is disabled the :term:`Resource Owner` (End User) will only be prompted if required by the standard.

OIDC_RP_INITIATED_LOGOUT_STRICT_REDIRECT_URIS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Default: ``False``

Enable this setting to require `https` in post logout redirect URIs. `http` is only allowed when a :term:`Client` is `confidential`.

OIDC_RP_INITIATED_LOGOUT_ACCEPT_EXPIRED_TOKENS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Default: ``True``

Whether expired ID tokens are accepted for RP-Initiated Logout. The Tokens must still be signed by the OP and otherwise valid.

OIDC_RP_INITIATED_LOGOUT_DELETE_TOKENS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Default: ``True``

Whether to delete the access, refresh and ID tokens of the user that is being logged out.
The types of applications for which tokens are deleted can be customized with ``RPInitiatedLogoutView.token_types_to_delete``.
The default is to delete the tokens of all applications if this flag is enabled.

OIDC_RP_INITIATED_REGISTRATION_ENABLED
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Default: ``False``

Whether to allow the Relying Party (RP) to direct a user to an OpenID
Provider (OP) to create a new account rather than authenticate with an
existing one. This is done by adding a `prompt=create` parameter to
the authorization request.

OIDC_RP_INITIATED_REGISTRATION_VIEW_NAME
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Default: ''

The name of the view for the URL that the user will be redirected to
in case RP-Initated Registration is enabled.



OIDC_ISS_ENDPOINT
~~~~~~~~~~~~~~~~~
Default: ``""``

The URL of the issuer that is used in the ID token JWT and advertised in the
OIDC discovery metadata. Clients use this location to retrieve the OIDC
discovery metadata from ``OIDC_ISS_ENDPOINT`` +
``/.well-known/openid-configuration``.

If unset, the default location is used, eg if ``django-oauth-toolkit`` is
mounted at ``/o``, it will be ``<server-address>/o``.

OIDC_RESPONSE_TYPES_SUPPORTED
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Default::

    [
        "code",
        "token",
        "id_token",
        "id_token token",
        "code token",
        "code id_token",
        "code id_token token",
    ]


The response types that are advertised to be supported by this server.

OIDC_SUBJECT_TYPES_SUPPORTED
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Default: ``["public"]``

The subject types that are advertised to be supported by this server.

OIDC_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Default: ``["client_secret_post", "client_secret_basic"]``

The authentication methods that are advertised to be supported by this server.

CLEAR_EXPIRED_TOKENS_BATCH_SIZE
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Default: ``10000``

The size of delete batches used by ``cleartokens`` management command.

CLEAR_EXPIRED_TOKENS_BATCH_INTERVAL
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Default: ``0``

Time of sleep in seconds used by ``cleartokens`` management command between batch deletions.

Set this to a non-zero value (e.g. ``0.1``) to add a pause between batch sizes to reduce system
load when clearing large batches of expired tokens.

List of non-namespaced settings
-------------------------------
.. note::
   These settings must be set as top-level Django settings (outside of ``OAUTH2_PROVIDER``),
   because of the way Django currently implements swappable models.
   See `issue #90 <https://github.com/jazzband/django-oauth-toolkit/issues/90>`_ for details.


OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The import string of the class (model) representing your access tokens.
Overwrite this value if you wrote your own implementation (subclass of
``oauth2_provider.models.AccessToken``).

OAUTH2_PROVIDER_APPLICATION_MODEL
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The import string of the class (model) representing your applications.
Overwrite this value if you wrote your own implementation (subclass of
``oauth2_provider.models.Application``).

OAUTH2_PROVIDER_ID_TOKEN_MODEL
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The import string of the class (model) representing your OpenID Connect ID Token.
Overwrite this value if you wrote your own implementation (subclass of
``oauth2_provider.models.IDToken``).

OAUTH2_PROVIDER_GRANT_MODEL
~~~~~~~~~~~~~~~~~~~~~~~~~~~
The import string of the class (model) representing your OAuth2 grants.
Overwrite this value if you wrote your own implementation (subclass of
``oauth2_provider.models.Grant``).

OAUTH2_PROVIDER_REFRESH_TOKEN_MODEL
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The import string of the class (model) representing your refresh tokens.
Overwrite this value if you wrote your own implementation (subclass of
``oauth2_provider.models.RefreshToken``).

Settings imported from Django project
-------------------------------------

USE_TZ
~~~~~~
Used to determine whether or not to make token expire dates timezone aware.
