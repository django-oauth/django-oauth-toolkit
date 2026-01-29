OpenID Connect
++++++++++++++

OpenID Connect support
======================

``django-oauth-toolkit`` supports `OpenID Connect <https://openid.net/specs/openid-connect-core-1_0.html>`_
(OIDC), which standardizes authentication flows and provides a plug and play integration with other
systems. OIDC is built on top of OAuth 2.0 to provide:

* Generating ID tokens as part of the login process. These are JWT that
  describe the user, and can be used to authenticate them to your application.
* Metadata based auto-configuration for providers
* A user info endpoint, which applications can query to get more information
  about a user.

Enabling OIDC doesn't affect your existing OAuth 2.0 flows, these will
continue to work alongside OIDC.

We support:

* OpenID Connect Authorization Code Flow
* OpenID Connect Implicit Flow
* OpenID Connect Hybrid Flow

Furthermore ``django-oauth-toolkit`` also supports `OpenID Connect RP-Initiated Logout <https://openid.net/specs/openid-connect-rpinitiated-1_0.html>`_.


Configuration
=============

OIDC is not enabled by default because it requires additional configuration
that must be provided. ``django-oauth-toolkit`` supports two different
algorithms for signing JWT tokens, ``RS256``, which uses asymmetric RSA keys (a
public key and a private key), and ``HS256``, which uses a symmetric key.

It is preferable to use ``RS256``, because this produces a token that can be
verified by anyone using the public key (which is made available and
discoverable by OIDC service auto-discovery, included with
``django-oauth-toolkit``). ``HS256`` on the other hand uses the
``client_secret`` in order to verify keys. This is simpler to implement, but
makes it harder to safely verify tokens.

Using ``HS256`` also means that you cannot use the Implicit or Hybrid flows,
or verify the tokens in public clients, because you cannot disclose the
``client_secret`` to a public client. If you are using a public client, you
must use ``RS256``.


Creating RSA private key
~~~~~~~~~~~~~~~~~~~~~~~~

To use ``RS256`` requires an RSA private key, which is used for signing JWT. You
can generate this using the `openssl`_ tool::

    openssl genrsa -out oidc.key 4096

This will generate a 4096-bit RSA key, which will be sufficient for our needs.

.. _openssl: https://www.openssl.org

.. warning::
    The contents of this key *must* be kept a secret. Don't put it in your
    settings and commit it to version control!

    If the key is ever accidentally disclosed, an attacker could use it to
    forge JWT tokens that verify as issued by your OAuth provider, which is
    very bad!

    If it is ever disclosed, you should immediately replace the key.

    Safe ways to handle it would be:

    * Store it in a secure system like `Hashicorp Vault`_, and inject it in to
      your environment when running your server.
    * Store it in a secure file on your server, and use your initialization
      scripts to inject it in to your environment.

.. _Hashicorp Vault: https://www.hashicorp.com/products/vault

Now we need to add this key to our settings and allow the ``openid`` scope to
be used. Assuming we have set an environment variable called
``OIDC_RSA_PRIVATE_KEY``, we can make changes to our ``settings.py``::

    import os

    OAUTH2_PROVIDER = {
        "OIDC_ENABLED": True,
        "OIDC_RSA_PRIVATE_KEY": os.environ.get("OIDC_RSA_PRIVATE_KEY"),
        "SCOPES": {
            "openid": "OpenID Connect scope",
            # ... any other scopes that you use
        },
        # ... any other settings you want
    }

If you are adding OIDC support to an existing OAuth 2.0 provider site, and you
are currently using a custom class for ``OAUTH2_SERVER_CLASS``, you must
change this class to derive from ``oauthlib.openid.Server`` instead of
``oauthlib.oauth2.Server``.

With ``RSA`` key-pairs, the public key can be generated from the private key,
so there is no need to add a setting for the public key.


Rotating the RSA private key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Extra keys can be published in the jwks_uri with the ``OIDC_RSA_PRIVATE_KEYS_INACTIVE``
setting. For example:::

    OAUTH2_PROVIDER = {
        "OIDC_RSA_PRIVATE_KEY": os.environ.get("OIDC_RSA_PRIVATE_KEY"),
        "OIDC_RSA_PRIVATE_KEYS_INACTIVE": [
            os.environ.get("OIDC_RSA_PRIVATE_KEY_2"),
            os.environ.get("OIDC_RSA_PRIVATE_KEY_3")
        ]
        # ... other settings
    }

To rotate, follow these steps:

#. Generate a new key, and add it to the inactive set. Then deploy the app.
#. Swap the active and inactive keys, then re-deploy.
#. After some reasonable amount of time, remove the inactive key. At a minimum,
   you should wait ``ID_TOKEN_EXPIRE_SECONDS`` to ensure the key isn't removed
   before valid tokens expire.


Using ``HS256`` keys
~~~~~~~~~~~~~~~~~~~~

If you would prefer to use just ``HS256`` keys, you don't need to create any
additional keys, ``django-oauth-toolkit`` will just use the application's
``client_secret`` to sign the JWT token.

To be able to verify the JWT's signature using the ``client_secret``, you
must set the application's ``hash_client_secret`` to ``False``.

In this case, you just need to enable OIDC and add ``openid`` to your list of
scopes in your ``settings.py``::

    OAUTH2_PROVIDER = {
        "OIDC_ENABLED": True,
        "SCOPES": {
            "openid": "OpenID Connect scope",
            # ... any other scopes that you use
        },
        # ... any other settings you want
    }

.. note::
    ``RS256`` is the more secure algorithm for signing your JWTs. Only use ``HS256`` if you must.
    Using ``RS256`` will allow you to keep your ``client_secret`` hashed.


RP-Initiated Logout
~~~~~~~~~~~~~~~~~~~
This feature has to be enabled separately as it is an extension to the core standard.

.. code-block:: python

   OAUTH2_PROVIDER = {
       # OIDC has to be enabled to use RP-Initiated Logout
       "OIDC_ENABLED": True,
       # Enable and configure RP-Initiated Logout
       "OIDC_RP_INITIATED_LOGOUT_ENABLED": True,
       "OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT": True,
       # ... any other settings you want
   }


Setting up OIDC enabled clients
===============================

Setting up an OIDC client in ``django-oauth-toolkit`` is simple - in fact, all
existing OAuth 2.0 Authorization Code Flow and Implicit Flow applications that
are already configured can be easily updated to use OIDC by setting the
appropriate algorithm for them to use.

You can also switch existing apps to use OIDC Hybrid Flow by changing their
Authorization Grant Type and selecting a signing algorithm to use.

You can read about the pros and cons of the different flows in `this excellent
article`_ from Robert Broeckelmann.

.. _this excellent article: https://medium.com/@robert.broeckelmann/when-to-use-which-oauth2-grants-and-oidc-flows-ec6a5c00d864

OIDC Authorization Code Flow
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To create an OIDC Authorization Code Flow client, create an ``Application``
with the grant type ``Authorization code`` and select your desired signing
algorithm.

When making an authorization request, be sure to include ``openid`` as a
scope. When the code is exchanged for the access token, the response will
also contain an ID token JWT.

If the ``openid`` scope is not requested, authorization requests will be
treated as standard OAuth 2.0 Authorization Code Grant requests.

With ``PKCE`` enabled, even public clients can use this flow, and it is the most
secure and recommended flow.

OIDC Implicit Flow
~~~~~~~~~~~~~~~~~~

OIDC Implicit Flow is very similar to OAuth 2.0 Implicit Grant, except that
the client can request a ``response_type`` of ``id_token`` or ``id_token
token``. Requesting just ``token`` is also possible, but it would make it not
an OIDC flow and would fall back to being the same as OAuth 2.0 Implicit
Grant.

To setup an OIDC Implicit Flow client, simply create an ``Application`` with
the a grant type of ``Implicit`` and select your desired signing algorithm,
and configure the client to request the ``openid`` scope and an OIDC
``response_type`` (``id_token`` or ``id_token token``).


OIDC Hybrid Flow
~~~~~~~~~~~~~~~~

OIDC Hybrid Flow is a mixture of the previous two flows. It allows the ID
token and an access token to be returned to the frontend, whilst also
allowing the backend to retrieve the ID token and an access token (not
necessarily the same access token) on the backend.

To setup an OIDC Hybrid Flow application, create an ``Application`` with a
grant type of ``OpenID connect hybrid`` and select your desired signing
algorithm.


Customizing the OIDC responses
==============================

This basic configuration will give you a basic working OIDC setup, but your
ID tokens will have very few claims in them, and the ``UserInfo`` service will
just return the same claims as the ID token.

To configure all of these things we need to customize the
``OAUTH2_VALIDATOR_CLASS`` in ``django-oauth-toolkit``. Create a new file in
our project, eg ``my_project/oauth_validators.py``::

    from oauth2_provider.oauth2_validators import OAuth2Validator


    class CustomOAuth2Validator(OAuth2Validator):
        pass


and then configure our site to use this in our ``settings.py``::

    OAUTH2_PROVIDER = {
        "OAUTH2_VALIDATOR_CLASS": "my_project.oauth_validators.CustomOAuth2Validator",
        # ... other settings
    }

Now we can customize the tokens and the responses that are produced by adding
methods to our custom validator.


Adding claims to the ID token
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By default the ID token will just have a ``sub`` claim (in addition to the
required claims, eg ``iss``, ``aud``, ``exp``, ``iat``, ``auth_time`` etc),
and the ``sub`` claim will use the primary key of the user as the value.
You'll probably want to customize this and add additional claims or change
what is sent for the ``sub`` claim. To do so, you will need to add a method to
our custom validator. It takes one of two forms:

The first form gets passed a request object, and should return a dictionary
mapping a claim name to claim data::

    class CustomOAuth2Validator(OAuth2Validator):
        # Set `oidc_claim_scope = None` to ignore scopes that limit which claims to return,
        # otherwise the OIDC standard scopes are used.

        def get_additional_claims(self, request):
            return {
                "given_name": request.user.first_name,
                "family_name": request.user.last_name,
                "name": ' '.join([request.user.first_name, request.user.last_name]),
                "preferred_username": request.user.username,
                "email": request.user.email,
            }


The second form gets no request object, and should return a dictionary
mapping a claim name to a callable, accepting a request and producing
the claim data::
    class CustomOAuth2Validator(OAuth2Validator):
        # Extend the standard scopes to add a new "permissions" scope
        # which returns a "permissions" claim:
        oidc_claim_scope = OAuth2Validator.oidc_claim_scope
        oidc_claim_scope.update({"permissions": "permissions"})

        def get_additional_claims(self):
            return {
                "given_name": lambda request: request.user.first_name,
                "family_name": lambda request: request.user.last_name,
                "name": lambda request: ' '.join([request.user.first_name, request.user.last_name]),
                "preferred_username": lambda request: request.user.username,
                "email": lambda request: request.user.email,
                "permissions": lambda request: list(request.user.get_group_permissions()),
            }


Standard claim ``sub`` is included by default, to remove it override ``get_claim_dict``.

Supported claims discovery
--------------------------

In order to help clients discover claims early, they can be advertised in the discovery
info, under the ``claims_supported`` key. In order for the discovery info view to automatically
add all claims your validator returns, you need to use the second form (producing callables),
because the discovery info views are requested with an unauthenticated request, so directly
producing claim data would fail. If you use the first form, producing claim data directly,
your claims will not be added to discovery info.

In some cases, it might be desirable to not list all claims in discovery info. To customize
which claims are advertised, you can override the ``get_discovery_claims`` method to return
a list of claim names to advertise. If your ``get_additional_claims`` uses the first form
and you still want to advertise claims, you can also override ``get_discovery_claims``.

Using OIDC scopes to determine which claims are returned
--------------------------------------------------------

The ``oidc_claim_scope`` OAuth2Validator class attribute implements OIDC's
`5.4 Requesting Claims using Scope Values`_ feature.
For example, a ``given_name`` claim is only returned if the ``profile`` scope was granted.

To change the list of claims and which scopes result in their being returned,
override ``oidc_claim_scope`` with a dict keyed by claim with a value of scope.
The following example adds instructions to return the ``foo`` claim when the ``bar`` scope is granted::
    class CustomOAuth2Validator(OAuth2Validator):
        oidc_claim_scope = OAuth2Validator.oidc_claim_scope
        oidc_claim_scope.update({"foo": "bar"})

Set ``oidc_claim_scope = None`` to return all claims irrespective of the granted scopes.

You have to make sure you've added additional claims via ``get_additional_claims``
and defined the ``OAUTH2_PROVIDER["SCOPES"]`` in your settings in order for this functionality to work.

.. note::
    This ``request`` object is not a ``django.http.Request`` object, but an
    ``oauthlib.common.Request`` object. This has a number of attributes that
    you can use to decide what claims to put in to the ID token:

    * ``request.scopes`` - the list of granted scopes.
    * ``request.claims`` - the requested claims per OIDC's `5.5 Requesting Claims using the "claims" Request Parameter`_.
      These must be requested by the client when making an authorization request.
    * ``request.user`` - the `Django User`_ object.

.. _5.4 Requesting Claims using Scope Values: https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
.. _5.5 Requesting Claims using the "claims" Request Parameter: https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
.. _Django User: https://docs.djangoproject.com/en/stable/ref/contrib/auth/#user-model

What claims you decide to put in to the token is up to you to determine based
upon what the scopes and / or claims means to your provider.


Adding information to the ``UserInfo`` service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``UserInfo`` service is supplied as part of the OIDC service, and is used
to retrieve information about the user given their Access Token.
It is optional to use the service. The service is accessed by making a request to the
``UserInfo`` endpoint, eg ``/o/userinfo/`` and supplying the access token
retrieved at login as a ``Bearer`` token or as a form-encoded ``access_token`` body parameter
for a POST request.

Again, to modify the content delivered, we need to add a function to our
custom validator. The default implementation adds the claims from the ID
token, so you will probably want to reuse that::

    class CustomOAuth2Validator(OAuth2Validator):

        def get_userinfo_claims(self, request):
            claims = super().get_userinfo_claims(request)
            claims["color_scheme"] = get_color_scheme(request.user)
            return claims

Customizing the login flow
==========================

Clients can request that the user logs in each time a request to the
``/authorize`` endpoint is made during the OIDC Authorization Code Flow by
adding the ``prompt=login`` query parameter and value. Only ``login`` is
currently supported. See
OIDC's `3.1.2.1 Authentication Request <https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest>`_
for details.

OIDC Views
==========

Enabling OIDC support adds three views to ``django-oauth-toolkit``. When OIDC
is not enabled, these views will log that OIDC support is not enabled, and
return a ``404`` response, or if ``DEBUG`` is enabled, raise an
``ImproperlyConfigured`` exception.

In the docs below, it assumes that you have mounted the
``django-oauth-toolkit`` at ``/o/``. If you have mounted it elsewhere, adjust
the URLs accordingly.


Define where to store the profile
=================================

.. py:function:: OAuth2Validator.get_or_create_user_from_content(content)

An optional layer to define where to store the profile in ``UserModel`` or a separate model. For example ``UserOAuth``, where ``user = models.OneToOneField(UserModel)``.

The function is called after checking that the username is present in the content.

:return: An instance of the ``UserModel`` representing the user fetched or created.

ConnectDiscoveryInfoView
~~~~~~~~~~~~~~~~~~~~~~~~

Available at ``/o/.well-known/openid-configuration``, this view provides auto
discovery information to OIDC clients, telling them the JWT issuer to use, the
location of the JWKs to verify JWTs with, the token and userinfo endpoints to
query, and other details.


JwksInfoView
~~~~~~~~~~~~

Available at ``/o/.well-known/jwks.json``, this view provides details of the keys used to sign
the JWTs generated for ID tokens, so that clients are able to verify them.


UserInfoView
~~~~~~~~~~~~

Available at ``/o/userinfo/``, this view provides extra user details. You can
customize the details included in the response as described above.


RPInitiatedLogoutView
~~~~~~~~~~~~~~~~~~~~~

Available at ``/o/logout/``, this view allows a :term:`Client` (Relying Party) to request that a :term:`Resource Owner`
is logged out at the :term:`Authorization Server` (OpenID Provider).
