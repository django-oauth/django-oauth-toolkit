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
change this class to derive from
``oauth2_provider.authorization_server.oidc.server.Server`` (a subclass of
``oauthlib.openid.Server``) instead of ``oauthlib.oauth2.Server``. Deriving from
``oauthlib.openid.Server`` directly also works, but the UserInfo response is then
never signed (see :ref:`signed-userinfo`).

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

``HS256`` is set by an administrator. Because the client secret is the HMAC
key, it must be at least 32 octets long, as `OpenID Connect Core 1.0 section
16.19 <https://openid.net/specs/openid-connect-core-1_0.html#SymmetricKeyEntropy>`_
requires; the default ``CLIENT_SECRET_GENERATOR_LENGTH`` of 128 satisfies it.
Clients that register themselves, through :doc:`Dynamic Client Registration
<views/dynamic_client_registration>` or a :doc:`Client ID Metadata Document
<cimd>`, cannot request ``HS256``: they are given ``RS256`` when the server has
an ``OIDC_RSA_PRIVATE_KEY``, and no signing algorithm otherwise, so a server
that should issue them ID Tokens needs an RSA key. An administrator can still
set ``HS256`` on a dynamically registered client; the Dynamic Client
Registration page describes when an update keeps it.


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

Logout requests are idempotent, as the specification requires. An ``id_token_hint`` that verifies but
whose ID Token is no longer stored is therefore not treated as an error: this is the case once another
RP has already logged the same End-User out, since that deletes their ID Tokens, and equally for an ID
Token that was deliberately revoked or that this OP never issued. The End-User is
prompted if they still have a session with the OP, just as they are for a request carrying no
``id_token_hint`` at all. The requesting RP is still identified, from the ID Token's ``aud`` claim, so
a ``post_logout_redirect_uri`` is still validated against it. An ``id_token_hint`` that cannot be
verified is still rejected, and a ``client_id`` given alongside it is still required to match the RP
the ID Token was issued for.

``Application.clean()`` validates an application's ``post_logout_redirect_uris`` like its
``redirect_uris``: by ``REDIRECT_URI_VALIDATOR`` (by default, against ``ALLOWED_REDIRECT_URI_SCHEMES``)
and, with ``OIDC_RP_INITIATED_LOGOUT_STRICT_REDIRECT_URIS`` on, by refusing an ``http`` URI for a
client that is not confidential, since logout would never redirect to it. The admin, the application
management views, ``createapplication`` and Dynamic Client Registration all run it, so an existing
application whose post-logout redirect URIs break either rule is refused there until they are
corrected. Like any Django model validation, it is not run by ``Model.save()`` or ``loaddata``.
Clients registered through :doc:`Dynamic Client Registration <views/dynamic_client_registration>`
send them as the ``post_logout_redirect_uris`` metadata.


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

For both the Implicit and Hybrid flows, authorization responses, errors
included, are returned in the fragment of the redirect URI, as `OAuth 2.0
Multiple Response Type Encoding Practices
<https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations>`_
requires for any ``response_type`` containing ``token`` or ``id_token``.

The values of a multi-valued ``response_type`` may be sent in any order
(:rfc:`6749#section-3.1.1`): ``id_token code`` is served exactly like
``code id_token``, and ``token id_token`` like ``id_token token``. A value that
names the same response type twice is refused.

The supported values of ``response_mode`` are ``query`` and ``fragment``, and
``query`` is not permitted for response types containing ``token`` or
``id_token``. A request with any other value, ``form_post`` included, is refused
with an HTTP 400 and no redirect, as `OpenID Connect Core 1.0 §3.1.2.6
<https://openid.net/specs/openid-connect-core-1_0.html#AuthError>`_ requires,
because the error cannot be returned in a mode the server does not support.

.. _oidc-authorization-request-post:

Authorization requests sent by POST
-----------------------------------

As `OpenID Connect Core 1.0 §3.1.2.1
<https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest>`_ requires,
the authorization endpoint accepts the authorization request by HTTP ``POST`` as
well as ``GET``, with the parameters form-serialized
(``application/x-www-form-urlencoded``) in the request body. It answers with a
``303 See Other`` redirect to the same request sent by ``GET``: the body's
parameters are added to the query string, so every later step (logging in,
``prompt``, ``resource``, pushed authorization requests, :ref:`request objects
<oidc-request-objects>` and the consent form) sees the request exactly as if it had
been sent by ``GET``. A parameter sent in both the query string and the body counts as
repeated, as it would in a ``GET``.

The redirect also matters for the session: a ``POST`` from the client's site does
not carry a session cookie set with ``SameSite=Lax`` (Django's default), but the
browser sends it with the ``GET``, so a user who is logged in is not asked to log
in again. Because the request ends up in a URL, it is subject to the same length
limits as a ``GET`` (in the web server and the browser), so a very large request,
such as one with a long ``claims`` parameter, may need a pushed authorization
request instead.

The consent form posts to the same endpoint. A ``POST`` that carries the form's
``allow`` field or a CSRF token, in the ``csrfmiddlewaretoken`` field or the CSRF
header, is taken to be a consent submission and is CSRF-protected; any other
``POST`` is an authorization request, which carries no CSRF token since it comes
from the client's site. The view enforces this itself, so consent submissions are
CSRF-protected even where ``CsrfViewMiddleware`` is not installed, and the
exemption is applied in ``AuthorizationView.as_view()``, so a subclass that
overrides ``dispatch`` keeps it. A custom ``authorize.html`` template must
therefore keep ``{% csrf_token %}`` in its form, as Django requires anyway. If a
custom consent form submits neither the ``allow`` field nor a CSRF token, override
``AuthorizationView.is_consent_submission``.

.. _oidc-request-objects:

Request objects
---------------

Request objects (`OpenID Connect Core 1.0 section 6
<https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests>`_) carry the authorization
request parameters in a JWT, passed by value in the ``request`` parameter or by reference in a
``request_uri`` the server fetches. They are off by default; enable them with
``OIDC_REQUEST_OBJECTS_ENABLED`` (``OIDC_ENABLED`` must be on too):

.. code-block:: python

    OAUTH2_PROVIDER = {
        "OIDC_ENABLED": True,
        "OIDC_REQUEST_OBJECTS_ENABLED": True,
        # ...
    }

**Assembling the request.** The parameters inside the request object are combined with those sent
the usual way, and when both carry a parameter the request object's value is used (section 6.3.3).
``client_id``, ``response_type`` and a ``scope`` including ``openid`` must be sent the usual way
even when the request object carries them (sections 6.1 and 6.2), or the request is answered with
``invalid_request``; the request object's ``client_id`` and ``response_type``, if present, must
match the ones sent the usual way. A parameter sent more than once the usual way is refused even
when the request object carries it (only ``resource`` may repeat). A request object must not
contain ``request`` or ``request_uri``, and ``request`` and ``request_uri`` cannot be used together.

**Keeping the request off the URL.** Once the request object is valid, the assembled request is
validated as the authorization endpoint validates any request, and an invalid one is reported at
once, before the user is asked to log in (sections 3.1.2.2 and 3.1.2.3). A valid one is kept on the
server, in the same store as :doc:`pushed authorization requests <pushed_authorization_requests>`,
and the authorization endpoint redirects the user agent back to itself with only ``client_id`` and
a single-use ``request_uri`` in the ``urn:ietf:params:oauth:request_uri:`` namespace, bound to the
client. The rest of the flow (logging in, ``prompt``, ``max_age`` and the consent form) resolves
that reference, so a ``redirect_uri``, ``state`` or ``nonce`` sent only inside the request object is
honoured, and the request object's parameters never appear in the browser URL, its history, server
logs or ``Referer`` headers, cannot be edited there, and are not limited by URL length. The request
object is resolved, and a ``request_uri`` fetched, exactly once, before the user is asked to log in.
Every valid request object therefore stores a row (see :ref:`stored-authorization-requests`); one
that is never redeemed is removed once it expires by the ``cleartokens`` management command, so
run it regularly when request objects are enabled.

For a user who is not logged in, the stored request is only a reference until they log in, so its
``prompt`` is acted on when the request object is resolved: ``none`` is answered with
``login_required`` at once, and ``create`` sends the user to register (see
``OIDC_RP_INITIATED_REGISTRATION_ENABLED``), returning to the stored request. Logging in, or
registering, has to finish within ``OIDC_REQUEST_OBJECT_STORE_LIFETIME_SECONDS`` (60 seconds by
default); after that the stored request has expired and the client has to start again.

**Signing.** A request object may be unsigned (``alg`` ``none``) or signed with an algorithm in
``OIDC_REQUEST_OBJECT_SIGNING_ALGS`` (by default RS, PS and ES with SHA-256, -384 and -512). A signed
request object is verified against the client's registered public keys, ``client_jwks`` or
``client_jwks_uri``, which also verify :doc:`private_key_jwt <rfc7523>` client assertions and are
fetched and cached the same way. If a signed request object carries ``iss``, it must be the client's
``client_id``; if it carries ``aud``, that must be or include this server's issuer, exactly as
published in discovery (no trailing-slash or case normalization, RFC 7519 section 2). ``exp`` and ``nbf``
are checked when present. A client that registers ``request_object_signing_alg`` must sign every
request object with exactly that algorithm, so a client registering an asymmetric algorithm cannot
have unsigned request objects accepted on its behalf. Remove ``"none"`` from
``OIDC_REQUEST_OBJECT_SIGNING_ALGS`` to require signed request objects from every client. Encrypted
request objects are not supported.

**Fetching** ``request_uri``. A ``request_uri`` is fetched with the fetcher configured as
``OIDC_REQUEST_URI_FETCHER``. The default fetcher only fetches ``https`` URLs and only from public
addresses, pins the connection to the address it checked, does not follow redirects, and is
bounded by ``OIDC_REQUEST_URI_FETCH_TIMEOUT_SECONDS`` and ``OIDC_REQUEST_URI_MAX_SIZE``. Fetched
documents are not cached. At most ``OIDC_REQUEST_URI_MAX_CONCURRENT_FETCHES`` fetches run at once,
and a ``request_uri`` that could not be fetched is not fetched again for
``OIDC_REQUEST_URI_FAILURE_BACKOFF_SECONDS``. A client may register ``request_uris``; when it has registered any, a
``request_uri`` must match one of them, ignoring the fragment, and is refused without being
fetched otherwise. Clients that registered none may use any ``https`` URL, so
``require_request_uri_registration`` is published as ``false``. Because the request is resolved
before the user logs in, anyone who knows a client's ``client_id`` can make the server fetch a URL;
registering ``request_uris`` limits that client to known URLs.

**Errors.** An invalid request object passed in ``request`` is answered with
``invalid_request_object``; a ``request_uri`` that is not registered, cannot be fetched or refers to
an invalid request object with ``invalid_request_uri`` (section 3.1.2.6); and a ``request`` sent with
a ``request_uri`` with ``invalid_request``. As for other authorization errors, the error is only
redirected to a redirect URI the client registered and sent the usual way, or to the client's only
registered redirect URI when none was sent, with the ``state`` sent the usual way; values inside the
rejected request object are never used. Otherwise the error is
shown to the user.

**Discovery.** With request objects enabled, both discovery documents publish
``request_parameter_supported`` and ``request_uri_parameter_supported`` as ``true``,
``request_object_signing_alg_values_supported`` and ``require_request_uri_registration``. Clients
register ``request_uris`` and ``request_object_signing_alg`` through :doc:`dynamic client
registration <views/dynamic_client_registration>`, :doc:`CIMD <cimd>`, or the admin.

**Disabled.** With ``OIDC_REQUEST_OBJECTS_ENABLED`` off, once the client and redirect URI have been
validated, the authorization endpoint redirects a request carrying ``request`` or a ``request_uri``
back to the client with the section 3.1.2.6 error ``request_not_supported`` or
``request_uri_not_supported``. If the client or redirect URI is invalid, the error is shown to the
user instead. The request is checked before the user is asked to log in, so a client gets this
error even when the user is not logged in, including for a ``prompt=none`` request. Parameters
inside a request object are never read, so a ``state`` sent only inside it is not echoed. Both
discovery documents publish ``request_parameter_supported`` and ``request_uri_parameter_supported``
as ``false``.

Either way, a ``request_uri`` issued by the :doc:`pushed authorization request
<pushed_authorization_requests>` endpoint (``urn:ietf:params:oauth:request_uri:...``) is resolved as
a pushed request, never fetched: PAR is advertised separately through
``pushed_authorization_request_endpoint``.


Customizing the OIDC responses
==============================

This basic configuration will give you a basic working OIDC setup, but your
ID tokens will have very few claims in them, and the ``UserInfo`` service will
just return the same claims as the ID token (see
:ref:`scope-claims-id-token-or-userinfo` for how ``OIDC_COMPLIANT_SCOPE_CLAIMS``
changes that).

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
the claim data:

.. code-block:: python

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
The following example adds instructions to return the ``foo`` claim when the ``bar`` scope is granted:

.. code-block:: python

    class CustomOAuth2Validator(OAuth2Validator):
        oidc_claim_scope = OAuth2Validator.oidc_claim_scope
        oidc_claim_scope.update({"foo": "bar"})

Set ``oidc_claim_scope = None`` to return all claims irrespective of the granted scopes.

You have to make sure you've added additional claims via ``get_additional_claims``
and defined the ``OAUTH2_PROVIDER["SCOPES"]`` in your settings in order for this functionality to work.

.. _scope-claims-id-token-or-userinfo:

ID Token or ``UserInfo``
^^^^^^^^^^^^^^^^^^^^^^^^

Section 5.4 also says *where* the claims requested by the ``profile``, ``email``,
``address`` and ``phone`` scope values are returned: from the ``UserInfo`` endpoint
when the response type issues an access token, and in the ID Token only when no
access token is issued (``response_type=id_token``).

By default the toolkit returns those claims in both the ID Token and the
``UserInfo`` response. Set ``OIDC_COMPLIANT_SCOPE_CLAIMS`` to ``True`` to follow
section 5.4: they are then left out of every ID Token except the one issued for
``response_type=id_token`` (including ID Tokens from the token endpoint and from
refresh), and relying parties read them from ``UserInfo``. ``sub`` and claims gated
by your own scopes stay in the ID Token. To treat another scope value the same way,
extend the ``oidc_userinfo_only_scopes`` class attribute:

.. code-block:: python

    class CustomOAuth2Validator(OAuth2Validator):
        oidc_userinfo_only_scopes = OAuth2Validator.oidc_userinfo_only_scopes + ("permissions",)

The ``claims`` request parameter (`5.5 Requesting Claims using the "claims" Request Parameter`_),
which lets a client ask for individual claims in the ID Token, is not yet honoured.

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
custom validator. The default implementation returns the claims from
``get_additional_claims`` that the access token's scopes allow, so you will
probably want to reuse that::

    class CustomOAuth2Validator(OAuth2Validator):

        def get_userinfo_claims(self, request):
            claims = super().get_userinfo_claims(request)
            claims["color_scheme"] = get_color_scheme(request.user)
            return claims

``get_userinfo_claims`` always returns the claims as a ``dict``. Whether they are
sent as JSON or as a signed JWT is decided afterwards by
``finalize_userinfo_response(claims, request)``, which you can also override, for
instance to add claims to the signed JWT only (see :ref:`signed-userinfo`).


Adding more information to the request object passed to the authentication backends
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By default, ``build_http_request`` creates a new Django ``HttpRequest`` for the
``authenticate()`` call that only carries a subset of the incoming request's
attributes (path, method, body and headers).

If your authentication backends need more, override ``build_http_request`` to
copy the extra attributes onto the Django ``HttpRequest`` it returns.

Note that the ``request`` argument is the oauthlib ``Request``, **not** the
original Django ``HttpRequest``. Attributes attached to the Django request by
middleware (for example a ``tenant_id`` set by a multi-tenant middleware) are
not automatically present on the oauthlib request, so make sure the value you
need has been made available on it -- or forward it there yourself -- and read
it with ``getattr`` and a default to avoid an ``AttributeError`` when it is
missing::

    class CustomOAuth2Validator(OAuth2Validator):

        def build_http_request(self, request):
            # ``request`` is the oauthlib Request; ``tenant_id`` must already
            # have been set on it (e.g. by a custom OAuthLibCore that forwards
            # it from the Django request).
            new_request = super().build_http_request(request)
            new_request.tenant_id = getattr(request, "tenant_id", None)
            return new_request


Customizing the login flow
==========================

Clients can request that the user logs in each time a request to the
``/authorize`` endpoint is made during the OIDC Authorization Code Flow by
adding the ``prompt=login`` query parameter and value. Only ``login`` is
currently supported. See
OIDC's `3.1.2.1 Authentication Request <https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest>`_
for details.

Clients can also require that the user logged in recently by sending the
``max_age`` parameter, the number of seconds allowed since the user last
logged in. If the login that authenticated the user's current browser session
is older than that, the user is sent to log in again before the request
continues. A ``max_age`` of ``0`` is treated as ``prompt=login``, as the
specification says it is equivalent to. ``max_age`` applies only to OpenID
Connect requests (those with the ``openid`` scope); other requests ignore it.
A request with ``prompt=none`` whose ``max_age`` has passed gets a
``login_required`` error instead of a login page. A value that is not a
non-negative integer, or a ``prompt`` or ``max_age`` given more than once,
gets an ``invalid_request`` error, also from the PAR endpoint.

Each login is recorded in the Django session it authenticated, when Django's
:func:`~django.contrib.auth.login` runs: its time, and an identifier that
tells one login from the next. ``last_login`` is not used, since every session
of the account shares it: logging in on another browser does not make this one
fresh. A session authenticated before this was recorded, or without
:func:`~django.contrib.auth.login`, counts as not having logged in recently.

``prompt=login`` and ``max_age`` stay in the request while the user logs in.
A new login since the authorization endpoint asked for one satisfies them,
even when it no longer fits the value (``0``, or a slow return from the login
page), as long as the user comes back to the same request within five minutes.
Coming back to that request without a new login gets a ``login_required``
error for the client rather than another login page, so the flow cannot loop.
A login made before the authorization endpoint sent the user to log in for
the request does not count either. One login satisfies all the requests
pending at the time (in several tabs, say). Django clears the session when
a different user logs in, so a user who switches accounts at the login page may
be asked to log in once more.

When the request was pushed (PAR), its ``request_uri`` has already been used,
so for ``max_age`` and ``prompt=login`` the request is pushed again for the
same client and the login page returns to the new ``request_uri``. Logging in
has to finish within ``PAR_REQUEST_URI_LIFETIME_SECONDS``, as it already does
when a user who is not logged in follows a pushed request.

These checks are made by the authorization endpoint. The ID Token's
``auth_time`` claim is still taken from the user's ``last_login``, which every
session of the account shares: after the user logs in on another browser, an
ID Token issued to this one (at the code exchange, or on refresh) reports that
other login. Recording the authentication time of each authorization and
carrying it to the ID Token is planned separately.

When users authenticate with an upstream identity provider (SAML, an OpenID
provider, CAS, an SSO proxy), the toolkit sees only the local
:func:`~django.contrib.auth.login`, which may simply restore the upstream
session. Making that login a fresh authentication upstream is up to the
deployment: point the login URL used by ``AuthorizationView`` (Django's
``LOGIN_URL``, or an override of ``get_login_url()``) at an entry point that
asks the provider for one, for example SAML ``ForceAuthn``, or ``prompt=login``
or ``max_age`` for an OpenID provider.

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
query, and other details. When ``DCR_ENABLED`` is on it also advertises the
:doc:`Dynamic Client Registration <views/dynamic_client_registration>` endpoint
as ``registration_endpoint``, like the :doc:`RFC 8414 metadata document
<oauth2_server_metadata>` does. It also lists ``grant_types_supported``, taken from the
:doc:`OAUTH2_GRANT_TYPES_SUPPORTED <settings>` setting, so relying
parties can see that ``refresh_token`` is supported.


JwksInfoView
~~~~~~~~~~~~

Available at ``/o/.well-known/jwks.json``, this view provides details of the keys used to sign
the JWTs generated for ID tokens, so that clients are able to verify them.


UserInfoView
~~~~~~~~~~~~

Available at ``/o/userinfo/``, this view provides extra user details. You can
customize the details included in the response as described above.

Per `OpenID Connect Core 1.0 section 5.3
<https://openid.net/specs/openid-connect-core-1_0.html#UserInfo>`_ the view supports CORS out of
the box, so browser-based (JavaScript) clients can call it cross-origin: it answers the preflight
``OPTIONS`` request and sends ``Access-Control-Allow-Origin: *`` on its responses, including error
responses such as ``401``. Claims are still only released to a caller presenting a valid access
token, and ``Access-Control-Allow-Credentials`` is never sent. Set
``OIDC_USERINFO_CORS_ENABLED`` to ``False`` to turn this off.

.. _signed-userinfo:

Signed UserInfo responses
-------------------------

By default the UserInfo response is a JSON object. A client whose application has
``userinfo_signed_response_alg`` set to ``RS256`` receives it as a signed JWT
instead, with ``Content-Type: application/jwt``, per `OpenID Connect Core 1.0
section 5.3.2 <https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse>`_.
The field is set in the admin or the application views, or registered by the client
itself through :doc:`Dynamic Client Registration <views/dynamic_client_registration>`
or a :doc:`Client ID Metadata Document <cimd>`.

The JWT is signed with the active ``OIDC_RSA_PRIVATE_KEY``, whatever algorithm the
client's ID Tokens use, and its header names the key with the same ``kid`` as the
``jwks_uri`` document. Besides the user's claims it carries ``iss`` (the issuer),
``aud`` (the client's ``client_id``) and ``iat``, plus ``exp`` when
``OIDC_USERINFO_JWT_EXPIRE_SECONDS`` is set. ``exp``, ``nbf`` and ``jti`` among
the user's claims are left out: the OP alone sets the JWT's validity window, and
``jti`` is what tells an ID Token apart from this JWT, which is signed with the
same key. ``RS256`` is the only algorithm offered, and encrypted UserInfo
responses (``userinfo_encrypted_response_alg``) are not supported.

Signing needs OpenID Connect enabled, an ``OIDC_RSA_PRIVATE_KEY``, the default
``OIDC_SERVER_CLASS`` or a class derived from it, and a validator with a
callable ``finalize_userinfo_response``, such as one derived from ``OAuth2Validator``: the
server's UserInfo endpoint passes the claims from ``get_userinfo_claims`` to that
hook, which returns the claims (sent as JSON) or the signed JWT (sent as
``application/jwt``). Only then does discovery advertise
``userinfo_signing_alg_values_supported: ["RS256"]`` and registration accept
``userinfo_signed_response_alg``, so a client is never promised a signed response
it would receive as JSON. Otherwise the admin and application forms refuse
``RS256``, and they always refuse it for an application without OIDC support (no
``algorithm``). When an RSA key is configured but the server or validator class
cannot sign, the ``oauth2_provider.I001`` system check reports that signing is
switched off. While OpenID Connect stays enabled, an application left with
``RS256`` after signing became unavailable receives JSON, and its registration
responses say so. With the default server class, ``finalize_userinfo_response``
also logs a warning for each such response. A server or validator class that
cannot sign never calls it, so nothing is logged per response; the
``oauth2_provider.I001`` system check reports that case once, when an
``OIDC_RSA_PRIVATE_KEY`` is configured.

.. note::
    If your project also installs `django-cors-headers
    <https://github.com/adamchainz/django-cors-headers>`_, its middleware answers every CORS
    preflight itself, before any view runs, so the ``OPTIONS`` handler above never sees the
    request. Configure that middleware to allow the userinfo path as well, or the preflight
    will be answered without CORS headers and the browser will block the request.


RPInitiatedLogoutView
~~~~~~~~~~~~~~~~~~~~~

Available at ``/o/logout/``, this view allows a :term:`Client` (Relying Party) to request that a :term:`Resource Owner`
is logged out at the :term:`Authorization Server` (OpenID Provider).
