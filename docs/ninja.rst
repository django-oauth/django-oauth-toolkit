Django Ninja
============

Django OAuth Toolkit provides a support layer for
`Django Ninja <https://django-ninja.dev/>`_.

This consists of a ``HttpOAuth2`` class, which will determine whether the
incoming HTTP request contains a valid OAuth2 access token issued
by Django OAuth Toolkit. Optionally, ``HttpOAuth2`` can ensure that the
OAuth2 Access Token contains a defined set of scopes.

Import ``HttpOAuth2`` as:

.. code-block:: python

    from oauth2_provider.contrib.ninja import HttpOAuth2


Basic Usage
-----------
``HttpOAuth2`` can be used anywhere that
`Django Ninja expects an authentication callable <https://django-ninja.dev/guides/authentication/>`_.

For example, to ensure all requests are authenticated with OAuth2:

.. code-block:: python

    from ninja import NinjaAPI
    from oauth2_provider.contrib.ninja import HttpOAuth2

    api = NinjaAPI(auth=HttpOAuth2())


To require authentication on only a single endpoint:

.. code-block:: python

    from ninja import NinjaAPI
    from oauth2_provider.contrib.ninja import HttpOAuth2

    api = NinjaAPI()

    @api.get("/private", auth=HttpOAuth2())
    def private_endpoint(request):
        return {"message": "This is a private endpoint"}


Optional Authentication
-----------------------
``HttpOAuth2`` will always fail if the request is not authenticated.
However, many use cases require optional authentication (for example, where
additional private content is returned for authenticated users).

Django Ninja's support for
`multiple authenticators <https://django-ninja.dev/guides/authentication/#multiple-authenticators>`_
can be used for optional authentication. Simply place ``HttpOAuth2`` at the
beginning of a list of authenticators (where it will be run first), with more
permissive authenticator functions near the end (as a fall-back).

For example, to attempt OAuth2 authentication on all requests,
but allow access even for unauthenticated requests:

.. code-block:: python

    from ninja import NinjaAPI
    from oauth2_provider.contrib.ninja import HttpOAuth2

    # Stricter authenticators must be placed first,
    # as the first success terminates the chain
    api = NinjaAPI(auth=[HttpOAuth2(), lambda _request: True])


Scope Enforcement
-----------------
``HttpOAuth2`` can optionally enforce that the OAuth2 access token has certain
scopes (defined by the application).

If a ``scopes`` argument is passed to ``HttpOAuth2``, then incoming access
tokens must contain all of the specified scopes to be considered valid.

For example:

.. code-block:: python

    from ninja import NinjaAPI
    from oauth2_provider.contrib.ninja import HttpOAuth2

    api = NinjaAPI()

    @api.post("/thing", auth=HttpOAuth2(scopes=["read", "write"]))
    def create_endpoint(request):
        ...


Custom Authorization Behavior
-----------------------------
``HttpOAuth2`` can be extended to provide custom authorization behaviors.

Simply subclass it and override its ``authenticate`` method.

.. autoclass:: oauth2_provider.contrib.ninja.HttpOAuth2
   :members: authenticate

For example:

.. code-block:: python

    from typing import Any

    from django.http import HttpRequest
    from ninja import NinjaAPI
    from oauth2_provider.contrib.ninja import HttpOAuth2
    from oauth2_provider.models import AbstractAccessToken

    class StaffOnlyOAuth2(HttpOAuth2):
        def authenticate(self, request: HttpRequest, access_token: AbstractAccessToken) -> Any | None:
            if not access_token.user.is_staff:
                return None

            # Anything truthy can be returned, and will be available as `request.auth`
            return access_token

    api = NinjaAPI(auth=StaffOnlyOAuth2())


Throttling
----------
``OAuth2ClientRateThrottle`` and ``OAuth2UserOrClientRateThrottle`` key `Ninja's rate
limiting <https://django-ninja.dev/guides/throttling/>`_ on the OAuth2 credentials a
request was made with.

They exist because a token issued through the ``client_credentials`` grant has no user
attached to it -- there is no resource owner in that flow, only a client acting on its
own behalf. Ninja's ``UserRateThrottle`` therefore falls through to keying such requests
by IP address, which puts every machine-to-machine client behind a shared egress address
into a single bucket, while its ``AuthRateThrottle`` keys on ``str(request.auth)`` and so
gives each *token* its own bucket -- a client that can mint a fresh token can mint a
fresh allowance with it. These classes key on the client application's primary key
instead, which is stable across token rotation:

.. code-block:: python

    from ninja import NinjaAPI
    from oauth2_provider.contrib.ninja import HttpOAuth2, OAuth2ClientRateThrottle

    api = NinjaAPI()

    @api.get("/songs", auth=HttpOAuth2(), throttle=[OAuth2ClientRateThrottle("10000/day")])
    def songs_endpoint(request):
        ...

``OAuth2UserOrClientRateThrottle`` keys on the user when the token has one, and on the
client application otherwise, which is what an API serving both interactive and
machine-to-machine clients usually wants. Requests that were not authenticated with an
OAuth2 access token are left alone by ``OAuth2ClientRateThrottle``, so it can be
combined with the throttles covering the rest of an operation's traffic, and are keyed
by user or IP address by ``OAuth2UserOrClientRateThrottle``.

Ninja has no built-in default rate for either scope, so pass one to the constructor as
above, or add ``oauth2_client`` / ``oauth2`` keys to the ``NINJA_DEFAULT_THROTTLE_RATES``
setting. Throttle state lives in Django's cache, so a cache shared by every process
serving the API is what makes the limit a limit.
