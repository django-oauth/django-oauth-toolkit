Django Ninja
============

Django OAuth Toolkit provides a support layer for
`Django Ninja <https://django-ninja.dev/>`_.

This consists of a ``HttpOAuth2`` class, which will determine whether the
incoming HTTP request contains a valid OAuth2 access token issued
by Django OAuth Toolkit. Optionally, ``HttpOAuth2`` can also ensure that the
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

.. autoclass:: oauth2_provider.contrib.ninja::HttpOAuth2
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
