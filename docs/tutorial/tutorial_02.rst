Part 2 - protect your APIs
==========================

Scenario
--------
It's very common for an :term:`Authorization Server` to also be the :term:`Resource Server`, usually exposing an API to
let others access its own resources. Django OAuth Toolkit implements an easy way to protect the views of a Django
application with OAuth2, in this tutorial we will see how to do it.

Make your API
-------------
We start where we left the :doc:`part 1 of the tutorial <tutorial_01>`: you have an authorization server and we want it
to provide an API to access some kind of resources. We don't need an actual resource, so we will simply expose an
endpoint protected with OAuth2: let's do it in a *class based view* fashion!

Django OAuth Toolkit provides a set of generic class based view you can use to add OAuth behaviour to your views. Open
your :file:`views.py` module and import the view:

.. code-block:: python

    from oauth2_provider.views.generic import ProtectedResourceView
    from django.http import HttpResponse

Then create the view which will respond to the API endpoint:

.. code-block:: python

    class ApiEndpoint(ProtectedResourceView):
        def get(self, request, *args, **kwargs):
            return HttpResponse('Hello, OAuth2!')

That's it, our API will expose only one method, responding to ``GET`` requests. Now open your :file:`urls.py` and specify the
URL this view will respond to:

.. code-block:: python

    from django.urls import path, include
    import oauth2_provider.views as oauth2_views
    from django.conf import settings
    from .views import ApiEndpoint

    # OAuth2 provider endpoints
    oauth2_endpoint_views = [
        path('authorize/', oauth2_views.AuthorizationView.as_view(), name="authorize"),
        path('token/', oauth2_views.TokenView.as_view(), name="token"),
        path('revoke-token/', oauth2_views.RevokeTokenView.as_view(), name="revoke-token"),
    ]

    if settings.DEBUG:
        # OAuth2 Application Management endpoints
        oauth2_endpoint_views += [
            path('applications/', oauth2_views.ApplicationList.as_view(), name="list"),
            path('applications/register/', oauth2_views.ApplicationRegistration.as_view(), name="register"),
            path('applications/<pk>/', oauth2_views.ApplicationDetail.as_view(), name="detail"),
            path('applications/<pk>/delete/', oauth2_views.ApplicationDelete.as_view(), name="delete"),
            path('applications/<pk>/update/', oauth2_views.ApplicationUpdate.as_view(), name="update"),
        ]

        # OAuth2 Token Management endpoints
        oauth2_endpoint_views += [
            path('authorized-tokens/', oauth2_views.AuthorizedTokensListView.as_view(), name="authorized-token-list"),
            path('authorized-tokens/<pk>/delete/', oauth2_views.AuthorizedTokenDeleteView.as_view(),
                name="authorized-token-delete"),
        ]

    urlpatterns = [
        # OAuth 2 endpoints:
        # need to pass in a tuple of the endpoints as well as the app's name
        # because the app_name attribute is not set in the included module
        path('o/', include((oauth2_endpoint_views, 'oauth2_provider'), namespace="oauth2_provider")),
        path('api/hello', ApiEndpoint.as_view()),  # an example resource endpoint
    ]

You will probably want to write your own application views to deal with permissions and access control but the ones packaged with the library can get you started when developing the app.

Since we inherit from ``ProtectedResourceView``, we're done and our API is OAuth2 protected - for the sake of the lazy
programmer.

Testing your API
----------------
Time to make requests to your API.

For a quick test, try accessing your app at the url ``/api/hello`` with your browser
and verify that it responds with a ``403`` (in fact no ``HTTP_AUTHORIZATION`` header was provided).
You can test your API with anything that can perform HTTP requests, but for this tutorial you can use the online
`consumer client <http://django-oauth-toolkit.herokuapp.com/consumer/client>`_.
Just fill the form with the URL of the API endpoint (i.e. http://localhost:8000/api/hello if you're on localhost) and
the access token coming from the :doc:`part 1 of the tutorial <tutorial_01>`. Going in the Django admin and get the
token from there is not considered cheating, so it's an option.

Try performing a request and check that your :term:`Resource Server` aka :term:`Authorization Server` correctly responds with
an HTTP 200.

:doc:`Part 3 of the tutorial <tutorial_03>` will show how to use an access token to authenticate
users.
