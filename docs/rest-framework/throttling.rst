Throttling
==========

Django OAuth Toolkit provides throttle classes that key rate limits on the OAuth2
credentials a request was made with, for use with `Django REST Framework's throttling
<https://www.django-rest-framework.org/api-guide/throttling/>`_.

They exist because a token issued through the ``client_credentials`` grant has no user
attached to it -- there is no resource owner in that flow, only a client acting on its
own behalf. DRF's ``UserRateThrottle`` therefore falls through to keying such requests
by IP address, which puts every machine-to-machine client behind a shared egress
address into a single bucket, and ``AnonRateThrottle`` treats them as anonymous
traffic. The classes below key on the client application instead, so each client gets
the bucket it deserves.

Buckets are keyed on primary keys, never on the token itself, so a client cannot buy
itself a fresh allowance by asking for a fresh token.

OAuth2ClientRateThrottle
------------------------
Limits the rate of API calls made by a given OAuth2 client application, whether or not
the token carries a user.

Requests that were not authenticated with an OAuth2 access token are not throttled by
this class at all, so it can be combined with whatever throttles cover the rest of a
view's traffic:

.. code-block:: python

    from rest_framework.throttling import UserRateThrottle
    from oauth2_provider.contrib.rest_framework import (
        OAuth2Authentication,
        OAuth2ClientRateThrottle,
        TokenHasScope,
    )

    class SongView(views.APIView):
        authentication_classes = [OAuth2Authentication]
        permission_classes = [TokenHasScope]
        throttle_classes = [OAuth2ClientRateThrottle, UserRateThrottle]
        required_scopes = ["music"]

Its rate is configured under the ``oauth2_client`` scope:

.. code-block:: python

    REST_FRAMEWORK = {
        "DEFAULT_THROTTLE_RATES": {
            "oauth2_client": "10000/day",
        }
    }

OAuth2UserOrClientRateThrottle
------------------------------
Limits the rate of API calls made by a given user, or -- for ``client_credentials``
tokens, which have no user -- by the client application the token was issued to. This
is the drop-in replacement for ``UserRateThrottle`` on an API that serves both kinds of
client:

.. code-block:: python

    REST_FRAMEWORK = {
        "DEFAULT_THROTTLE_CLASSES": [
            "oauth2_provider.contrib.rest_framework.OAuth2UserOrClientRateThrottle",
        ],
        "DEFAULT_THROTTLE_RATES": {
            "oauth2": "1000/day",
        },
    }

Requests that were not authenticated with an OAuth2 access token keep
``UserRateThrottle``'s behavior: they are keyed by user when one is authenticated, and
by IP address otherwise.

Per-application rates
---------------------
Both classes take their rate from the DRF settings, which makes it the same for every
client. To vary it -- a partner with a negotiated quota, say -- override ``get_rate``
or ``allow_request`` on a subclass. Because ``SimpleRateThrottle`` parses its rate in
``__init__``, before there is a request to inspect, a per-request rate has to be
re-parsed in ``allow_request``, the way DRF's own ``ScopedRateThrottle`` does:

.. code-block:: python

    class PerApplicationRateThrottle(OAuth2ClientRateThrottle):
        def allow_request(self, request, view):
            application = getattr(request.auth, "application", None)
            # `rate_limit` here is a field on a custom application model.
            rate = getattr(application, "rate_limit", None) or self.get_rate()
            self.rate = rate
            self.num_requests, self.duration = self.parse_rate(rate)
            return super().allow_request(request, view)

Note that throttle state lives in Django's cache, so a cache shared by every process
serving the API is what makes the limit a limit.
