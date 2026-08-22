from rest_framework.request import Request
from rest_framework.throttling import SimpleRateThrottle
from rest_framework.views import APIView

from ...core.throttling import USER_IDENT_PREFIX, get_client_ident, get_user_or_client_ident


class OAuth2ClientRateThrottle(SimpleRateThrottle):
    """
    Limit the rate of API calls made by a given OAuth2 client application.

    The primary key of the application the access token was issued to is used as the
    cache key, so every client gets its own bucket regardless of whether the token
    carries a user. Requests that were not authenticated with an OAuth2 access token
    are not throttled by this class at all, which lets it be combined with the throttles
    that cover the rest of a view's traffic.

    Configure its rate under the ``oauth2_client`` key of DRF's
    ``DEFAULT_THROTTLE_RATES`` setting, or set ``rate`` on a subclass.
    """

    scope = "oauth2_client"

    def get_cache_key(self, request: Request, view: APIView) -> str | None:
        ident = get_client_ident(getattr(request, "auth", None))
        if ident is None:
            return None
        return self.cache_format % {"scope": self.scope, "ident": ident}


class OAuth2UserOrClientRateThrottle(SimpleRateThrottle):
    """
    Limit the rate of API calls made by a given user, or -- for ``client_credentials``
    tokens, which have no user -- by the client application the token was issued to.

    This is the drop-in replacement for DRF's ``UserRateThrottle`` on an API that serves
    machine-to-machine clients: ``UserRateThrottle`` keys those requests by IP address,
    which lumps every client behind a shared egress address into one bucket. Requests
    that were not authenticated with an OAuth2 access token keep ``UserRateThrottle``'s
    behavior: keyed by user when one is authenticated, by IP address otherwise.

    Configure its rate under the ``oauth2`` key of DRF's ``DEFAULT_THROTTLE_RATES``
    setting, or set ``rate`` on a subclass.
    """

    scope = "oauth2"

    def get_cache_key(self, request: Request, view: APIView) -> str:
        ident = get_user_or_client_ident(getattr(request, "auth", None))
        if ident is None:
            user = getattr(request, "user", None)
            if user is not None and user.is_authenticated:
                ident = "{prefix}-{pk}".format(prefix=USER_IDENT_PREFIX, pk=user.pk)
            else:
                ident = self.get_ident(request)
        return self.cache_format % {"scope": self.scope, "ident": ident}
