from django.http import HttpRequest
from ninja.throttling import SimpleRateThrottle

from ...core.throttling import USER_IDENT_PREFIX, get_client_ident, get_user_or_client_ident


class OAuth2ClientRateThrottle(SimpleRateThrottle):
    """
    Limit the rate of API calls made by a given OAuth2 client application.

    The primary key of the application the access token was issued to is used as the
    cache key, so every client gets its own bucket regardless of whether the token
    carries a user. Requests that were not authenticated with an OAuth2 access token
    are not throttled by this class at all, which lets it be combined with the throttles
    that cover the rest of an operation's traffic.

    Ninja has no default rate for this throttle's scope, so pass one to the constructor
    (``OAuth2ClientRateThrottle("1000/day")``) or add an ``oauth2_client`` key to the
    ``NINJA_DEFAULT_THROTTLE_RATES`` setting.
    """

    scope = "oauth2_client"

    def get_cache_key(self, request: HttpRequest) -> str | None:
        ident = get_client_ident(getattr(request, "auth", None))
        if ident is None:
            return None
        return self.cache_format % {"scope": self.scope, "ident": ident}


class OAuth2UserOrClientRateThrottle(SimpleRateThrottle):
    """
    Limit the rate of API calls made by a given user, or -- for ``client_credentials``
    tokens, which have no user -- by the client application the token was issued to.

    This is the throttle to reach for instead of Ninja's ``UserRateThrottle``, which
    keys userless tokens by IP address, or its ``AuthRateThrottle``, which keys on
    ``str(request.auth)`` and so gives each *token* its own bucket -- a client that can
    mint a fresh token can mint a fresh allowance with it. Requests that were not
    authenticated with an OAuth2 access token keep ``UserRateThrottle``'s behavior:
    keyed by user when one is authenticated, by IP address otherwise.

    Ninja has no default rate for this throttle's scope, so pass one to the constructor
    (``OAuth2UserOrClientRateThrottle("1000/day")``) or add an ``oauth2`` key to the
    ``NINJA_DEFAULT_THROTTLE_RATES`` setting.
    """

    scope = "oauth2"

    def get_cache_key(self, request: HttpRequest) -> str:
        ident = get_user_or_client_ident(getattr(request, "auth", None))
        if ident is None:
            user = getattr(request, "user", None)
            if user is not None and user.is_authenticated:
                ident = "{prefix}-{pk}".format(prefix=USER_IDENT_PREFIX, pk=user.pk)
            else:
                ident = self.get_ident(request)
        return self.cache_format % {"scope": self.scope, "ident": ident}
