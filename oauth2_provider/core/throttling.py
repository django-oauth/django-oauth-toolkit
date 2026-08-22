"""
Request identities used to key rate limits on OAuth2-authenticated requests.

Both framework integrations in :mod:`oauth2_provider.contrib` build their throttle
classes on their own framework's throttling machinery, but "who is this request
from?" has a single OAuth2 answer, so it is answered once here.

Tokens issued through the ``client_credentials`` grant have no user -- see
``OAuth2Validator._create_access_token`` -- so the per-user throttles that ship with
those frameworks fall through to keying every machine-to-machine client by IP
address. Keying on the client application the token was issued to instead gives each
client its own bucket, which is what a machine client actually is.

The identities below are derived from primary keys, never from the token itself: a
throttle bucket must survive the client rotating its tokens, and cache keys are not a
place to put credentials.
"""

from ..models import AbstractAccessToken


CLIENT_IDENT_PREFIX = "client"
USER_IDENT_PREFIX = "user"


def get_client_ident(access_token: object) -> str | None:
    """
    Identify the client application ``access_token`` was issued to.

    Returns ``None`` when the request was not authenticated with an OAuth2 access
    token, or when the token is not tied to an application, so that callers can leave
    such requests to whatever throttles handle the rest of their traffic.
    """
    if not isinstance(access_token, AbstractAccessToken):
        return None
    if access_token.application_id is None:
        return None
    return "{prefix}-{pk}".format(prefix=CLIENT_IDENT_PREFIX, pk=access_token.application_id)


def get_user_or_client_ident(access_token: object) -> str | None:
    """
    Identify the resource owner ``access_token`` was issued for, falling back to the
    client application for tokens with no user (``client_credentials``).

    The two are prefixed apart: without that, user #5 and application #5 would share a
    single bucket. Returns ``None`` under the same conditions as :func:`get_client_ident`.
    """
    if not isinstance(access_token, AbstractAccessToken):
        return None
    if access_token.user_id is not None:
        return "{prefix}-{pk}".format(prefix=USER_IDENT_PREFIX, pk=access_token.user_id)
    return get_client_ident(access_token)
