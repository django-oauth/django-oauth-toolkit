"""
A back-channel logout handler for local development.

The stock handler,
:func:`~oauth2_provider.authorization_server.oidc.handlers.send_backchannel_logout_request`,
refuses to deliver to an address that is not public, so it can never reach the demo RP or
the e2e suite's receiver on this machine's loopback interface, or an RP on a private
network such as Docker Compose's. This one mints the same Logout Token and drops only that
check: delivery still goes to the address that was resolved, with no redirects and under
the same ``OIDC_BACKCHANNEL_LOGOUT_TIMEOUT`` deadline.

Enabled through ``OAUTH2_PROVIDER_OIDC_BACKCHANNEL_LOGOUT_HANDLER``; never use it outside
a local test IdP.
"""

from typing import Any

from oauth2_provider.authorization_server.oidc.handlers import build_logout_token, post_logout_token
from oauth2_provider.models import AbstractIDToken


def send_loopback_backchannel_logout_request(id_token: AbstractIDToken, **kwargs: Any) -> None:
    post_logout_token(
        id_token.application.backchannel_logout_uri,
        build_logout_token(id_token),
        require_public_address=False,
    )
