"""
OpenID Connect Dynamic Client Registration 1.0 client metadata.

Shared by the two ways a client registers itself from a metadata document, RFC
7591 Dynamic Client Registration and Client ID Metadata Documents, so both
provision the same OpenID Provider behaviour from the same metadata fields.
See ``rfcs/openid-connect-registration-1_0.txt``.
"""

import logging

from oauth2_provider.models import AbstractApplication, get_application_model
from oauth2_provider.settings import oauth2_settings


log = logging.getLogger(__name__)

# OIDC Dynamic Client Registration 1.0 section 2 ``id_token_signed_response_alg``
# values the OP honours for a registered client. HS256 is deliberately absent
# even though discovery advertises it: its HMAC key is the plaintext client
# secret, which registration stores hashed for every auth method but
# client_secret_jwt, and a public client has no secret at all.
ID_TOKEN_SIGNED_RESPONSE_ALGS = ("RS256",)


class UnsupportedClientMetadata(ValueError):
    """A registration document asks for something this OP cannot provide.

    The message names the RFC field so callers can surface it verbatim.
    """


def resolve_id_token_signing_algorithm(metadata: dict) -> str:
    """Return the ``Application.algorithm`` to provision for *metadata*.

    Without an ``id_token_signed_response_alg`` the OIDC registration default is
    RS256, so the application is provisioned to sign ID Tokens with the server's
    ``OIDC_RSA_PRIVATE_KEY`` whenever OIDC is enabled and a key is configured
    (the same gate the server metadata applies to ``jwks_uri``); a server that
    cannot sign leaves the application unable to issue ID Tokens rather than
    failing registration outright.

    An explicit value the OP never offers to registered clients is rejected, as
    RFC 7591 section 2 permits, rather than silently replaced: a client that
    asked for an algorithm would otherwise validate tokens against the wrong
    one. The one substitution made is an explicit RS256 on a server that cannot
    sign at the moment: that is what the server would have provisioned anyway,
    so the application is stored with no algorithm (and the Dynamic Client
    Registration response omits the field). Rejecting it instead would freeze a
    Client ID Metadata Document row on its stale document once the key is
    removed, and would refuse a Dynamic Client Registration update that merely
    echoes the configuration the server itself reported.

    Raises :class:`UnsupportedClientMetadata` for a value the server cannot
    honour. A JSON ``null`` is a value, not an omission, and is rejected like
    any other non-string.
    """
    Application = get_application_model()
    server_can_sign = bool(oauth2_settings.OIDC_ENABLED and oauth2_settings.OIDC_RSA_PRIVATE_KEY)
    if "id_token_signed_response_alg" not in metadata:
        return Application.RS256_ALGORITHM if server_can_sign else Application.NO_ALGORITHM
    requested = metadata["id_token_signed_response_alg"]
    if requested not in ID_TOKEN_SIGNED_RESPONSE_ALGS:
        raise UnsupportedClientMetadata(
            f"Unsupported id_token_signed_response_alg: {requested!r}. "
            f"Supported values for registered clients: {', '.join(ID_TOKEN_SIGNED_RESPONSE_ALGS)}"
        )
    if not server_can_sign:
        log.info(
            "Client metadata requests id_token_signed_response_alg %r but the server cannot sign "
            "ID Tokens (OIDC_ENABLED and OIDC_RSA_PRIVATE_KEY); provisioning no signing algorithm",
            requested,
        )
        return Application.NO_ALGORITHM
    return Application.RS256_ALGORITHM


def id_token_signed_response_alg(application: AbstractApplication) -> str | None:
    """The ``id_token_signed_response_alg`` to report for *application*, or None."""
    Application = get_application_model()
    if application.algorithm == Application.RS256_ALGORITHM:
        return "RS256"
    if application.algorithm == Application.HS256_ALGORITHM:
        return "HS256"
    return None
