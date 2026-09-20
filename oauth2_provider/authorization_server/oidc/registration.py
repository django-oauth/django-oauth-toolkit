"""
OpenID Connect Dynamic Client Registration 1.0 client metadata.

Shared by the two ways a client registers itself from a metadata document, RFC
7591 Dynamic Client Registration and Client ID Metadata Documents, so both
provision the same OpenID Provider behaviour from the same metadata fields.
"""

from oauth2_provider.models import get_application_model
from oauth2_provider.settings import oauth2_settings


# OIDC Dynamic Client Registration 1.0 section 2 ``id_token_signed_response_alg``
# values the OP can honour for a registered client, mapped to
# ``AbstractApplication.algorithm``. HS256 is deliberately absent: its HMAC key
# is the plaintext client secret, which registration stores hashed at rest.
ID_TOKEN_SIGNED_RESPONSE_ALGS = ("RS256",)


class UnsupportedClientMetadata(ValueError):
    """A registration document asks for something this OP cannot provide.

    The message names the RFC field so callers can surface it verbatim.
    """


def resolve_id_token_signing_algorithm(metadata: dict) -> str:
    """Return the ``Application.algorithm`` to provision for *metadata*.

    Without an explicit ``id_token_signed_response_alg`` the OIDC registration
    default is RS256, so the application is provisioned to sign ID Tokens with
    the server's ``OIDC_RSA_PRIVATE_KEY`` whenever one is configured; a server
    without a key leaves the application unable to issue ID Tokens rather than
    failing registration outright. An explicit value is honoured when the server
    supports it and rejected otherwise: with no registration response to carry a
    substituted value back to the client, silently minting tokens the client did
    not ask for would only make its validation fail later.

    Raises :class:`UnsupportedClientMetadata` for a value the server cannot
    honour.
    """
    Application = get_application_model()
    server_can_sign = bool(oauth2_settings.OIDC_RSA_PRIVATE_KEY)
    requested = metadata.get("id_token_signed_response_alg")
    if requested is None:
        return Application.RS256_ALGORITHM if server_can_sign else Application.NO_ALGORITHM
    if requested not in ID_TOKEN_SIGNED_RESPONSE_ALGS:
        raise UnsupportedClientMetadata(
            f"Unsupported id_token_signed_response_alg: {requested!r}. "
            f"Supported values: {', '.join(ID_TOKEN_SIGNED_RESPONSE_ALGS)}"
        )
    if not server_can_sign:
        raise UnsupportedClientMetadata(
            f"id_token_signed_response_alg {requested!r} is not supported by this server"
        )
    return Application.RS256_ALGORITHM


def id_token_signed_response_alg(application) -> str | None:
    """The ``id_token_signed_response_alg`` to report for *application*, or None."""
    Application = get_application_model()
    if application.algorithm == Application.RS256_ALGORITHM:
        return "RS256"
    if application.algorithm == Application.HS256_ALGORITHM:
        return "HS256"
    return None
