"""
OpenID Connect client metadata for clients that register from a document.

RFC 7591 Dynamic Client Registration and OAuth Client ID Metadata Documents both
describe a client with the IANA-registered client metadata parameters, which
include the OpenID Connect Dynamic Client Registration 1.0 ones. This module
maps the parameter that selects how the OpenID Provider signs a client's ID
Tokens onto :class:`~oauth2_provider.models.AbstractApplication` so that every
registration path provisions it the same way. See
``rfcs/openid-connect-registration-1_0.txt``.
"""

from collections.abc import Mapping
from typing import Any

from oauth2_provider.models import AbstractApplication, get_application_model
from oauth2_provider.settings import oauth2_settings


#: OpenID Connect Dynamic Client Registration 1.0 section 2: the JWS ``alg``
#: the client wants its ID Tokens signed with. OPTIONAL; the default is RS256.
ID_TOKEN_SIGNED_RESPONSE_ALG = "id_token_signed_response_alg"

# Requested ``alg`` values the provider can sign with for a registered client,
# mapped to ``AbstractApplication.algorithm``. HS256 is deliberately absent: its
# HMAC key is the plaintext client secret, which a registered client either does
# not have (public, every CIMD client) or has stored hashed.
_SUPPORTED_ID_TOKEN_ALGS = {"RS256": AbstractApplication.RS256_ALGORITHM}

# The reverse mapping, for registration responses.
_ID_TOKEN_ALG_BY_ALGORITHM = {
    AbstractApplication.RS256_ALGORITHM: "RS256",
    AbstractApplication.HS256_ALGORITHM: "HS256",
}


class UnsupportedClientMetadataError(ValueError):
    """The registering client asked for metadata this provider cannot honour.

    The message names the metadata parameter so a registration path can
    surface it unchanged (RFC 7591 section 3.2.2 ``invalid_client_metadata``,
    or the CIMD validation log).
    """


def _server_can_sign_rs256() -> bool:
    return bool(oauth2_settings.OIDC_RSA_PRIVATE_KEY)


def id_token_signing_algorithm(metadata: Mapping[str, Any]) -> str:
    """Return the ``AbstractApplication.algorithm`` to provision for *metadata*.

    With no ``id_token_signed_response_alg`` the OpenID Connect Dynamic Client
    Registration 1.0 default of RS256 applies, so the client is provisioned to
    receive RS256-signed ID Tokens whenever the server holds an
    ``OIDC_RSA_PRIVATE_KEY``. Without one the client is stored with no signing
    algorithm: registration still succeeds and plain OAuth 2.0 flows work, it
    just cannot be issued ID Tokens until the server can sign them.

    An explicit value is honoured when the server can sign with it and refused
    otherwise (section 3.1 lets the provider reject requested metadata).
    Refusing beats substituting: a CIMD client never receives a registration
    response that could tell it which value was substituted, and an ID Token
    signed with an algorithm the client did not ask for only fails its
    validation later.

    Raises :class:`UnsupportedClientMetadataError` for a value the server
    cannot honour.
    """
    Application = get_application_model()
    requested = metadata.get(ID_TOKEN_SIGNED_RESPONSE_ALG)
    if requested is None:
        return Application.RS256_ALGORITHM if _server_can_sign_rs256() else Application.NO_ALGORITHM
    if not isinstance(requested, str) or requested not in _SUPPORTED_ID_TOKEN_ALGS:
        raise UnsupportedClientMetadataError(
            f"Unsupported {ID_TOKEN_SIGNED_RESPONSE_ALG}: {requested!r}. "
            f"Supported values: {', '.join(_SUPPORTED_ID_TOKEN_ALGS)}"
        )
    if not _server_can_sign_rs256():
        raise UnsupportedClientMetadataError(
            f"{ID_TOKEN_SIGNED_RESPONSE_ALG} {requested!r} is not available: "
            "this server has no RSA signing key configured"
        )
    return _SUPPORTED_ID_TOKEN_ALGS[requested]


def id_token_signed_response_alg(application: AbstractApplication) -> str | None:
    """Return the ``id_token_signed_response_alg`` value describing *application*.

    The inverse of :func:`id_token_signing_algorithm`, for registration
    responses (OpenID Connect Dynamic Client Registration 1.0 section 3.2: the
    response carries every registered value, including those the provider
    chose itself). None when the application has no signing algorithm, so the
    parameter is omitted rather than reported with a value the spec does not
    define.
    """
    return _ID_TOKEN_ALG_BY_ALGORITHM.get(application.algorithm)
