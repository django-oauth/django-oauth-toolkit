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

from oauth2_provider.models import AbstractApplication
from oauth2_provider.settings import oauth2_settings


#: OpenID Connect Dynamic Client Registration 1.0 section 2: the JWS ``alg``
#: the client wants its ID Tokens signed with. OPTIONAL; the default is RS256.
ID_TOKEN_SIGNED_RESPONSE_ALG = "id_token_signed_response_alg"

# ``AbstractApplication.algorithm`` stores the JWS ``alg`` name itself, so the
# wire value and the model value are one and the same; this is the subset a
# registered client may ask for. HS256 is deliberately absent: its HMAC key is
# the plaintext client secret, which a registered client either does not have
# (public, every CIMD client) or has stored hashed. Honouring it for the one
# eligible case (confidential ``client_secret_jwt`` clients) is #1871.
SUPPORTED_ID_TOKEN_ALGS = frozenset({AbstractApplication.RS256_ALGORITHM})


class UnsupportedClientMetadataError(ValueError):
    """The registering client asked for metadata this provider cannot honour.

    The message names the metadata parameter so a registration path can
    surface it unchanged (RFC 7591 section 3.2.2 ``invalid_client_metadata``,
    or the CIMD validation log).
    """


def _server_can_sign_rs256() -> bool:
    # The same gate the RFC 8414 metadata view applies before advertising a
    # jwks_uri: a key alone does not make the server an OpenID Provider.
    return bool(oauth2_settings.OIDC_ENABLED and oauth2_settings.OIDC_RSA_PRIVATE_KEY)


def id_token_signing_algorithm(metadata: Mapping[str, Any], *, current: str = "") -> str:
    """Return the ``AbstractApplication.algorithm`` to provision for *metadata*.

    With no ``id_token_signed_response_alg`` (absent or JSON ``null``) the
    OpenID Connect Dynamic Client Registration 1.0 default of RS256 applies, so
    the client is provisioned to receive RS256-signed ID Tokens whenever
    OpenID Connect is enabled and the server holds an ``OIDC_RSA_PRIVATE_KEY``.
    Otherwise the client is stored with no signing algorithm: registration
    still succeeds and plain OAuth 2.0 flows work, it just cannot be issued ID
    Tokens until the server can sign them.

    An explicit value is honoured when the server can sign with it and refused
    otherwise (section 3.1 lets the provider reject requested metadata).
    Refusing beats substituting: a CIMD client never receives a registration
    response that could tell it which value was substituted, and an ID Token
    signed with an algorithm the client did not ask for only fails its
    validation later.

    On an update, *current* is the algorithm the application already has. A
    request that merely echoes a value registration would not grant (an
    administrator's HS256) keeps it and leaves it to model validation: RFC
    7592 section 2.2 has the client send back every field it was given, and a
    management response reports such a value too, so the client could
    otherwise never update without a refusal. An echoed RS256 still needs the
    server to be able to sign with it.

    Raises :class:`UnsupportedClientMetadataError` for a value the server
    cannot honour.
    """
    requested = metadata.get(ID_TOKEN_SIGNED_RESPONSE_ALG)
    if requested is None:
        if _server_can_sign_rs256():
            return AbstractApplication.RS256_ALGORITHM
        return AbstractApplication.NO_ALGORITHM
    if current and requested == current and requested not in SUPPORTED_ID_TOKEN_ALGS:
        return current
    if not isinstance(requested, str) or requested not in SUPPORTED_ID_TOKEN_ALGS:
        raise UnsupportedClientMetadataError(
            f"Unsupported {ID_TOKEN_SIGNED_RESPONSE_ALG}: {requested!r}. "
            f"Supported values: {', '.join(sorted(SUPPORTED_ID_TOKEN_ALGS))}"
        )
    if not _server_can_sign_rs256():
        raise UnsupportedClientMetadataError(
            f"{ID_TOKEN_SIGNED_RESPONSE_ALG} {requested!r} is not available: "
            "this server does not issue RSA-signed ID Tokens"
        )
    return requested


def id_token_signed_response_alg(application: AbstractApplication) -> str | None:
    """Return the ``id_token_signed_response_alg`` value describing *application*.

    The inverse of :func:`id_token_signing_algorithm`, for registration
    responses (OpenID Connect Dynamic Client Registration 1.0 section 3.2: the
    response carries every registered value, including those the provider
    chose itself). None when the application has no signing algorithm, so the
    parameter is omitted rather than reported with a value the spec does not
    define. An algorithm set outside registration (an administrator choosing
    HS256 for a confidential client) is reported as well.
    """
    return application.algorithm or None
