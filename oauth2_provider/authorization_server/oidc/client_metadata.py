"""
OpenID Connect client metadata for clients that register from a document.

RFC 7591 Dynamic Client Registration and OAuth Client ID Metadata Documents both
describe a client with the IANA-registered client metadata parameters, which
include the OpenID Connect Dynamic Client Registration 1.0 ones. This module
maps the parameters that select how the OpenID Provider signs a client's ID
Tokens and UserInfo responses, and the request object parameters, onto
:class:`~oauth2_provider.models.AbstractApplication` so that every registration
path provisions them the same way. See
``rfcs/openid-connect-registration-1_0.txt``.
"""

from collections.abc import Mapping
from typing import Any

from oauth2_provider.authorization_server.oidc.server import signs_userinfo_for, userinfo_signing_available
from oauth2_provider.models import AbstractApplication
from oauth2_provider.settings import oauth2_settings


#: OpenID Connect Dynamic Client Registration 1.0 section 2: the JWS ``alg``
#: the client wants its ID Tokens signed with. OPTIONAL; the default is RS256.
ID_TOKEN_SIGNED_RESPONSE_ALG = "id_token_signed_response_alg"

#: OpenID Connect Dynamic Client Registration 1.0 section 2: the JWS ``alg``
#: the client wants its UserInfo responses signed with. OPTIONAL; by default
#: the response is plain JSON.
USERINFO_SIGNED_RESPONSE_ALG = "userinfo_signed_response_alg"

#: OpenID Connect Dynamic Client Registration 1.0 section 2: the
#: ``request_uri`` values the client may use (OpenID Connect Core 1.0
#: section 6.2), and the JWS ``alg`` all its request objects must be signed with.
REQUEST_URIS = "request_uris"
REQUEST_OBJECT_SIGNING_ALG = "request_object_signing_alg"

# ``AbstractApplication.algorithm`` stores the JWS ``alg`` name itself, so the
# wire value and the model value are one and the same; this is the subset a
# registered client may ask for. HS256 is deliberately absent: its HMAC key is
# the client secret, so it is not offered to self-registered clients, which
# use RS256, the algorithm OpenID Connect Core 1.0 section 15.1 requires of an
# OpenID Provider that signs its ID Tokens. Only a value an administrator set
# is kept when a PUT echoes it (see ``_echoed_algorithm_refusal_reason``).
SUPPORTED_ID_TOKEN_ALGS = frozenset({AbstractApplication.RS256_ALGORITHM})

# ``AbstractApplication.userinfo_signed_response_alg`` also stores the JWS
# ``alg`` name itself. UserInfo is only signed with the server's RSA key, so
# RS256 is the one value offered, to every client alike.
SUPPORTED_USERINFO_ALGS = frozenset({AbstractApplication.RS256_ALGORITHM})

# The grants ``AbstractApplication.clean()`` forbids HS256 with, and that an
# echoed administrator-set algorithm may not be kept with.
_HS256_FORBIDDEN_GRANT_TYPES = (
    AbstractApplication.GRANT_IMPLICIT,
    AbstractApplication.GRANT_OPENID_HYBRID,
)

# OpenID Connect Core 1.0 section 16.19: a client_secret used as an HMAC key
# must contain at least as many octets as the algorithm's MAC key, 32 for HS256.
_HS256_MIN_CLIENT_SECRET_OCTETS = 32


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


def _hs256_refusal_reason(
    client_type: str, token_endpoint_auth_method: str, authorization_grant_type: str, client_secret: str
) -> str | None:
    """Return why the described client cannot keep an echoed HS256, or None.

    HS256 is never granted on request; this decides whether an HS256 an
    administrator set survives an RFC 7592 update that sends it back. It
    mirrors the HS256 rules of ``AbstractApplication.clean()`` so a refusal is
    reported with registration metadata names instead of model field names.
    Only ``client_secret_jwt`` qualifies as an authentication method because it
    is the one registration stores the client secret in plaintext for (it is
    the HMAC key of the client's assertions too); every other method keeps the
    secret hashed at rest, and ``clean()`` refuses HS256 with a hashed secret.
    The plaintext *client_secret* must also be long enough to be an HS256 key
    (OpenID Connect Core 1.0 section 16.19), which ``clean()`` does not check
    but signing does.
    """
    if client_type == AbstractApplication.CLIENT_PUBLIC:
        return "HS256 signs ID Tokens with the client secret, which a public client does not have"
    if token_endpoint_auth_method != AbstractApplication.TOKEN_AUTH_METHOD_CLIENT_SECRET_JWT:
        return (
            "HS256 requires token_endpoint_auth_method 'client_secret_jwt', the only method that "
            "keeps the client secret in plaintext for use as the HMAC key"
        )
    if authorization_grant_type in _HS256_FORBIDDEN_GRANT_TYPES:
        return "HS256 cannot be used with the implicit or hybrid grant"
    if len(client_secret.encode("utf-8")) < _HS256_MIN_CLIENT_SECRET_OCTETS:
        return (
            f"HS256 needs a client secret of at least {_HS256_MIN_CLIENT_SECRET_OCTETS} octets as its "
            "HMAC key (OpenID Connect Core 1.0 section 16.19), and this client's secret is shorter"
        )
    return None


def _echoed_algorithm_refusal_reason(
    algorithm: str,
    client_type: str,
    token_endpoint_auth_method: str,
    authorization_grant_type: str,
    client_secret: str,
) -> str | None:
    """Return why an echoed administrator-set *algorithm* cannot be kept, or None.

    HS256 gets its specific rules from :func:`_hs256_refusal_reason`. Any other
    value outside :data:`SUPPORTED_ID_TOKEN_ALGS` (one a swapped application
    model may define) keeps the rule registration has always applied to an
    echoed value: the client must stay on ``client_secret_jwt`` and off the
    implicit and hybrid grants.
    """
    if algorithm == AbstractApplication.HS256_ALGORITHM:
        return _hs256_refusal_reason(
            client_type, token_endpoint_auth_method, authorization_grant_type, client_secret
        )
    if (
        token_endpoint_auth_method != AbstractApplication.TOKEN_AUTH_METHOD_CLIENT_SECRET_JWT
        or authorization_grant_type in _HS256_FORBIDDEN_GRANT_TYPES
    ):
        return (
            f"an administrator-set {algorithm} is kept only for token_endpoint_auth_method "
            "'client_secret_jwt' with a grant other than implicit or hybrid"
        )
    return None


def id_token_signing_algorithm(
    metadata: Mapping[str, Any],
    *,
    current: str = "",
    client_type: str = AbstractApplication.CLIENT_PUBLIC,
    token_endpoint_auth_method: str = "",
    authorization_grant_type: str = "",
    client_secret: str = "",
) -> str:
    """Return the ``AbstractApplication.algorithm`` to provision for *metadata*.

    The client keyword arguments describe the client being provisioned, as the
    registration path has already derived them; *client_secret* is the secret
    it holds. They only matter for an echoed administrator-set value and
    default to a public client without a secret, the most restrictive case.
    The CIMD path relies on those defaults: it passes neither *current* nor
    the client keyword arguments, since a fetched document never has a
    current value to echo.

    With no ``id_token_signed_response_alg`` (absent or JSON ``null``) the
    OpenID Connect Dynamic Client Registration 1.0 default of RS256 applies, so
    the client is provisioned to receive RS256-signed ID Tokens whenever
    OpenID Connect is enabled and the server holds an ``OIDC_RSA_PRIVATE_KEY``.
    Otherwise the client is stored with no signing algorithm: registration
    still succeeds and plain OAuth 2.0 flows work, it just cannot be issued ID
    Tokens until the server can sign them.

    An explicit value is honoured when the server can sign with it and refused
    otherwise (section 3.1 lets the provider reject requested metadata).
    RS256 needs OpenID Connect enabled and an ``OIDC_RSA_PRIVATE_KEY``. HS256
    is not offered: it would make the client secret the ID Token signing key,
    and RS256 is the algorithm OpenID Connect Core 1.0 section 15.1 requires
    of an OpenID Provider that signs its ID Tokens.
    Refusing beats substituting: a CIMD client never receives a registration
    response that could tell it which value was substituted, and an ID Token
    signed with an algorithm the client did not ask for only fails its
    validation later.

    On an update, *current* is the algorithm the application already has. An
    echoed value registration would not grant (an administrator's choice,
    reported by the management response) is kept even while OpenID Connect is
    disabled, since RFC 7592 section 2.2 has the client send back every field
    it was given and it could otherwise never update without a refusal; the
    client must still be eligible for it (see
    :func:`_echoed_algorithm_refusal_reason`). An echoed RS256 still needs the
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
        refusal = _echoed_algorithm_refusal_reason(
            current, client_type, token_endpoint_auth_method, authorization_grant_type, client_secret
        )
        if refusal is not None:
            raise UnsupportedClientMetadataError(
                f"{ID_TOKEN_SIGNED_RESPONSE_ALG} {requested!r} is not available for this client: {refusal}"
            )
        return current
    if requested == AbstractApplication.HS256_ALGORITHM:
        # Point the client at what this server can actually do: RS256 when it
        # can sign with it, otherwise no signing algorithm at all, since asking
        # for RS256 would only be refused in turn.
        if _server_can_sign_rs256():
            advice = "use RS256 (OpenID Connect Core 1.0 section 15.1)"
        else:
            advice = (
                f"this server does not issue RSA-signed ID Tokens either, so omit "
                f"{ID_TOKEN_SIGNED_RESPONSE_ALG}"
            )
        raise UnsupportedClientMetadataError(
            f"Unsupported {ID_TOKEN_SIGNED_RESPONSE_ALG}: {requested!r}. HS256 is not offered "
            f"to self-registered clients; {advice}"
        )
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


def userinfo_signing_algorithm(metadata: Mapping[str, Any]) -> str:
    """Return the ``AbstractApplication.userinfo_signed_response_alg`` for *metadata*.

    With no ``userinfo_signed_response_alg`` (absent or JSON ``null``) the
    UserInfo response stays plain JSON, the OpenID Connect Dynamic Client
    Registration 1.0 section 2 default, so the field is blank. With OpenID Connect
    disabled the parameter is ignored the same way, as RFC 7591 section 2 has a
    server do with metadata it does not use: there is no UserInfo endpoint whose
    response it could describe. Otherwise RS256 is honoured
    when the server signs UserInfo responses (see
    :func:`~oauth2_provider.authorization_server.oidc.server.userinfo_signing_available`:
    OpenID Connect enabled, an ``OIDC_RSA_PRIVATE_KEY``, a server class that signs
    and a validator with a callable ``finalize_userinfo_response``). Every other value is refused rather than
    substituted (section 3.1 lets the provider reject requested metadata): a
    client that asked for a signed response would otherwise fail to parse the
    one it gets.

    Raises :class:`UnsupportedClientMetadataError` for a value the server
    cannot honour.
    """
    requested = metadata.get(USERINFO_SIGNED_RESPONSE_ALG)
    if requested is None or not oauth2_settings.OIDC_ENABLED:
        # Without OpenID Connect there is no UserInfo endpoint, so the parameter is
        # client metadata this server does not use and ignores (RFC 7591 section 2).
        return AbstractApplication.NO_ALGORITHM
    if not isinstance(requested, str) or requested not in SUPPORTED_USERINFO_ALGS:
        raise UnsupportedClientMetadataError(
            f"Unsupported {USERINFO_SIGNED_RESPONSE_ALG}: {requested!r}. "
            f"Supported values: {', '.join(sorted(SUPPORTED_USERINFO_ALGS))}"
        )
    if not userinfo_signing_available():
        raise UnsupportedClientMetadataError(
            f"{USERINFO_SIGNED_RESPONSE_ALG} {requested!r} is not available: "
            "this server does not sign UserInfo responses"
        )
    return requested


def userinfo_signed_response_alg(application: AbstractApplication) -> str | None:
    """Return the ``userinfo_signed_response_alg`` value describing *application*.

    The inverse of :func:`userinfo_signing_algorithm`, for registration
    responses. None when UserInfo is returned as plain JSON, so the parameter is
    omitted, as OpenID Connect Dynamic Client Registration 1.0 section 2 has the
    absence of the parameter mean. The value is reported only when
    :func:`~oauth2_provider.authorization_server.oidc.server.signs_userinfo_for`
    holds, the test the UserInfo endpoint signs under, so the client is told what
    it will actually receive; a stored value the server cannot honour is left out,
    and a ``PUT`` that echoes the response resets it to match.
    """
    if not signs_userinfo_for(application):
        return None
    return application.userinfo_signed_response_alg


def request_uris(metadata: Mapping[str, Any]) -> str:
    """Return the ``AbstractApplication.request_uris`` value to provision for *metadata*.

    ``request_uris`` is an array of https URLs (OpenID Connect Dynamic Client
    Registration 1.0 section 2), stored space separated like
    ``redirect_uris``. Absent or JSON ``null`` registers none. Raises
    :class:`UnsupportedClientMetadataError` for a malformed value. Callers
    only map it while request objects are enabled.
    """
    value = metadata.get(REQUEST_URIS)
    if value is None:
        return ""
    if not isinstance(value, list) or not all(isinstance(uri, str) for uri in value):
        raise UnsupportedClientMetadataError(f"{REQUEST_URIS} must be an array of strings")
    for uri in value:
        if not uri.lower().startswith("https://") or any(char.isspace() for char in uri):
            raise UnsupportedClientMetadataError(f"each of {REQUEST_URIS} must be an https URL")
    return " ".join(value)


def request_object_signing_alg(metadata: Mapping[str, Any], *, has_keys: bool) -> str:
    """Return the ``AbstractApplication.request_object_signing_alg`` for *metadata*.

    Absent or JSON ``null`` registers no algorithm, so any algorithm in
    ``OIDC_REQUEST_OBJECT_SIGNING_ALGS`` is accepted (OpenID Connect Dynamic
    Client Registration 1.0 section 2). A value outside that setting is
    refused, and so is a signing algorithm when the client registers no
    ``jwks`` or ``jwks_uri`` (*has_keys*) to verify it with. The value is never
    echoed in the message, which a registration response returns as its
    ``error_description``. Raises :class:`UnsupportedClientMetadataError`.
    Callers only map it while request objects are enabled.
    """
    value = metadata.get(REQUEST_OBJECT_SIGNING_ALG)
    if value is None:
        return ""
    supported = oauth2_settings.OIDC_REQUEST_OBJECT_SIGNING_ALGS
    if not isinstance(value, str) or value not in supported:
        raise UnsupportedClientMetadataError(
            f"Unsupported {REQUEST_OBJECT_SIGNING_ALG}. Supported values: {', '.join(supported)}"
        )
    if value != "none" and not has_keys:
        raise UnsupportedClientMetadataError(
            f"A signing {REQUEST_OBJECT_SIGNING_ALG} requires jwks or jwks_uri to verify request objects"
        )
    return value
