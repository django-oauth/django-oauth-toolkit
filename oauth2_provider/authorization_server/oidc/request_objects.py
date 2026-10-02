"""
OpenID Connect request objects (OpenID Connect Core 1.0 section 6).

A client may pass its authorization request parameters inside a JWT, either by
value in the ``request`` parameter (section 6.1) or by reference in
``request_uri``, which the OpenID Provider fetches (section 6.2). The request
object may be unsigned (``alg`` ``none``) or signed with an asymmetric
algorithm and verified against the client's registered ``client_jwks`` or
``client_jwks_uri`` (section 6.3.2). Encrypted request objects are not
supported.

:func:`resolve_request_object` validates the object and assembles the
authorization request parameters the rest of the flow sees (section 6.3.3):
the object's values supersede those passed with the OAuth 2.0 syntax.

Support is opt-in with ``OIDC_REQUEST_OBJECTS_ENABLED``. A pushed
authorization request's ``request_uri`` (RFC 9126) is not a request object
and is never resolved here.
"""

import contextlib
import hashlib
import json
import logging
import math
import threading
import time
from collections.abc import Iterator, Mapping
from typing import TYPE_CHECKING, Any

from django.core.cache import cache
from django.http import HttpRequest
from jwcrypto import jws
from jwcrypto.common import JWException, base64url_decode
from oauthlib.oauth2.rfc6749.errors import InvalidRequestError, OAuth2Error
from oauthlib.openid.connect.core.exceptions import InvalidRequestObject, InvalidRequestURI

from oauth2_provider.authorization_server.client_assertions import ClientAssertionError, client_signing_keys
from oauth2_provider.core import safe_fetch
from oauth2_provider.settings import oauth2_settings


if TYPE_CHECKING:
    from oauth2_provider.models import AbstractApplication


log = logging.getLogger(__name__)

#: The ``Accept`` header sent when fetching a ``request_uri``: the RFC 9101
#: media type, then the generic JWT one.
REQUEST_OBJECT_ACCEPT = "application/oauth-authz-req+jwt, application/jwt;q=0.9, */*;q=0.1"

#: Clock skew, in seconds, tolerated on the ``exp`` and ``nbf`` claims.
CLOCK_SKEW_SECONDS = 60

#: Cache key prefix of the per-URI fetch failure backoff.
BACKOFF_CACHE_PREFIX = "oauth2_provider:request_uri_backoff:"

_semaphore_lock = threading.Lock()
_semaphore: threading.BoundedSemaphore | None = None
_semaphore_size: int | None = None

# JWT registered claims (RFC 7519 section 4.1) that describe the request object
# itself rather than carry an authorization request parameter.
_JWT_CLAIMS = frozenset({"iss", "aud", "exp", "nbf", "iat", "jti"})


class RequestObjectError(Exception):
    """A request object could not be used.

    *error_class* is the oauthlib error the client is answered with:
    ``invalid_request_object``, ``invalid_request_uri`` (OpenID Connect Core
    1.0 section 3.1.2.6) or ``invalid_request``. The message is a safe
    ``error_description``: it never contains the request object.
    """

    def __init__(self, description: str, error_class: type[OAuth2Error] = InvalidRequestObject) -> None:
        super().__init__(description)
        self.description = description
        self.error_class = error_class


class RequestURIFetchError(Exception):
    """A ``request_uri`` could not be fetched.

    Raised by an ``OIDC_REQUEST_URI_FETCHER``; the message is logged, never
    returned to the client.
    """


class SafeRequestURIFetcher:
    """Fetch the request object a ``request_uri`` refers to (the default fetcher).

    Uses :func:`oauth2_provider.core.safe_fetch.fetch_https_document`: https
    only, every resolved address must be public and the connection is pinned to
    it, redirects are not followed, and the fetch is bounded by
    ``OIDC_REQUEST_URI_FETCH_TIMEOUT_SECONDS``. The response must be HTTP 200
    and at most ``OIDC_REQUEST_URI_MAX_SIZE`` bytes. Its media type is not
    checked: section 6.2 does not define one. The URI's fragment is never sent.

    A replacement is configured with ``OIDC_REQUEST_URI_FETCHER``: any class
    whose instances have ``fetch(request_uri) -> str`` and raise
    :class:`RequestURIFetchError` on failure.
    """

    def fetch(self, request_uri: str) -> str:
        return safe_fetch.fetch_https_document(
            request_uri,
            timeout=oauth2_settings.OIDC_REQUEST_URI_FETCH_TIMEOUT_SECONDS,
            read_response=self._read_document,
            exc_class=RequestURIFetchError,
            accept=REQUEST_OBJECT_ACCEPT,
        )

    @staticmethod
    def _read_document(response: Any) -> str:
        if response.status != 200:
            raise RequestURIFetchError(f"request_uri returned HTTP {response.status}")
        max_size = oauth2_settings.OIDC_REQUEST_URI_MAX_SIZE
        body = response.read(max_size + 1)
        if len(body) > max_size:
            raise RequestURIFetchError("request_uri document exceeds the maximum allowed size")
        try:
            return body.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise RequestURIFetchError("request_uri document is not a JWT") from exc


def request_objects_enabled() -> bool:
    """Whether the authorization endpoint accepts ``request`` and ``request_uri``."""
    return bool(oauth2_settings.OIDC_ENABLED and oauth2_settings.OIDC_REQUEST_OBJECTS_ENABLED)


def discovery_metadata() -> dict[str, Any]:
    """The request object fields of both discovery documents.

    OpenID Connect Discovery 1.0 section 3 defaults
    ``request_uri_parameter_supported`` to true, and RFC 8414 adopts the same
    fields, so both flags are always published. They cover request objects,
    not PAR request URIs, which RFC 9126 section 5 advertises separately.
    ``request_uris`` registration is never required: a client that registers
    some is held to them, one that does not may use any https ``request_uri``.
    """
    if not request_objects_enabled():
        return {"request_parameter_supported": False, "request_uri_parameter_supported": False}
    return {
        "request_parameter_supported": True,
        "request_uri_parameter_supported": True,
        "require_request_uri_registration": False,
        "request_object_signing_alg_values_supported": list(oauth2_settings.OIDC_REQUEST_OBJECT_SIGNING_ALGS),
    }


def resolve_request_object(
    parameters: Mapping[str, list[str]], application: "AbstractApplication", request: HttpRequest
) -> dict[str, list[str]]:
    """Validate the request object in *parameters* and assemble the authorization request.

    *parameters* are the authorization request's OAuth 2.0 parameters, as
    lists of values, carrying ``request`` or a non-PAR ``request_uri``.
    *application* is the client identified by their ``client_id``. Returns
    the assembled parameters (OpenID Connect Core 1.0 section 6.3.3), without
    ``request`` and ``request_uri``. Raises :class:`RequestObjectError`.
    """
    request_object = _single(parameters, "request")
    request_uri = _single(parameters, "request_uri")
    if request_object and request_uri:
        raise RequestObjectError(
            "The request and request_uri parameters cannot be used together.", InvalidRequestError
        )
    # Sections 6.1 and 6.2: response_type, and a scope including openid, must
    # be sent the usual way even when the request object repeats them, so the
    # request is a valid OAuth 2.0 and OpenID Connect request on its own.
    if not _single(parameters, "response_type"):
        raise RequestObjectError(
            "The response_type parameter is required alongside a request object.", InvalidRequestError
        )
    if "openid" not in (_single(parameters, "scope") or "").split():
        raise RequestObjectError(
            "The scope parameter must include openid alongside a request object.", InvalidRequestError
        )
    if request_uri:
        request_object = _fetch_request_object(request_uri, application)

    try:
        claims = _decode(request_object, application, request)
        _check_claims(claims, parameters, application)
    except RequestObjectError as error:
        # Section 3.1.2.6: invalid_request_object is for the request parameter;
        # a request_uri whose document is invalid "contains invalid data".
        if request_uri:
            raise RequestObjectError(error.description, InvalidRequestURI) from error
        raise

    assembled = {
        key: list(values) for key, values in parameters.items() if key not in ("request", "request_uri")
    }
    for name, value in claims.items():
        if name in _JWT_CLAIMS or value is None or value == []:
            continue
        # A response_type matching the outer one may list its values in another
        # order (see _check_claims); keep the outer spelling, which the client
        # registered and the rest of the flow compares against.
        if name == "response_type" and "response_type" in assembled:
            continue
        # A parameter repeated the usual way is invalid (RFC 6749 section 3.1);
        # superseding it must not hide that. Only resource may repeat. The name
        # comes from the request object, so it is not echoed.
        if name != "resource" and len(parameters.get(name) or []) > 1:
            raise RequestObjectError(
                "A parameter the request object carries must not be repeated.", InvalidRequestError
            )
        assembled[name] = _parameter_values(name, value)
    return assembled


def _single(parameters: Mapping[str, list[str]], name: str) -> str | None:
    values = parameters.get(name) or []
    if len(values) > 1:
        raise RequestObjectError(f"The {name} parameter must not be repeated.", InvalidRequestError)
    return values[0] if values else None


def _fetch_request_object(request_uri: str, application: "AbstractApplication") -> str:
    """Fetch the request object *request_uri* refers to (section 6.2)."""
    registered = application.request_uris.split()
    # Registration 1.0 section 2: a fragment only tells a cached copy apart, so
    # it is not part of what is registered.
    if registered and request_uri.split("#", 1)[0] not in {uri.split("#", 1)[0] for uri in registered}:
        raise RequestObjectError("The request_uri is not registered for this client.", InvalidRequestURI)
    # The fetch runs before the end-user logs in, for anyone who knows a
    # client_id, so a URL that just failed is not fetched again for a while,
    # and only so many fetches run at once (as for CIMD documents).
    backoff_key = BACKOFF_CACHE_PREFIX + hashlib.sha256(request_uri.split("#", 1)[0].encode()).hexdigest()
    if cache.get(backoff_key):
        raise RequestObjectError("The request_uri could not be retrieved.", InvalidRequestURI)
    fetcher = oauth2_settings.OIDC_REQUEST_URI_FETCHER()
    with _fetch_slot() as acquired:
        if not acquired:
            log.info(
                "request_uri fetch for client %r refused: too many fetches in flight", application.client_id
            )
            raise RequestObjectError("The request_uri could not be retrieved.", InvalidRequestURI)
        try:
            document = fetcher.fetch(request_uri)
        except Exception as exc:
            # RequestURIFetchError is the fetcher contract, and ValueError
            # (UnicodeError included) what URL parsing and host name encoding
            # raise for a malformed request_uri. Anything else is a fetcher
            # breaking that contract; like CIMD, still answer the client rather
            # than fail before login.
            if isinstance(exc, (RequestURIFetchError, safe_fetch.SafeFetchError, ValueError)):
                log.info("Could not fetch request_uri for client %r: %s", application.client_id, exc)
            else:
                log.exception("request_uri fetcher failed unexpectedly for client %r", application.client_id)
            backoff = oauth2_settings.OIDC_REQUEST_URI_FAILURE_BACKOFF_SECONDS
            if backoff:
                cache.set(backoff_key, True, timeout=backoff)
            raise RequestObjectError("The request_uri could not be retrieved.", InvalidRequestURI) from exc
    if not document:
        raise RequestObjectError("The request_uri did not return a request object.", InvalidRequestURI)
    return document


def _get_fetch_semaphore() -> threading.BoundedSemaphore | None:
    """Return the in-flight fetch semaphore, or None when the cap is disabled."""
    global _semaphore, _semaphore_size
    size = oauth2_settings.OIDC_REQUEST_URI_MAX_CONCURRENT_FETCHES
    if not size:
        return None
    with _semaphore_lock:
        if _semaphore is None or _semaphore_size != size:
            _semaphore = threading.BoundedSemaphore(size)
            _semaphore_size = size
        return _semaphore


@contextlib.contextmanager
def _fetch_slot() -> Iterator[bool]:
    """Take an in-flight fetch slot without blocking.

    Yields True when a slot was taken (or the cap is disabled) and False when
    ``OIDC_REQUEST_URI_MAX_CONCURRENT_FETCHES`` fetches are already running,
    so a flood of slow URLs fails fast rather than tying up workers. The cap
    is per process.
    """
    semaphore = _get_fetch_semaphore()
    acquired = semaphore is None or semaphore.acquire(blocking=False)
    try:
        yield acquired
    finally:
        if acquired and semaphore is not None:
            semaphore.release()


def _decode(request_object: str, application: "AbstractApplication", request: HttpRequest) -> dict[str, Any]:
    """Return the claims of *request_object*, verifying its signature (section 6.3.2)."""
    segments = request_object.strip().split(".")
    if len(segments) == 5:
        raise RequestObjectError("Encrypted request objects are not supported.")
    if len(segments) != 3:
        raise RequestObjectError("The request object is not a JWT.")
    header = _json_segment(segments[0], "header")

    alg = header.get("alg")
    # The header is attacker-controlled, so its alg is never echoed in the error.
    if not isinstance(alg, str) or alg not in oauth2_settings.OIDC_REQUEST_OBJECT_SIGNING_ALGS:
        raise RequestObjectError("The request object alg is not accepted.")
    registered_alg = application.request_object_signing_alg
    if registered_alg and alg != registered_alg:
        raise RequestObjectError("The request object alg is not the one registered for this client.")

    if alg == "none":
        if segments[2]:
            raise RequestObjectError("An unsigned request object must have an empty signature.")
        if "crit" in header:
            raise RequestObjectError("The request object has unsupported critical header parameters.")
        claims = _json_segment(segments[1], "payload")
    else:
        claims = _verify(request_object.strip(), alg, header, application)
        _check_signed_claims(claims, application, request)
    _check_times(claims)
    # JSON escapes can produce lone UTF-16 surrogates, which no URL or database
    # can carry; plain query parameters never contain them.
    try:
        json.dumps(claims, ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError:
        raise RequestObjectError("The request object contains invalid Unicode.")
    return claims


def _json_segment(segment: str, name: str) -> dict[str, Any]:
    try:
        value = json.loads(base64url_decode(segment))
    except (ValueError, TypeError, UnicodeDecodeError, RecursionError):
        raise RequestObjectError(f"The request object {name} is not valid JSON.")
    if not isinstance(value, dict):
        raise RequestObjectError(f"The request object {name} is not a JSON object.")
    return value


def _verify(
    request_object: str, alg: str, header: dict[str, Any], application: "AbstractApplication"
) -> dict[str, Any]:
    kid = header.get("kid")
    try:
        keys = client_signing_keys(application, kid if isinstance(kid, str) else None)
    except ClientAssertionError as exc:
        log.info("No key to verify the request object of client %r: %s", application.client_id, exc)
        raise RequestObjectError("The request object signature could not be verified.")
    for key in keys:
        token = jws.JWS()
        try:
            token.deserialize(request_object)
            token.allowed_algs = [alg]
            token.verify(key, alg=alg)
        except (JWException, ValueError, TypeError):
            continue
        try:
            claims = json.loads(token.payload)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise RequestObjectError("The request object payload is not valid JSON.")
        if not isinstance(claims, dict):
            raise RequestObjectError("The request object payload is not a JSON object.")
        return claims
    raise RequestObjectError("The request object signature could not be verified.")


def _check_signed_claims(
    claims: dict[str, Any], application: "AbstractApplication", request: HttpRequest
) -> None:
    """Check ``iss`` and ``aud`` of a signed request object (section 6.1).

    Both are optional (SHOULD), so each is only checked when present: ``iss``
    must be the client, and ``aud`` must be or include this OP's issuer,
    compared exactly as published (RFC 7519 section 2, StringOrURI).
    """
    if "iss" in claims and claims["iss"] != application.client_id:
        raise RequestObjectError("The request object iss claim is not the client_id.")
    if "aud" in claims:
        audience = claims["aud"]
        audiences = audience if isinstance(audience, list) else [audience]
        issuers = _issuers(request)
        if not any(isinstance(aud, str) and aud in issuers for aud in audiences):
            raise RequestObjectError("The request object aud claim does not include this issuer.")


def _issuers(request: HttpRequest) -> set[str]:
    issuers = set()
    for issuer in (oauth2_settings.oidc_issuer, oauth2_settings.oauth2_authorization_server_issuer):
        try:
            issuers.add(issuer(request))
        except Exception:
            # The OIDC or RFC 8414 URLs may not be installed; the other still applies.
            log.debug("Could not derive an issuer for request object audiences", exc_info=True)
    return issuers


def _check_times(claims: dict[str, Any]) -> None:
    now = time.time()
    for name in ("exp", "nbf"):
        value = claims.get(name)
        # Python's JSON parser accepts NaN and Infinity, which are not NumericDates.
        # Only floats can be non-finite; an int compares exactly however large.
        if name in claims and (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or (isinstance(value, float) and not math.isfinite(value))
        ):
            raise RequestObjectError(f"The request object {name} claim is not a number.")
    if "exp" in claims and claims["exp"] <= now - CLOCK_SKEW_SECONDS:
        raise RequestObjectError("The request object has expired.")
    if "nbf" in claims and claims["nbf"] > now + CLOCK_SKEW_SECONDS:
        raise RequestObjectError("The request object is not valid yet.")


def _check_claims(
    claims: dict[str, Any], parameters: Mapping[str, list[str]], application: "AbstractApplication"
) -> None:
    """Check the claims against the OAuth 2.0 parameters (sections 6.1 and 6.3.3)."""
    if "request" in claims or "request_uri" in claims:
        raise RequestObjectError("A request object must not contain request or request_uri.")
    if "client_id" in claims and claims["client_id"] != application.client_id:
        raise RequestObjectError("The request object client_id does not match the client_id parameter.")
    outer_response_type = _single(parameters, "response_type")
    if "response_type" in claims:
        # The order of the values does not matter (RFC 6749 section 3.1.1).
        response_type = claims["response_type"]
        if not isinstance(response_type, str) or set(response_type.split()) != set(
            (outer_response_type or "").split()
        ):
            raise RequestObjectError(
                "The request object response_type does not match the response_type parameter."
            )


def _parameter_values(name: str, value: Any) -> list[str]:
    """Express a request object claim as authorization request parameter values.

    A string is used as is, and ``resource`` (RFC 8707), the one parameter
    that may be repeated, as repeated values when it is an array of strings.
    Anything else, such as the ``claims`` object or a numeric ``max_age``, is
    its JSON text, as the OAuth 2.0 syntax carries it; a value of the wrong
    type for its parameter then fails that parameter's normal validation.
    """
    if isinstance(value, str):
        return [value]
    if name == "resource" and isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    return [json.dumps(value)]
